package lsm

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// Note: PolicyRule is now defined in common.go

// OpenPolicyRule matches struct policy_rule in lsm_file_open.bpf.c exactly (272 bytes)
type OpenPolicyRule struct {
	Action      uint32
	Operation   uint32
	PathLen     uint32
	Path        [256]byte
	IsDirectory uint32
}

type openExactRuleKey struct {
	Generation uint32
	Operation  uint32
	PathLen    uint32
	Path       [256]byte
}

type openDirectoryRuleKey struct {
	PrefixLen uint32
	Domain    uint8
	Path      [MaxPolicyPathLength]byte
}

type openIndexRule struct {
	Action      uint32
	Specificity uint32
	Order       uint32
}

type compiledOpenIndex struct {
	exact     map[openExactRuleKey]openIndexRule
	directory map[openDirectoryRuleKey]openIndexRule
}

type mutationPrefixRuleKey struct {
	PrefixLen uint32
	Domain    uint8
	Path      [MaxPolicyPathLength]byte
}

type mutationExactRuleKey struct {
	Generation uint32
	PathLen    uint32
	Path       [256]byte
}

type compiledMutationIndex struct {
	denies     map[mutationPrefixRuleKey]uint8
	allows     map[mutationPrefixRuleKey]uint8
	selfDenies map[mutationExactRuleKey]uint8
}

type openEventFingerprint struct {
	valid     bool
	timestamp uint64
	pid       uint32
	tgid      uint32
	cgroup    uint64
	operation uint32
	result    int32
	path      string
	comm      string
}

// File open event structure - must match BPF code
type OpenEvent struct {
	PID       uint32
	TGID      uint32
	Timestamp uint64
	CgroupID  uint64
	Comm      [16]byte
	Path      [256]byte
	Operation uint32
	Result    int32
}

const (
	MaxPolicyRules                       = 256
	openTailCallMapName                  = "open_tail_calls"
	openTailCallCanonicalizerName        = "lsm_open_canonicalize"
	openTailCallProgramName              = "lsm_open_policy"
	openTailCallCanonicalizerSlot        = uint32(0)
	openTailCallPolicySlot               = uint32(1)
	openIndexDomainBits                  = uint32(8)
	mutationIndexDomainBits              = uint32(8)
	mutationOpMkdir               uint32 = 3
	mutationOpUnlink              uint32 = 4
	mutationOpRmdir               uint32 = 5
	mutationOpRename              uint32 = 6
	// Note: Policy constants are now defined in common.go

	// duplicateSuppressionWindow limits how long we treat identical payloads as retries.
	duplicateSuppressionWindow = 50 * time.Millisecond
)

type LsmLoader func() (*ebpf.CollectionSpec, error)

type OpenLsm struct {
	cgroupPath string
	logger     *SharedLogger

	policyRules         []OpenPolicyRule
	numPolicyRules      int
	defaultPolicyResult bool // Default policy result: false=deny, true=allow
	containerOverlay    bool
	logMutex            sync.Mutex // Protect concurrent writes to stdout and log file
	policyUpdateMutex   sync.Mutex // Serialize complete indexed-policy generations and publication.

	// BPF program state
	ebpfCollection *ebpf.Collection
	exitTracepoint link.Link

	lastEvent openEventFingerprint
}

func NewOpenLsm(cgroupPath string, logger *SharedLogger) (*OpenLsm, error) {
	if cgroupPath == "" {
		return nil, fmt.Errorf("cgroup path is required")
	}

	l := &OpenLsm{
		cgroupPath:          cgroupPath,
		logger:              logger,
		defaultPolicyResult: false, // Default to deny (false)
	}

	// Note: Policy loading is now done separately via LoadPolicies()
	return l, nil
}

// Interface methods for LSMModule

func (l *OpenLsm) getCgroupPath() string {
	return l.cgroupPath
}

func (l *OpenLsm) setEbpfCollection(coll *ebpf.Collection) {
	l.policyUpdateMutex.Lock()
	defer l.policyUpdateMutex.Unlock()
	l.ebpfCollection = coll
}

func (l *OpenLsm) withPolicyUpdate(fn func() error) error {
	l.policyUpdateMutex.Lock()
	defer l.policyUpdateMutex.Unlock()
	return fn()
}

// LoadPolicies loads file open policy rules into the LSM
func (l *OpenLsm) LoadPolicies(policies []OpenPolicyRule) error {
	if len(policies) > MaxPolicyRules {
		return fmt.Errorf("too many file open policy rules: %d exceeds maximum %d", len(policies), MaxPolicyRules)
	}
	for i := range policies {
		if policies[i].PathLen == 0 || policies[i].PathLen > MaxPolicyPathLength {
			return fmt.Errorf("invalid file open policy rule %d path length: %d (must be 1-%d)", i, policies[i].PathLen, MaxPolicyPathLength)
		}
		if bytes.IndexByte(policies[i].Path[:policies[i].PathLen], 0) >= 0 {
			return fmt.Errorf("invalid file open policy rule %d path: contains a NUL byte", i)
		}
	}
	nextRules := append([]OpenPolicyRule(nil), policies...)

	// Sort policy rules by path length (longest first) for specificity
	sort.SliceStable(nextRules, func(i, j int) bool {
		return nextRules[i].PathLen > nextRules[j].PathLen
	})
	nextDefaultPolicyResult := rootPathPolicy(nextRules)

	return l.withPolicyUpdate(func() error {
		// A failed live update must leave the published in-memory view unchanged.
		if l.ebpfCollection != nil {
			if err := l.loadPolicyStateIntoBPF(l.ebpfCollection, nextRules, nextDefaultPolicyResult); err != nil {
				return fmt.Errorf("failed to update BPF maps: %w", err)
			}
			fmt.Printf("Updated BPF maps with new policies\n")
		}

		l.policyRules = nextRules
		l.numPolicyRules = len(nextRules)
		l.defaultPolicyResult = nextDefaultPolicyResult
		fmt.Printf("Loaded %d file open policy rules\n", l.numPolicyRules)
		if l.defaultPolicyResult {
			fmt.Printf("Default open policy result: ALLOW (root path '/' is allowed)\n")
		} else {
			fmt.Printf("Default open policy result: DENY (root path '/' is not explicitly allowed)\n")
		}

		return nil
	})
}

func (l *OpenLsm) LoadAndAttach(loader func() (*ebpf.CollectionSpec, error)) error {
	config := BPFConfig{
		ProgramNames: l.requiredProgramNames(),
		// lsm_link (hard-link guard, audit #3) is best-effort: it needs
		// CONFIG_SECURITY_PATH and rides the same policy maps, but must never
		// degrade file-open enforcement if it can't attach on some kernel.
		OptionalProgramNames: []string{"lsm_link"},
		EventMapName:         "events",
		AllowedCgroupsMap:    "allowed_cgroups",
		TargetCgroupMap:      "target_cgroup",
		StartMessage:         "Successfully started monitoring file opens",
		ShutdownMessage:      "Shutting down open LSM tracker",
	}
	if l.containerOverlay {
		config.AfterRequiredAttach = l.attachCopyUpExitTracepoint
	}
	return LoadAndAttachBPFWithSetup(l, loader, config, populateOpenTailCall)
}

func populateOpenTailCall(coll *ebpf.Collection) error {
	if coll == nil {
		return fmt.Errorf("file-open tail-call collection is nil")
	}
	tailCalls := coll.Maps[openTailCallMapName]
	if tailCalls == nil {
		return fmt.Errorf("required file-open tail-call map %q not found", openTailCallMapName)
	}
	stages := []struct {
		name    string
		slot    uint32
		program *ebpf.Program
	}{
		{name: openTailCallCanonicalizerName, slot: openTailCallCanonicalizerSlot},
		{name: openTailCallProgramName, slot: openTailCallPolicySlot},
	}
	for i := range stages {
		stages[i].program = coll.Programs[stages[i].name]
		if stages[i].program == nil {
			return fmt.Errorf("required file-open tail-call program %q not found", stages[i].name)
		}
	}
	for _, stage := range stages {
		programFD := uint32(stage.program.FD())
		if err := tailCalls.Put(stage.slot, programFD); err != nil {
			return fmt.Errorf("populate file-open tail-call slot %d: %w", stage.slot, err)
		}
	}
	return nil
}

func (l *OpenLsm) requiredProgramNames() []string {
	programs := []string{"lsm_open", "lsm_mkdir", "lsm_unlink", "lsm_rmdir", "lsm_rename_source", "lsm_rename_destination"}
	if l.containerOverlay {
		return append(programs, "lsm_mark_overlay_write")
	}
	return programs
}

func (l *OpenLsm) attachCopyUpExitTracepoint(coll *ebpf.Collection) error {
	if !l.containerOverlay {
		return nil
	}
	prog := coll.Programs["trace_sys_exit_open"]
	if prog == nil {
		return fmt.Errorf("required container copy-up syscall-exit program not found")
	}
	tp, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: "sys_exit", Program: prog})
	if err != nil {
		return fmt.Errorf("attach required container copy-up syscall-exit raw tracepoint: %w", err)
	}
	l.exitTracepoint = tp
	return nil
}

func rootPathPolicy(rules []OpenPolicyRule) bool {
	for _, rule := range rules {
		pathStr := string(bytes.TrimRight(rule.Path[:rule.PathLen], "\x00"))
		if pathStr == "/" && rule.Action == PolicyAllow {
			return true
		}
	}
	return false
}

func compileOpenIndex(rules []OpenPolicyRule) compiledOpenIndex {
	index := compiledOpenIndex{
		exact:     make(map[openExactRuleKey]openIndexRule),
		directory: make(map[openDirectoryRuleKey]openIndexRule),
	}
	for order, rule := range rules {
		operations := []uint32{rule.Operation}
		if rule.Operation == OpOpen {
			operations = []uint32{OpOpen, OpOpenRO, OpOpenRW}
		}
		value := openIndexRule{
			Action:      rule.Action,
			Specificity: rule.PathLen,
			Order:       uint32(order),
		}
		for _, operation := range operations {
			if operation > OpOpenRW {
				continue
			}
			if rule.IsDirectory != 0 {
				directoryKey := openDirectoryRuleKey{
					PrefixLen: openIndexDomainBits + rule.PathLen*8,
					Domain:    uint8(operation),
				}
				copy(directoryKey.Path[:], rule.Path[:rule.PathLen])
				if _, exists := index.directory[directoryKey]; !exists {
					index.directory[directoryKey] = value
				}

				if rule.PathLen > 1 {
					selfKey := openExactRuleKey{
						Operation: operation,
						PathLen:   rule.PathLen - 1,
					}
					copy(selfKey.Path[:], rule.Path[:rule.PathLen-1])
					if _, exists := index.exact[selfKey]; !exists {
						index.exact[selfKey] = value
					}
				}
				continue
			}

			exactKey := openExactRuleKey{
				Operation: operation,
				PathLen:   rule.PathLen,
			}
			copy(exactKey.Path[:], rule.Path[:rule.PathLen])
			if _, exists := index.exact[exactKey]; !exists {
				index.exact[exactKey] = value
			}
		}
	}
	return index
}

type openIndexStore interface {
	activeToken() (uint64, error)
	setActiveToken(uint64) error
	setDefault(uint32, uint32) error
	listExactKeys() ([]openExactRuleKey, error)
	listDirectoryKeys() ([]openDirectoryRuleKey, error)
	putExact(openExactRuleKey, openIndexRule) error
	putDirectory(openDirectoryRuleKey, openIndexRule) error
	deleteExact(openExactRuleKey) error
	deleteDirectory(openDirectoryRuleKey) error
}

type ebpfOpenIndexStore struct {
	exact     *ebpf.Map
	directory *ebpf.Map
	active    *ebpf.Map
	defaults  *ebpf.Map
}

func newEBPFOpenIndexStore(coll *ebpf.Collection) (*ebpfOpenIndexStore, error) {
	store := &ebpfOpenIndexStore{
		exact:     coll.Maps["open_exact_rules"],
		directory: coll.Maps["open_directory_rules"],
		active:    coll.Maps["active_open_generation"],
		defaults:  coll.Maps["open_default_policy"],
	}
	for name, resource := range map[string]*ebpf.Map{
		"open_exact_rules":       store.exact,
		"open_directory_rules":   store.directory,
		"active_open_generation": store.active,
		"open_default_policy":    store.defaults,
	} {
		if resource == nil {
			return nil, fmt.Errorf("required %s map not found", name)
		}
	}
	return store, nil
}

func (s *ebpfOpenIndexStore) activeToken() (uint64, error) {
	key := uint32(0)
	var token uint64
	if err := s.active.Lookup(&key, &token); err != nil {
		return 0, err
	}
	return token, nil
}

func (s *ebpfOpenIndexStore) setActiveToken(token uint64) error {
	key := uint32(0)
	return s.active.Put(&key, &token)
}

func (s *ebpfOpenIndexStore) setDefault(generation, action uint32) error {
	return s.defaults.Put(&generation, &action)
}

func (s *ebpfOpenIndexStore) listExactKeys() ([]openExactRuleKey, error) {
	iterator := s.exact.Iterate()
	var key openExactRuleKey
	var value openIndexRule
	var keys []openExactRuleKey
	for iterator.Next(&key, &value) {
		keys = append(keys, key)
	}
	return keys, iterator.Err()
}

func (s *ebpfOpenIndexStore) listDirectoryKeys() ([]openDirectoryRuleKey, error) {
	iterator := s.directory.Iterate()
	var key openDirectoryRuleKey
	var value openIndexRule
	var keys []openDirectoryRuleKey
	for iterator.Next(&key, &value) {
		keys = append(keys, key)
	}
	return keys, iterator.Err()
}

func (s *ebpfOpenIndexStore) putExact(key openExactRuleKey, value openIndexRule) error {
	return s.exact.Put(&key, &value)
}

func (s *ebpfOpenIndexStore) putDirectory(key openDirectoryRuleKey, value openIndexRule) error {
	return s.directory.Put(&key, &value)
}

func (s *ebpfOpenIndexStore) deleteExact(key openExactRuleKey) error {
	return s.exact.Delete(&key)
}

func (s *ebpfOpenIndexStore) deleteDirectory(key openDirectoryRuleKey) error {
	return s.directory.Delete(&key)
}

func cleanOpenIndexGeneration(store openIndexStore, generation uint32) error {
	exactKeys, err := store.listExactKeys()
	if err != nil {
		return fmt.Errorf("list exact generation %d: %w", generation, err)
	}
	for _, key := range exactKeys {
		if key.Generation == generation {
			if err := store.deleteExact(key); err != nil {
				return fmt.Errorf("delete exact generation %d entry: %w", generation, err)
			}
		}
	}
	directoryKeys, err := store.listDirectoryKeys()
	if err != nil {
		return fmt.Errorf("list directory generation %d: %w", generation, err)
	}
	for _, key := range directoryKeys {
		if uint32(key.Domain)/3 == generation {
			if err := store.deleteDirectory(key); err != nil {
				return fmt.Errorf("delete directory generation %d entry: %w", generation, err)
			}
		}
	}
	return nil
}

type openIndexReplaceResult struct {
	cleanupDebt error
}

func replaceOpenIndex(store openIndexStore, index compiledOpenIndex, defaultAllow bool) (openIndexReplaceResult, error) {
	activeToken, err := store.activeToken()
	if err != nil {
		return openIndexReplaceResult{}, fmt.Errorf("read active token: %w", err)
	}
	if activeToken == ^uint64(0) {
		return openIndexReplaceResult{}, fmt.Errorf("active token exhausted at %d", activeToken)
	}
	active := uint32(activeToken & 1)
	nextToken := activeToken + 1
	inactive := uint32(nextToken & 1)
	if err := cleanOpenIndexGeneration(store, inactive); err != nil {
		return openIndexReplaceResult{}, fmt.Errorf("prepare inactive generation: %w", err)
	}
	cleanup := func(stageErr error) error {
		if cleanupErr := cleanOpenIndexGeneration(store, inactive); cleanupErr != nil {
			return fmt.Errorf("%w (cleanup failed: %v)", stageErr, cleanupErr)
		}
		return stageErr
	}

	defaultAction := uint32(0)
	if defaultAllow {
		defaultAction = 1
	}
	if err := store.setDefault(inactive, defaultAction); err != nil {
		return openIndexReplaceResult{}, cleanup(fmt.Errorf("stage generation %d default: %w", inactive, err))
	}
	for key, value := range index.exact {
		key.Generation = inactive
		if err := store.putExact(key, value); err != nil {
			return openIndexReplaceResult{}, cleanup(fmt.Errorf("stage generation %d exact entry: %w", inactive, err))
		}
	}
	for key, value := range index.directory {
		key.Domain += uint8(inactive * 3)
		if err := store.putDirectory(key, value); err != nil {
			return openIndexReplaceResult{}, cleanup(fmt.Errorf("stage generation %d directory entry: %w", inactive, err))
		}
	}
	if err := store.setActiveToken(nextToken); err != nil {
		return openIndexReplaceResult{}, cleanup(fmt.Errorf("activate token %d: %w", nextToken, err))
	}
	if err := cleanOpenIndexGeneration(store, active); err != nil {
		return openIndexReplaceResult{cleanupDebt: fmt.Errorf("clean old generation %d after committed token %d: %w", active, nextToken, err)}, nil
	}
	return openIndexReplaceResult{}, nil
}

func (l *OpenLsm) loadPolicyIntoBPF(coll *ebpf.Collection) error {
	return l.withPolicyUpdate(func() error {
		return l.loadPolicyStateIntoBPF(coll, l.policyRules, l.defaultPolicyResult)
	})
}

func (l *OpenLsm) loadPolicyStateIntoBPF(coll *ebpf.Collection, policyRules []OpenPolicyRule, defaultPolicyResult bool) error {
	openStore, err := newEBPFOpenIndexStore(coll)
	if err != nil {
		return err
	}
	openIndex := compileOpenIndex(policyRules)

	// Always load the default policy result into BPF map
	key := uint32(0)
	defaultResult := uint32(0) // Default to deny
	if defaultPolicyResult {
		defaultResult = uint32(1) // Allow
	}
	if err := coll.Maps["default_policy"].Put(&key, &defaultResult); err != nil {
		return fmt.Errorf("failed to update default_policy map: %w", err)
	}
	containerOverlay := uint32(0)
	if l.containerOverlay {
		containerOverlay = 1
	}
	if err := coll.Maps["container_overlay_mode"].Put(&key, &containerOverlay); err != nil {
		return fmt.Errorf("failed to update container_overlay_mode map: %w", err)
	}
	mutationStore, err := newEBPFMutationIndexStore(coll)
	if err != nil {
		return err
	}
	mutationResult, err := replaceMutationIndex(mutationStore, compileMutationIndex(policyRules))
	if err != nil {
		return fmt.Errorf("failed to update indexed mutation policy: %w", err)
	}
	if mutationResult.cleanupDebt != nil {
		fmt.Fprintf(os.Stderr, "Warning: indexed mutation policy committed with deferred cleanup: %v\n", mutationResult.cleanupDebt)
	}

	// Always update the legacy rule count so an empty reload cannot retain stale
	// hard-link authority from the prior policy.
	numPolicyRules := len(policyRules)
	numRules := int32(numPolicyRules)
	if err := coll.Maps["num_rules"].Put(&key, &numRules); err != nil {
		return fmt.Errorf("failed to update num_rules map: %w", err)
	}

	if numPolicyRules > 0 {
		fmt.Printf("Loading %d policy rules into BPF maps...\n", numPolicyRules)
	}

	// Load each policy rule
	for i := 0; i < numPolicyRules; i++ {
		if err := coll.Maps["policy_rules"].Put(uint32(i), &policyRules[i]); err != nil {
			return fmt.Errorf("failed to update policy_rules map for rule %d: %w", i, err)
		}

		// pathStr := string(bytes.TrimRight(l.policyRules[i].Path[:], "\x00"))
		// actionStr := "deny"
		// if l.policyRules[i].Action == 1 {
		// 	actionStr = "allow"
		// }
		// dirStr := ""
		// if l.policyRules[i].IsDirectory == 1 {
		// 	dirStr = " (directory)"
		// }

		// fmt.Printf("Loaded rule %d: %s %s%s\n", i, actionStr, pathStr, dirStr)
	}
	replaceResult, err := replaceOpenIndex(openStore, openIndex, defaultPolicyResult)
	if err != nil {
		return fmt.Errorf("failed to update indexed file-open policy: %w", err)
	}
	if replaceResult.cleanupDebt != nil {
		fmt.Fprintf(os.Stderr, "Warning: indexed file-open policy committed with deferred cleanup: %v\n", replaceResult.cleanupDebt)
	}
	if numPolicyRules == 0 {
		fmt.Printf("No policy rules to load, using default policy result: %v\n", defaultPolicyResult)
	}

	// fmt.Printf("Successfully loaded all policy rules into BPF\n")
	return nil
}

func compileMutationIndex(rules []OpenPolicyRule) compiledMutationIndex {
	index := compiledMutationIndex{denies: make(map[mutationPrefixRuleKey]uint8), allows: make(map[mutationPrefixRuleKey]uint8), selfDenies: make(map[mutationExactRuleKey]uint8)}
	for _, rule := range rules {
		if rule.PathLen == 0 || rule.PathLen > MaxPolicyPathLength {
			continue
		}
		genericDeny := rule.Operation == OpOpen && rule.Action == PolicyDeny
		rwDirectory := rule.IsDirectory != 0 && rule.Operation == OpOpenRW
		if !genericDeny && !rwDirectory {
			continue
		}
		prefix := mutationPrefixRuleKey{PrefixLen: mutationIndexDomainBits + rule.PathLen*8}
		copy(prefix.Path[:], rule.Path[:rule.PathLen])
		if genericDeny || (rwDirectory && rule.Action == PolicyDeny) {
			index.denies[prefix] = 1
		}
		if rwDirectory && rule.Action == PolicyAllow {
			index.allows[prefix] = 1
		}
		if genericDeny && rule.IsDirectory != 0 && rule.PathLen > 1 && rule.Path[rule.PathLen-1] == '/' {
			self := mutationExactRuleKey{PathLen: rule.PathLen - 1}
			copy(self.Path[:], rule.Path[:rule.PathLen-1])
			index.selfDenies[self] = 1
		}
	}
	return index
}

type mutationIndexStore interface {
	activeToken() (uint64, error)
	setActiveToken(uint64) error
	listDenyKeys() ([]mutationPrefixRuleKey, error)
	listAllowKeys() ([]mutationPrefixRuleKey, error)
	listSelfDenyKeys() ([]mutationExactRuleKey, error)
	putDeny(mutationPrefixRuleKey, uint8) error
	putAllow(mutationPrefixRuleKey, uint8) error
	putSelfDeny(mutationExactRuleKey, uint8) error
	deleteDeny(mutationPrefixRuleKey) error
	deleteAllow(mutationPrefixRuleKey) error
	deleteSelfDeny(mutationExactRuleKey) error
}

type ebpfMutationIndexStore struct{ denies, allows, selfDenies, active *ebpf.Map }

func newEBPFMutationIndexStore(coll *ebpf.Collection) (*ebpfMutationIndexStore, error) {
	s := &ebpfMutationIndexStore{coll.Maps["mutation_deny_rules"], coll.Maps["mutation_allow_rules"], coll.Maps["mutation_self_deny_rules"], coll.Maps["active_mutation_generation"]}
	for name, m := range map[string]*ebpf.Map{"mutation_deny_rules": s.denies, "mutation_allow_rules": s.allows, "mutation_self_deny_rules": s.selfDenies, "active_mutation_generation": s.active} {
		if m == nil {
			return nil, fmt.Errorf("required %s map not found", name)
		}
	}
	return s, nil
}
func (s *ebpfMutationIndexStore) activeToken() (uint64, error) {
	key := uint32(0)
	var token uint64
	if err := s.active.Lookup(&key, &token); err != nil {
		return 0, err
	}
	return token, nil
}
func (s *ebpfMutationIndexStore) setActiveToken(token uint64) error {
	key := uint32(0)
	return s.active.Put(&key, &token)
}
func mutationPrefixKeys(m *ebpf.Map) ([]mutationPrefixRuleKey, error) {
	it := m.Iterate()
	var key mutationPrefixRuleKey
	var value uint8
	var keys []mutationPrefixRuleKey
	for it.Next(&key, &value) {
		keys = append(keys, key)
	}
	return keys, it.Err()
}
func (s *ebpfMutationIndexStore) listDenyKeys() ([]mutationPrefixRuleKey, error) {
	return mutationPrefixKeys(s.denies)
}
func (s *ebpfMutationIndexStore) listAllowKeys() ([]mutationPrefixRuleKey, error) {
	return mutationPrefixKeys(s.allows)
}
func (s *ebpfMutationIndexStore) listSelfDenyKeys() ([]mutationExactRuleKey, error) {
	it := s.selfDenies.Iterate()
	var key mutationExactRuleKey
	var value uint8
	var keys []mutationExactRuleKey
	for it.Next(&key, &value) {
		keys = append(keys, key)
	}
	return keys, it.Err()
}
func (s *ebpfMutationIndexStore) putDeny(k mutationPrefixRuleKey, v uint8) error {
	return s.denies.Put(&k, &v)
}
func (s *ebpfMutationIndexStore) putAllow(k mutationPrefixRuleKey, v uint8) error {
	return s.allows.Put(&k, &v)
}
func (s *ebpfMutationIndexStore) putSelfDeny(k mutationExactRuleKey, v uint8) error {
	return s.selfDenies.Put(&k, &v)
}
func (s *ebpfMutationIndexStore) deleteDeny(k mutationPrefixRuleKey) error {
	return s.denies.Delete(&k)
}
func (s *ebpfMutationIndexStore) deleteAllow(k mutationPrefixRuleKey) error {
	return s.allows.Delete(&k)
}
func (s *ebpfMutationIndexStore) deleteSelfDeny(k mutationExactRuleKey) error {
	return s.selfDenies.Delete(&k)
}

func cleanMutationGeneration(store mutationIndexStore, generation uint32) error {
	denies, err := store.listDenyKeys()
	if err != nil {
		return fmt.Errorf("list deny generation %d: %w", generation, err)
	}
	for _, k := range denies {
		if uint32(k.Domain) == generation {
			if err := store.deleteDeny(k); err != nil {
				return err
			}
		}
	}
	allows, err := store.listAllowKeys()
	if err != nil {
		return fmt.Errorf("list allow generation %d: %w", generation, err)
	}
	for _, k := range allows {
		if uint32(k.Domain) == generation {
			if err := store.deleteAllow(k); err != nil {
				return err
			}
		}
	}
	self, err := store.listSelfDenyKeys()
	if err != nil {
		return fmt.Errorf("list self-deny generation %d: %w", generation, err)
	}
	for _, k := range self {
		if k.Generation == generation {
			if err := store.deleteSelfDeny(k); err != nil {
				return err
			}
		}
	}
	return nil
}

type mutationIndexReplaceResult struct{ cleanupDebt error }

func replaceMutationIndex(store mutationIndexStore, index compiledMutationIndex) (mutationIndexReplaceResult, error) {
	token, err := store.activeToken()
	if err != nil {
		return mutationIndexReplaceResult{}, fmt.Errorf("read active token: %w", err)
	}
	if token == ^uint64(0) {
		return mutationIndexReplaceResult{}, fmt.Errorf("active token exhausted at %d", token)
	}
	active, next := uint32(token&1), token+1
	inactive := uint32(next & 1)
	if err := cleanMutationGeneration(store, inactive); err != nil {
		return mutationIndexReplaceResult{}, fmt.Errorf("prepare inactive generation: %w", err)
	}
	cleanup := func(e error) error {
		if ce := cleanMutationGeneration(store, inactive); ce != nil {
			return fmt.Errorf("%w (cleanup failed: %v)", e, ce)
		}
		return e
	}
	for k, v := range index.denies {
		k.Domain = uint8(inactive)
		if err := store.putDeny(k, v); err != nil {
			return mutationIndexReplaceResult{}, cleanup(err)
		}
	}
	for k, v := range index.allows {
		k.Domain = uint8(inactive)
		if err := store.putAllow(k, v); err != nil {
			return mutationIndexReplaceResult{}, cleanup(err)
		}
	}
	for k, v := range index.selfDenies {
		k.Generation = inactive
		if err := store.putSelfDeny(k, v); err != nil {
			return mutationIndexReplaceResult{}, cleanup(err)
		}
	}
	if err := store.setActiveToken(next); err != nil {
		return mutationIndexReplaceResult{}, cleanup(err)
	}
	if err := cleanMutationGeneration(store, active); err != nil {
		return mutationIndexReplaceResult{fmt.Errorf("clean old generation %d after committed token %d: %w", active, next, err)}, nil
	}
	return mutationIndexReplaceResult{}, nil
}

// validateEvent checks if the event data is properly formed
func validateEvent(event *OpenEvent) bool {
	return validateEventArrays(event.Comm[:], event.Path[:])
}

// Note: safeString is now defined in common.go

func (l *OpenLsm) handleEvent(data []byte) {
	if len(data) < int(unsafe.Sizeof(OpenEvent{})) {
		fmt.Fprintf(os.Stderr, "Error: received incomplete event\n")
		return
	}

	var event OpenEvent
	reader := bytes.NewReader(data)
	if err := binary.Read(reader, binary.LittleEndian, &event); err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to parse event: %v\n", err)
		return
	}

	// Validate event data to prevent corruption
	if !validateEvent(&event) {
		fmt.Fprintf(os.Stderr, "Error: received corrupted event data (missing null terminators)\n")
		return
	}

	// Extract strings from byte arrays with safe conversion
	comm := safeString(event.Comm[:])
	path := safeString(event.Path[:])

	// Additional validation - reject obviously corrupted data
	if len(comm) == 0 || len(path) == 0 {
		fmt.Fprintf(os.Stderr, "Error: received event with empty comm or path\n")
		return
	}

	// Use current time for ISO 8601 format (BPF timestamp is kernel boot time, not Unix time)
	timestamp := time.Now().Format(time.RFC3339)

	// Format result string (match C version)
	resultStr := "allowed"
	if event.Result != 0 {
		resultStr = "denied"
	}

	eventName := "file.open"
	switch event.Operation {
	case uint32(OpOpenRO):
		eventName = "file.open:ro"
	case uint32(OpOpenRW):
		eventName = "file.open:rw"
	case uint32(OpOpen):
		eventName = "file.open"
	case mutationOpMkdir:
		eventName = "file.mkdir"
	case mutationOpUnlink:
		eventName = "file.unlink"
	case mutationOpRmdir:
		eventName = "file.rmdir"
	case mutationOpRename:
		eventName = "file.rename"
	}

	// Format in logfmt (key=value pairs) - matching C version format exactly
	logEntry := fmt.Sprintf("time=%s event=%s pid=%d cgroup=%d exe=\"%s\" path=\"%s\" decision=%s",
		timestamp, eventName, event.PID, event.CgroupID, comm, path, resultStr)

	// Protect concurrent writes with mutex
	l.logMutex.Lock()
	defer l.logMutex.Unlock()

	// The kernel occasionally re-runs the file_open LSM hook during path resolution,
	// emitting identical ring buffer samples for the same file descriptor. Without
	// filtering, these retries double-count in the UI stream and policy suggestions.
	// Track the most recent payload so we can drop byte-for-byte duplicates while
	// still forwarding genuine consecutive opens.
	if l.lastEvent.valid &&
		l.lastEvent.pid == event.PID &&
		l.lastEvent.tgid == event.TGID &&
		l.lastEvent.cgroup == event.CgroupID &&
		l.lastEvent.operation == event.Operation &&
		l.lastEvent.result == event.Result &&
		l.lastEvent.path == path &&
		l.lastEvent.comm == comm {
		var delta uint64
		if event.Timestamp >= l.lastEvent.timestamp {
			delta = event.Timestamp - l.lastEvent.timestamp
		} else {
			delta = l.lastEvent.timestamp - event.Timestamp
		}
		if time.Duration(delta) <= duplicateSuppressionWindow {
			return
		}
	}

	l.lastEvent = openEventFingerprint{
		valid:     true,
		timestamp: event.Timestamp,
		pid:       event.PID,
		tgid:      event.TGID,
		cgroup:    event.CgroupID,
		operation: event.Operation,
		result:    event.Result,
		path:      path,
		comm:      comm,
	}

	// Write to shared logger if configured
	if l.logger != nil {
		_ = l.logger.Write(logEntry)
	}

	// Unique path logging removed
}

func addDescendantCgroups(cgroupMap *ebpf.Map, cgroupPath string) error {
	value := uint8(1)

	// Add the current directory's cgroup ID (matching C version exactly)
	cgroupID, err := getCgroupID(cgroupPath)
	if err == nil {
		if err := cgroupMap.Put(&cgroupID, &value); err == nil {
			// fmt.Printf("Added cgroup ID %d: %s\n", cgroupID, cgroupPath)
		}
	}

	// Open the directory (matching C version logic)
	entries, err := os.ReadDir(cgroupPath)
	if err != nil {
		return nil // Return silently like C version
	}

	// Iterate through entries (matching C version)
	for _, entry := range entries {
		// Skip . and .. (matching C version)
		if entry.Name() == "." || entry.Name() == ".." {
			continue
		}

		// Build full path
		fullPath := filepath.Join(cgroupPath, entry.Name())

		// Check if it's a directory (matching C version)
		if entry.IsDir() {
			// Skip cgroup control files (matching C version exactly)
			name := entry.Name()
			if strings.HasPrefix(name, "cgroup.") ||
				strings.HasPrefix(name, "cpu.") ||
				strings.HasPrefix(name, "memory.") ||
				strings.HasPrefix(name, "io.") ||
				strings.HasPrefix(name, "pids.") ||
				strings.HasPrefix(name, "rdma.") ||
				strings.HasPrefix(name, "hugetlb.") ||
				strings.HasPrefix(name, "misc.") ||
				strings.HasPrefix(name, "irq.") {
				continue // Skip control files
			}

			// Recursively add subdirectory (matching C version)
			addDescendantCgroups(cgroupMap, fullPath)
		}
	}

	return nil
}

func getCgroupID(cgroupPath string) (uint64, error) {
	// Get the real cgroup ID using the inode number (matching C version)
	var stat unix.Stat_t
	if err := unix.Stat(cgroupPath, &stat); err != nil {
		return 0, fmt.Errorf("failed to stat cgroup path %s: %w", cgroupPath, err)
	}

	// The cgroup ID is the inode number (same as C version)
	cgroupID := stat.Ino
	return cgroupID, nil
}

// cgroupLevel is the depth of a cgroup path below the v2 root (/sys/fs/cgroup),
// which equals the kernel's cgroup "level" that bpf_get_current_ancestor_cgroup_id
// indexes by. The unified root itself is level 0. Used so the LSM can match a
// process by cgroup hierarchy (box + any descendant) rather than a static snapshot.
func cgroupLevel(cgroupPath string) int {
	rel := strings.Trim(strings.TrimPrefix(cgroupPath, "/sys/fs/cgroup"), "/")
	if rel == "" {
		return 0
	}
	return len(strings.Split(rel, "/"))
}

// addSingleCgroup adds only the exact cgroup ID to the allowed map (non-recursive scope)
func addSingleCgroup(cgroupMap *ebpf.Map, cgroupPath string) error {
	value := uint8(1)
	cgroupID, err := getCgroupID(cgroupPath)
	if err != nil {
		return err
	}
	if err := cgroupMap.Put(&cgroupID, &value); err != nil {
		return fmt.Errorf("failed to add cgroup ID %d: %w", cgroupID, err)
	}
	return nil
}

// Increase memory lock limits for BPF operations
func BumpMemlockRlimit() error {
	var rlim unix.Rlimit

	// Try to set unlimited first
	rlim.Cur = unix.RLIM_INFINITY
	rlim.Max = unix.RLIM_INFINITY

	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &rlim); err != nil {
		// Try with a specific large value instead of INFINITY
		rlim.Cur = 512 * 1024 * 1024 // 512 MB
		rlim.Max = 512 * 1024 * 1024

		if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &rlim); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to increase RLIMIT_MEMLOCK limit: %v\n", err)
			fmt.Fprintf(os.Stderr, "Continuing anyway - may fail if BPF maps are too large\n")
			// Don't return error - let it fail later if it's actually a problem
		}
	}
	return nil
}
