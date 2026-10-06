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

type openPrefixRuleKey struct {
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
	exact  map[openExactRuleKey]openIndexRule
	prefix map[openPrefixRuleKey]openIndexRule
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
// validateOpenPolicyRules rejects any rule the kernel index could not
// enforce exactly as written, so no accepted rule is ever silently dropped.
func validateOpenPolicyRules(policies []OpenPolicyRule) error {
	if len(policies) > MaxPolicyRules {
		return fmt.Errorf("too many file open policy rules: %d exceeds maximum %d", len(policies), MaxPolicyRules)
	}
	for i := range policies {
		rule := &policies[i]
		if rule.PathLen == 0 || rule.PathLen > MaxPolicyPathLength {
			return fmt.Errorf("invalid file open policy rule %d path length: %d (must be 1-%d)", i, rule.PathLen, MaxPolicyPathLength)
		}
		if bytes.IndexByte(rule.Path[:rule.PathLen], 0) >= 0 {
			return fmt.Errorf("invalid file open policy rule %d path: contains a NUL byte", i)
		}
		if rule.Action != PolicyDeny && rule.Action != PolicyAllow {
			return fmt.Errorf("invalid file open policy rule %d action: %d", i, rule.Action)
		}
		if rule.Operation > OpOpenRW {
			return fmt.Errorf("invalid file open policy rule %d operation: %d", i, rule.Operation)
		}
		if rule.IsDirectory != 0 && rule.Path[rule.PathLen-1] != '/' {
			return fmt.Errorf("invalid file open policy rule %d: directory path must end with '/'", i)
		}
	}
	return nil
}

func (l *OpenLsm) LoadPolicies(policies []OpenPolicyRule) error {
	if err := validateOpenPolicyRules(policies); err != nil {
		return err
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

// compileOpenIndex turns the sorted rules into the kernel's full-byte indexes,
// preserving the historical matcher semantics over every accepted byte: each
// rule matches every path it is a byte prefix of (a directory rule carries its
// trailing '/', so it covers descendants), a directory rule also matches the
// directory itself, the longest matching rule wins, an earlier rule wins a
// length tie, and only rules for the requested operation (or generic open)
// apply. Prefix rules go to the LPM trie; directory-self matches go to the
// exact map. Generic rules are expanded to every runtime operation.
func compileOpenIndex(rules []OpenPolicyRule) compiledOpenIndex {
	index := compiledOpenIndex{
		exact:  make(map[openExactRuleKey]openIndexRule),
		prefix: make(map[openPrefixRuleKey]openIndexRule),
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
			prefixKey := openPrefixRuleKey{
				PrefixLen: openIndexDomainBits + rule.PathLen*8,
				Domain:    uint8(operation),
			}
			copy(prefixKey.Path[:], rule.Path[:rule.PathLen])
			if _, exists := index.prefix[prefixKey]; !exists {
				index.prefix[prefixKey] = value
			}

			if rule.IsDirectory != 0 && rule.PathLen > 1 && rule.Path[rule.PathLen-1] == '/' {
				selfKey := openExactRuleKey{
					Operation: operation,
					PathLen:   rule.PathLen - 1,
				}
				copy(selfKey.Path[:], rule.Path[:rule.PathLen-1])
				if _, exists := index.exact[selfKey]; !exists {
					index.exact[selfKey] = value
				}
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
	listPrefixKeys() ([]openPrefixRuleKey, error)
	putExact(openExactRuleKey, openIndexRule) error
	putPrefix(openPrefixRuleKey, openIndexRule) error
	deleteExact(openExactRuleKey) error
	deletePrefix(openPrefixRuleKey) error
}

type ebpfOpenIndexStore struct {
	exact    *ebpf.Map
	prefix   *ebpf.Map
	active   *ebpf.Map
	defaults *ebpf.Map
}

func newEBPFOpenIndexStore(coll *ebpf.Collection) (*ebpfOpenIndexStore, error) {
	store := &ebpfOpenIndexStore{
		exact:    coll.Maps["open_exact_rules"],
		prefix:   coll.Maps["open_prefix_rules"],
		active:   coll.Maps["active_open_generation"],
		defaults: coll.Maps["open_default_policy"],
	}
	for name, resource := range map[string]*ebpf.Map{
		"open_exact_rules":       store.exact,
		"open_prefix_rules":      store.prefix,
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

func (s *ebpfOpenIndexStore) listPrefixKeys() ([]openPrefixRuleKey, error) {
	iterator := s.prefix.Iterate()
	var key openPrefixRuleKey
	var value openIndexRule
	var keys []openPrefixRuleKey
	for iterator.Next(&key, &value) {
		keys = append(keys, key)
	}
	return keys, iterator.Err()
}

func (s *ebpfOpenIndexStore) putExact(key openExactRuleKey, value openIndexRule) error {
	return s.exact.Put(&key, &value)
}

func (s *ebpfOpenIndexStore) putPrefix(key openPrefixRuleKey, value openIndexRule) error {
	return s.prefix.Put(&key, &value)
}

func (s *ebpfOpenIndexStore) deleteExact(key openExactRuleKey) error {
	return s.exact.Delete(&key)
}

func (s *ebpfOpenIndexStore) deletePrefix(key openPrefixRuleKey) error {
	return s.prefix.Delete(&key)
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
	prefixKeys, err := store.listPrefixKeys()
	if err != nil {
		return fmt.Errorf("list prefix generation %d: %w", generation, err)
	}
	for _, key := range prefixKeys {
		if uint32(key.Domain)/3 == generation {
			if err := store.deletePrefix(key); err != nil {
				return fmt.Errorf("delete prefix generation %d entry: %w", generation, err)
			}
		}
	}
	return nil
}

type openIndexReplaceResult struct {
	cleanupDebt error
}

// tokenHeadroom keeps room for activation (+1) and a rollback (+2) without
// wrapping; a wrapped token could repeat a value a running hook snapshotted.
const tokenHeadroom = 2

// openIndexStage is a fully staged, not yet active, file-open generation.
type openIndexStage struct {
	store            openIndexStore
	active, inactive uint32
	token            uint64 // token active when staging began
}

// stageOpenIndex writes index into the inactive generation without changing
// what any hook observes. On error the inactive generation is cleaned.
func stageOpenIndex(store openIndexStore, index compiledOpenIndex, defaultAllow bool) (*openIndexStage, error) {
	activeToken, err := store.activeToken()
	if err != nil {
		return nil, fmt.Errorf("read active token: %w", err)
	}
	if activeToken > ^uint64(0)-tokenHeadroom {
		return nil, fmt.Errorf("active token exhausted at %d", activeToken)
	}
	stage := &openIndexStage{store: store, active: uint32(activeToken & 1), inactive: uint32((activeToken + 1) & 1), token: activeToken}
	if err := cleanOpenIndexGeneration(store, stage.inactive); err != nil {
		return nil, fmt.Errorf("prepare inactive generation: %w", err)
	}
	defaultAction := uint32(0)
	if defaultAllow {
		defaultAction = 1
	}
	if err := store.setDefault(stage.inactive, defaultAction); err != nil {
		return nil, stage.abort(fmt.Errorf("stage generation %d default: %w", stage.inactive, err))
	}
	for key, value := range index.exact {
		key.Generation = stage.inactive
		if err := store.putExact(key, value); err != nil {
			return nil, stage.abort(fmt.Errorf("stage generation %d exact entry: %w", stage.inactive, err))
		}
	}
	for key, value := range index.prefix {
		key.Domain += uint8(stage.inactive * 3)
		if err := store.putPrefix(key, value); err != nil {
			return nil, stage.abort(fmt.Errorf("stage generation %d prefix entry: %w", stage.inactive, err))
		}
	}
	return stage, nil
}

// abort discards the staged generation and returns cause (annotated with any
// cleanup failure).
func (s *openIndexStage) abort(cause error) error {
	if err := cleanOpenIndexGeneration(s.store, s.inactive); err != nil {
		return fmt.Errorf("%w (cleanup failed: %v)", cause, err)
	}
	return cause
}

// activate publishes the staged generation to every hook.
func (s *openIndexStage) activate() error {
	if err := s.store.setActiveToken(s.token + 1); err != nil {
		return fmt.Errorf("activate token %d: %w", s.token+1, err)
	}
	return nil
}

// rollback re-selects the previous (still intact) generation after a
// successful activate. It moves to token+2, which has the previous parity but
// a never-used value, so a hook that snapshotted token+1 cannot confirm.
func (s *openIndexStage) rollback() error {
	return s.store.setActiveToken(s.token + 2)
}

// finish cleans the previous generation once the staged one is active. A
// failure is cleanup debt, not a failed update: the new authority is live.
func (s *openIndexStage) finish() error {
	if err := cleanOpenIndexGeneration(s.store, s.active); err != nil {
		return fmt.Errorf("clean old generation %d after committed token %d: %w", s.active, s.token+1, err)
	}
	return nil
}

func replaceOpenIndex(store openIndexStore, index compiledOpenIndex, defaultAllow bool) (openIndexReplaceResult, error) {
	stage, err := stageOpenIndex(store, index, defaultAllow)
	if err != nil {
		return openIndexReplaceResult{}, err
	}
	if err := stage.activate(); err != nil {
		return openIndexReplaceResult{}, stage.abort(err)
	}
	return openIndexReplaceResult{cleanupDebt: stage.finish()}, nil
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
	mutationStore, err := newEBPFMutationIndexStore(coll)
	if err != nil {
		return err
	}

	key := uint32(0)
	containerOverlay := uint32(0)
	if l.containerOverlay {
		containerOverlay = 1
	}
	if err := coll.Maps["container_overlay_mode"].Put(&key, &containerOverlay); err != nil {
		return fmt.Errorf("failed to update container_overlay_mode map: %w", err)
	}

	if err := commitPolicyIndexes(mutationStore, openStore, policyRules, defaultPolicyResult); err != nil {
		return err
	}
	if len(policyRules) == 0 {
		fmt.Printf("No policy rules to load, using default policy result: %v\n", defaultPolicyResult)
	} else {
		fmt.Printf("Loaded %d policy rules into BPF maps\n", len(policyRules))
	}
	return nil
}

// commitPolicyIndexes stages BOTH the mutation and file-open indexes before
// activating either, so a failure anywhere leaves the kernel on the previous
// file-open AND mutation authority (unless the mutation rollback itself fails,
// which is reported).
func commitPolicyIndexes(mutationStore mutationIndexStore, openStore openIndexStore, policyRules []OpenPolicyRule, defaultPolicyResult bool) error {
	mutationStage, err := stageMutationIndex(mutationStore, compileMutationIndex(policyRules))
	if err != nil {
		return fmt.Errorf("failed to stage indexed mutation policy: %w", err)
	}
	openStage, err := stageOpenIndex(openStore, compileOpenIndex(policyRules), defaultPolicyResult)
	if err != nil {
		return mutationStage.abort(fmt.Errorf("failed to stage indexed file-open policy: %w", err))
	}
	if err := mutationStage.activate(); err != nil {
		return openStage.abort(mutationStage.abort(fmt.Errorf("failed to activate indexed mutation policy: %w", err)))
	}
	if err := openStage.activate(); err != nil {
		cause := fmt.Errorf("failed to activate indexed file-open policy: %w", err)
		if rollbackErr := mutationStage.rollback(); rollbackErr != nil {
			// The mutation index is live on the new policy and cannot be
			// withdrawn; report the split rather than claim it unchanged.
			return fmt.Errorf("%w (mutation policy rollback failed: %v)", cause, rollbackErr)
		}
		return openStage.abort(mutationStage.abort(cause))
	}
	if debt := mutationStage.finish(); debt != nil {
		fmt.Fprintf(os.Stderr, "Warning: indexed mutation policy committed with deferred cleanup: %v\n", debt)
	}
	if debt := openStage.finish(); debt != nil {
		fmt.Fprintf(os.Stderr, "Warning: indexed file-open policy committed with deferred cleanup: %v\n", debt)
	}
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

// mutationIndexStage mirrors openIndexStage for the mutation index.
type mutationIndexStage struct {
	store            mutationIndexStore
	active, inactive uint32
	token            uint64
}

func stageMutationIndex(store mutationIndexStore, index compiledMutationIndex) (*mutationIndexStage, error) {
	token, err := store.activeToken()
	if err != nil {
		return nil, fmt.Errorf("read active token: %w", err)
	}
	if token > ^uint64(0)-tokenHeadroom {
		return nil, fmt.Errorf("active token exhausted at %d", token)
	}
	stage := &mutationIndexStage{store: store, active: uint32(token & 1), inactive: uint32((token + 1) & 1), token: token}
	if err := cleanMutationGeneration(store, stage.inactive); err != nil {
		return nil, fmt.Errorf("prepare inactive generation: %w", err)
	}
	for k, v := range index.denies {
		k.Domain = uint8(stage.inactive)
		if err := store.putDeny(k, v); err != nil {
			return nil, stage.abort(err)
		}
	}
	for k, v := range index.allows {
		k.Domain = uint8(stage.inactive)
		if err := store.putAllow(k, v); err != nil {
			return nil, stage.abort(err)
		}
	}
	for k, v := range index.selfDenies {
		k.Generation = stage.inactive
		if err := store.putSelfDeny(k, v); err != nil {
			return nil, stage.abort(err)
		}
	}
	return stage, nil
}

func (s *mutationIndexStage) abort(cause error) error {
	if err := cleanMutationGeneration(s.store, s.inactive); err != nil {
		return fmt.Errorf("%w (cleanup failed: %v)", cause, err)
	}
	return cause
}

func (s *mutationIndexStage) activate() error {
	return s.store.setActiveToken(s.token + 1)
}

func (s *mutationIndexStage) rollback() error {
	return s.store.setActiveToken(s.token + 2)
}

func (s *mutationIndexStage) finish() error {
	if err := cleanMutationGeneration(s.store, s.active); err != nil {
		return fmt.Errorf("clean old generation %d after committed token %d: %w", s.active, s.token+1, err)
	}
	return nil
}

func replaceMutationIndex(store mutationIndexStore, index compiledMutationIndex) (mutationIndexReplaceResult, error) {
	stage, err := stageMutationIndex(store, index)
	if err != nil {
		return mutationIndexReplaceResult{}, err
	}
	if err := stage.activate(); err != nil {
		return mutationIndexReplaceResult{}, stage.abort(err)
	}
	return mutationIndexReplaceResult{cleanupDebt: stage.finish()}, nil
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
