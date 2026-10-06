package lsm

import (
	"errors"
	"math/rand"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/strongdm/leash/internal/version"
)

func policyPathOfLength(length int, suffix byte) string {
	if length < 2 {
		panic("policy path length must leave room for slash and suffix")
	}
	return "/" + strings.Repeat("a", length-2) + string(suffix)
}

func openRuleForPath(action, operation uint32, path string) OpenPolicyRule {
	rule := OpenPolicyRule{
		Action:    action,
		Operation: operation,
		PathLen:   uint32(len(path)),
	}
	copy(rule.Path[:], path)
	return rule
}

func openDirectoryRuleForPath(action, operation uint32, path string) OpenPolicyRule {
	rule := openRuleForPath(action, operation, path)
	rule.IsDirectory = 1
	return rule
}

func TestPolicyPathLengthBoundariesPreservePermitAndForbid(t *testing.T) {
	for _, action := range []struct {
		name  string
		word  string
		value int32
	}{
		{name: "permit", word: "allow", value: PolicyAllow},
		{name: "forbid", word: "deny", value: PolicyDeny},
	} {
		for _, length := range []int{64, 65, MaxPolicyPathLength} {
			t.Run(action.name+"/length-"+strconv.Itoa(length), func(t *testing.T) {
				path := policyPathOfLength(length, 'x')
				parsed, err := ParseRuleString(action.word + " file.open:rw " + path)
				if err != nil {
					t.Fatalf("ParseRuleString(%d bytes): %v", length, err)
				}
				if parsed.Action != action.value || parsed.Operation != OpOpenRW {
					t.Fatalf("parsed action/operation = %d/%d, want %d/%d", parsed.Action, parsed.Operation, action.value, OpOpenRW)
				}
				if parsed.PathLen != int32(length) || string(parsed.Path[:parsed.PathLen]) != path {
					t.Fatalf("parsed path length/content changed at %d bytes", length)
				}

				converted := ConvertToFileOpenRules([]PolicyRule{*parsed})
				if len(converted) != 1 || converted[0].PathLen != uint32(length) || string(converted[0].Path[:converted[0].PathLen]) != path {
					t.Fatalf("Go/BPF conversion changed %d-byte path", length)
				}
				if err := (&OpenLsm{}).LoadPolicies(converted); err != nil {
					t.Fatalf("LoadPolicies(%d bytes): %v", length, err)
				}
			})
		}
	}

	tooLong := policyPathOfLength(MaxPolicyPathLength+1, 'x')
	if _, err := ParseRuleString("allow file.open:rw " + tooLong); err == nil || !strings.Contains(err.Error(), "max 255") {
		t.Fatalf("256-byte parser error = %v, want max-255 rejection", err)
	}
}

func TestPolicyPathLengthValidationIsAtomic(t *testing.T) {
	original := openRuleForPath(PolicyAllow, OpOpen, "/")
	l := &OpenLsm{}
	if err := l.LoadPolicies([]OpenPolicyRule{original}); err != nil {
		t.Fatal(err)
	}

	invalid := []OpenPolicyRule{
		{Action: PolicyDeny, Operation: OpOpenRW, PathLen: 0},
		{Action: PolicyDeny, Operation: OpOpenRW, PathLen: MaxPolicyPathLength + 1},
		{Action: PolicyDeny, Operation: OpOpenRW, PathLen: 3, Path: [256]byte{'/', 0, 'x'}},
	}
	for _, rule := range invalid {
		if err := l.LoadPolicies([]OpenPolicyRule{rule}); err == nil {
			t.Fatalf("invalid path length %d was accepted", rule.PathLen)
		}
		if l.numPolicyRules != 1 || len(l.policyRules) != 1 || l.policyRules[0] != original || !l.defaultPolicyResult {
			t.Fatalf("invalid path length %d changed prior policy state", rule.PathLen)
		}
	}
	if _, err := ParseRuleString("deny file.open:rw /bad\x00path"); err == nil || !strings.Contains(err.Error(), "NUL") {
		t.Fatalf("embedded-NUL parser error = %v, want rejection", err)
	}
}

func TestLongPolicyPathMatcherUsesFullByteIndexes(t *testing.T) {
	source, err := os.ReadFile("bpf/lsm_open.bpf.c")
	if err != nil {
		t.Fatal(err)
	}
	body := string(source)
	for _, required := range []string{
		"#define MAX_OPEN_INDEX_ENTRIES (MAX_POLICY_RULES * 3 * 2)",
		"u8 domain;",
		"char path[MAX_PATH_LEN - 1];",
		"lookup->prefix.prefix_len = 8 + path_len * 8;",
		"open_exact_rules SEC(\".maps\")",
		"open_prefix_rules SEC(\".maps\")",
		"check_open_indexed_policy(path, file_op_type)",
		"check_open_indexed_policy(s->path, OP_OPEN_RO)",
		"for (int i = 0; i < MAX_PATH_LEN; i++)",
		"path_len > MAX_PATH_LEN - 1",
	} {
		if !strings.Contains(body, required) {
			t.Fatalf("file policy source is missing long-path contract %q", required)
		}
	}
	for _, legacy := range []string{"check_path_policy", "simple_string_starts_with", "len > 64"} {
		if strings.Contains(body, legacy) {
			t.Fatalf("legacy 64-byte matcher %q is still present", legacy)
		}
	}
}

func TestOpenIndexedPolicyLinearizesOnFullActivationToken(t *testing.T) {
	source, err := os.ReadFile("bpf/lsm_open.bpf.c")
	if err != nil {
		t.Fatal(err)
	}
	body := string(source)
	if got := strings.Count(body, "bpf_map_lookup_elem(&active_open_generation"); got != 3 {
		t.Fatalf("active token reads = %d, want matcher snapshot plus file_open and path_link confirmations", got)
	}
	hookStart := strings.Index(body, "int BPF_PROG(lsm_open_policy")
	if hookStart < 0 {
		t.Fatal("could not find indexed file-open policy hook")
	}
	hookEnd := strings.Index(body[hookStart:], "\nSEC(\"lsm/file_open\")")
	if hookEnd < 0 {
		t.Fatal("could not isolate indexed file-open policy hook")
	}
	hook := body[hookStart : hookStart+hookEnd]
	lookups := []string{
		"int policy_result = check_open_indexed_policy(path, file_op_type);",
		"struct open_index_lookup_scratch *lookup = bpf_map_lookup_elem(&open_index_lookup_scratch_map",
		"barrier();",
		"u64 *confirmed_token = bpf_map_lookup_elem(&active_open_generation",
		"*confirmed_token != lookup->activation_token",
		"event->result = policy_result ? 0 : -13;",
		"bpf_ringbuf_submit(event, 0);",
		"return policy_result ? 0 : -13;",
	}
	previous := -1
	for _, lookup := range lookups {
		position := strings.Index(hook, lookup)
		if position <= previous {
			t.Fatalf("hook linearization sequence missing or reordered at %q", lookup)
		}
		previous = position
	}
	for _, required := range []string{
		"__type(value, u64);",
		"u64 activation_token;",
		"u32 active_generation = activation_token & 1;",
		"lookup->activation_token = activation_token;",
		"bpf_map_lookup_elem(&open_exact_rules",
		"bpf_map_lookup_elem(&open_prefix_rules",
		"bpf_map_lookup_elem(&open_default_policy",
	} {
		if !strings.Contains(body, required) {
			t.Fatalf("missing activation-token contract %q", required)
		}
	}
	if old, current := uint64(0), uint64(2); old&1 != current&1 || old == current {
		t.Fatalf("test setup does not model same-slot ABA: old=%d current=%d", old, current)
	}
}

func exactIndexKey(operation uint32, path string) openExactRuleKey {
	key := openExactRuleKey{Operation: operation, PathLen: uint32(len(path))}
	copy(key.Path[:], path)
	return key
}

func prefixIndexKey(operation uint32, path string) openPrefixRuleKey {
	key := openPrefixRuleKey{
		PrefixLen: openIndexDomainBits + uint32(len(path))*8,
		Domain:    uint8(operation),
	}
	copy(key.Path[:], path)
	return key
}

func TestOpenPrefixIndexKeyFitsKernelLPMContract(t *testing.T) {
	if got := unsafe.Sizeof(openPrefixRuleKey{}); got != 260 {
		t.Fatalf("prefix LPM key size = %d, want 260 (4-byte prefix + 256-byte data)", got)
	}
	if got := len(openPrefixRuleKey{}.Path); got != MaxPolicyPathLength {
		t.Fatalf("prefix LPM path capacity = %d, want %d", got, MaxPolicyPathLength)
	}
	for generation := uint32(0); generation < 2; generation++ {
		for operation := uint32(OpOpen); operation <= OpOpenRW; operation++ {
			domain := uint8(generation*3 + operation)
			if gotGeneration, gotOperation := uint32(domain)/3, uint32(domain)%3; gotGeneration != generation || gotOperation != operation {
				t.Fatalf("domain %d decoded as generation/op %d/%d, want %d/%d", domain, gotGeneration, gotOperation, generation, operation)
			}
		}
	}
	key := prefixIndexKey(OpOpenRW, policyPathOfLength(MaxPolicyPathLength, '/'))
	if key.PrefixLen != 8+MaxPolicyPathLength*8 {
		t.Fatalf("max path prefix bits = %d, want %d", key.PrefixLen, 8+MaxPolicyPathLength*8)
	}
}

func TestCompileOpenIndexPreservesFullBytesAtEveryBoundary(t *testing.T) {
	for _, action := range []uint32{PolicyAllow, PolicyDeny} {
		for _, length := range []int{64, 65, MaxPolicyPathLength} {
			path := policyPathOfLength(length, byte('a'+length%20))
			rule := openRuleForPath(action, OpOpenRW, path)
			// Bytes outside PathLen are not policy data and must not enter the key.
			rule.Path[length] = 0x7f
			index := compileOpenIndex([]OpenPolicyRule{rule})
			value, ok := index.prefix[prefixIndexKey(OpOpenRW, path)]
			if !ok {
				t.Fatalf("missing %d-byte prefix action %d", length, action)
			}
			if value.Action != action || value.Specificity != uint32(length) || value.Order != 0 {
				t.Fatalf("%d-byte prefix value = %+v", length, value)
			}
			if len(index.exact) != 0 || len(index.prefix) != 1 {
				t.Fatalf("%d-byte file rule compiled to exact=%d prefix=%d entries, want 0/1", length, len(index.exact), len(index.prefix))
			}
		}
	}
}

func TestCompileOpenIndexPreservesOperationOrderAndDirectorySemantics(t *testing.T) {
	parent := openDirectoryRuleForPath(PolicyAllow, OpOpen, "/workspace/")
	child := openDirectoryRuleForPath(PolicyDeny, OpOpenRO, "/workspace/private/")
	exact := openRuleForPath(PolicyAllow, OpOpenRO, "/workspace/private/readme")
	l := &OpenLsm{}
	if err := l.LoadPolicies([]OpenPolicyRule{parent, child, exact}); err != nil {
		t.Fatal(err)
	}
	index := compileOpenIndex(l.policyRules)

	if got := index.prefix[prefixIndexKey(OpOpenRO, "/workspace/private/readme")]; got.Action != PolicyAllow || got.Specificity != uint32(len("/workspace/private/readme")) {
		t.Fatalf("file candidate = %+v", got)
	}
	if got := index.exact[exactIndexKey(OpOpenRO, "/workspace/private")]; got.Action != PolicyDeny || got.Specificity != uint32(len("/workspace/private/")) {
		t.Fatalf("directory-self candidate = %+v", got)
	}
	if got := index.prefix[prefixIndexKey(OpOpenRO, "/workspace/private/")]; got.Action != PolicyDeny {
		t.Fatalf("read-only child directory = %+v", got)
	}
	if _, exists := index.prefix[prefixIndexKey(OpOpenRW, "/workspace/private/")]; exists {
		t.Fatal("read-only child directory leaked into read-write operation index")
	}
	for _, operation := range []uint32{OpOpen, OpOpenRO, OpOpenRW} {
		if got := index.prefix[prefixIndexKey(operation, "/workspace/")]; got.Action != PolicyAllow {
			t.Fatalf("generic parent for operation %d = %+v", operation, got)
		}
	}

	path := "/same"
	denyFirst := compileOpenIndex([]OpenPolicyRule{
		openRuleForPath(PolicyDeny, OpOpen, path),
		openRuleForPath(PolicyAllow, OpOpenRW, path),
	})
	if got := denyFirst.prefix[prefixIndexKey(OpOpenRW, path)]; got.Action != PolicyDeny || got.Order != 0 {
		t.Fatalf("same-path first rule lost precedence: %+v", got)
	}
	allowFirst := compileOpenIndex([]OpenPolicyRule{
		openRuleForPath(PolicyAllow, OpOpenRW, path),
		openRuleForPath(PolicyDeny, OpOpen, path),
	})
	if got := allowFirst.prefix[prefixIndexKey(OpOpenRW, path)]; got.Action != PolicyAllow || got.Order != 0 {
		t.Fatalf("same-path operation-specific first rule lost precedence: %+v", got)
	}
}

type fakeOpenIndexStore struct {
	active         uint64
	defaults       map[uint32]uint32
	exact          map[openExactRuleKey]openIndexRule
	prefix         map[openPrefixRuleKey]openIndexRule
	putCalls       int
	failPutAt      int
	failActivation bool
	failDelete     bool
}

func (s *fakeOpenIndexStore) activeToken() (uint64, error) { return s.active, nil }
func (s *fakeOpenIndexStore) setActiveToken(token uint64) error {
	if s.failActivation {
		return errors.New("active token write failed")
	}
	s.active = token
	return nil
}
func (s *fakeOpenIndexStore) setDefault(generation, action uint32) error {
	s.defaults[generation] = action
	return nil
}
func (s *fakeOpenIndexStore) listExactKeys() ([]openExactRuleKey, error) {
	keys := make([]openExactRuleKey, 0, len(s.exact))
	for key := range s.exact {
		keys = append(keys, key)
	}
	return keys, nil
}
func (s *fakeOpenIndexStore) listPrefixKeys() ([]openPrefixRuleKey, error) {
	keys := make([]openPrefixRuleKey, 0, len(s.prefix))
	for key := range s.prefix {
		keys = append(keys, key)
	}
	return keys, nil
}
func (s *fakeOpenIndexStore) putExact(key openExactRuleKey, value openIndexRule) error {
	s.putCalls++
	if s.failPutAt > 0 && s.putCalls == s.failPutAt {
		return errors.New("exact write failed")
	}
	s.exact[key] = value
	return nil
}
func (s *fakeOpenIndexStore) putPrefix(key openPrefixRuleKey, value openIndexRule) error {
	s.putCalls++
	if s.failPutAt > 0 && s.putCalls == s.failPutAt {
		return errors.New("prefix write failed")
	}
	s.prefix[key] = value
	return nil
}
func (s *fakeOpenIndexStore) deleteExact(key openExactRuleKey) error {
	if s.failDelete {
		return errors.New("exact delete failed")
	}
	delete(s.exact, key)
	return nil
}
func (s *fakeOpenIndexStore) deletePrefix(key openPrefixRuleKey) error {
	if s.failDelete {
		return errors.New("prefix delete failed")
	}
	delete(s.prefix, key)
	return nil
}

func newFakeOpenIndexStore() *fakeOpenIndexStore {
	return &fakeOpenIndexStore{
		defaults: make(map[uint32]uint32),
		exact:    make(map[openExactRuleKey]openIndexRule),
		prefix:   make(map[openPrefixRuleKey]openIndexRule),
	}
}

func TestReplaceOpenIndexFlipsOnlyAfterCompleteStaging(t *testing.T) {
	store := newFakeOpenIndexStore()
	oldKey := exactIndexKey(OpOpenRW, "/old")
	oldKey.Generation = 0
	store.exact[oldKey] = openIndexRule{Action: PolicyAllow}
	index := compileOpenIndex([]OpenPolicyRule{
		openRuleForPath(PolicyDeny, OpOpenRW, policyPathOfLength(65, 'x')),
		openDirectoryRuleForPath(PolicyAllow, OpOpenRW, "/new/"),
	})

	result, err := replaceOpenIndex(store, index, true)
	if err != nil {
		t.Fatal(err)
	}
	if result.cleanupDebt != nil {
		t.Fatalf("unexpected cleanup debt: %v", result.cleanupDebt)
	}
	if store.active != 1 || store.defaults[1] != PolicyAllow {
		t.Fatalf("active/default = %d/%d, want 1/1", store.active, store.defaults[1])
	}
	if _, exists := store.exact[oldKey]; exists {
		t.Fatal("old exact generation survived successful flip")
	}
	for key := range store.exact {
		if key.Generation != 1 {
			t.Fatalf("exact key retained generation %d", key.Generation)
		}
	}
	for key := range store.prefix {
		if uint32(key.Domain)/3 != 1 {
			t.Fatalf("prefix key retained generation domain %d", key.Domain)
		}
	}
}

func TestReplaceOpenIndexFailurePreservesActiveAuthority(t *testing.T) {
	for _, failActivation := range []bool{false, true} {
		t.Run(map[bool]string{false: "stage", true: "activation"}[failActivation], func(t *testing.T) {
			store := newFakeOpenIndexStore()
			store.failActivation = failActivation
			if !failActivation {
				store.failPutAt = 1
			}
			oldKey := exactIndexKey(OpOpenRW, "/old")
			store.exact[oldKey] = openIndexRule{Action: PolicyAllow}
			index := compileOpenIndex([]OpenPolicyRule{openRuleForPath(PolicyDeny, OpOpenRW, "/new")})

			if _, err := replaceOpenIndex(store, index, false); err == nil {
				t.Fatal("failed transition unexpectedly succeeded")
			}
			if store.active != 0 || store.exact[oldKey].Action != PolicyAllow {
				t.Fatal("failed transition changed active authority")
			}
			for key := range store.exact {
				if key.Generation == 1 {
					t.Fatal("failed transition left staged exact authority")
				}
			}
			for key := range store.prefix {
				if uint32(key.Domain)/3 == 1 {
					t.Fatal("failed transition left staged prefix authority")
				}
			}
		})
	}
}

func TestReplaceOpenIndexUsesMonotonicTokenAndRejectsExhaustion(t *testing.T) {
	store := newFakeOpenIndexStore()
	store.active = 42
	index := compileOpenIndex([]OpenPolicyRule{openRuleForPath(PolicyAllow, OpOpenRW, "/new")})
	if _, err := replaceOpenIndex(store, index, false); err != nil {
		t.Fatal(err)
	}
	if store.active != 43 {
		t.Fatalf("first active token = %d, want 43", store.active)
	}
	if _, err := replaceOpenIndex(store, index, false); err != nil {
		t.Fatal(err)
	}
	if store.active != 44 {
		t.Fatalf("second active token = %d, want 44", store.active)
	}

	exhausted := newFakeOpenIndexStore()
	exhausted.active = ^uint64(0)
	if _, err := replaceOpenIndex(exhausted, index, false); err == nil || !strings.Contains(err.Error(), "exhausted") {
		t.Fatalf("exhausted token error = %v, want rejection", err)
	}
	if exhausted.active != ^uint64(0) || len(exhausted.exact) != 0 || len(exhausted.prefix) != 0 {
		t.Fatal("token exhaustion changed indexed authority")
	}
}

func TestReplaceOpenIndexReportsCleanupDebtAsCommitted(t *testing.T) {
	store := newFakeOpenIndexStore()
	oldKey := exactIndexKey(OpOpenRW, "/old")
	store.exact[oldKey] = openIndexRule{Action: PolicyDeny}
	store.failDelete = true
	index := compileOpenIndex([]OpenPolicyRule{openRuleForPath(PolicyAllow, OpOpenRW, "/new")})

	result, err := replaceOpenIndex(store, index, false)
	if err != nil {
		t.Fatalf("committed transition reported as rejected: %v", err)
	}
	if store.active != 1 || result.cleanupDebt == nil {
		t.Fatalf("active/debt = %d/%v, want committed token 1 with debt", store.active, result.cleanupDebt)
	}
}

func TestOpenPolicyUpdateSerializesConcurrentGenerations(t *testing.T) {
	l := &OpenLsm{}
	store := newFakeOpenIndexStore()
	firstEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	secondStarted := make(chan struct{})
	secondEntered := make(chan struct{})
	done := make(chan error, 2)

	go func() {
		done <- l.withPolicyUpdate(func() error {
			close(firstEntered)
			<-releaseFirst
			_, err := replaceOpenIndex(store, compileOpenIndex([]OpenPolicyRule{
				openRuleForPath(PolicyAllow, OpOpenRW, "/first"),
			}), false)
			return err
		})
	}()
	<-firstEntered
	go func() {
		close(secondStarted)
		done <- l.withPolicyUpdate(func() error {
			close(secondEntered)
			_, err := replaceOpenIndex(store, compileOpenIndex([]OpenPolicyRule{
				openRuleForPath(PolicyDeny, OpOpenRW, "/second"),
			}), false)
			return err
		})
	}()
	<-secondStarted
	select {
	case <-secondEntered:
		t.Fatal("second policy writer entered while first generation was incomplete")
	case <-time.After(50 * time.Millisecond):
	}
	close(releaseFirst)
	for range 2 {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("serialized policy writer did not finish")
		}
	}
	if store.active != 2 {
		t.Fatalf("active token = %d, want two complete serialized generations", store.active)
	}
	secondKey := exactIndexKey(OpOpenRW, "/second")
	secondKey.Generation = 0
	if got := store.exact[secondKey]; got.Action != PolicyDeny {
		t.Fatalf("final generation missing second writer: %+v", got)
	}
	for key := range store.exact {
		if string(key.Path[:key.PathLen]) == "/first" {
			t.Fatal("first writer leaked into final generation")
		}
	}
}

func TestLoadPoliciesFailedLiveUpdatePreservesPublishedState(t *testing.T) {
	original := openRuleForPath(PolicyAllow, OpOpen, "/")
	l := &OpenLsm{}
	if err := l.LoadPolicies([]OpenPolicyRule{original}); err != nil {
		t.Fatal(err)
	}
	l.ebpfCollection = &ebpf.Collection{Maps: map[string]*ebpf.Map{}}
	if err := l.LoadPolicies([]OpenPolicyRule{openRuleForPath(PolicyDeny, OpOpenRW, "/new")}); err == nil {
		t.Fatal("live update with missing indexed maps unexpectedly succeeded")
	}
	if l.numPolicyRules != 1 || len(l.policyRules) != 1 || l.policyRules[0] != original || !l.defaultPolicyResult {
		t.Fatal("failed live update changed published in-memory policy")
	}
}

func TestLegacyLinearMatcherStateIsGone(t *testing.T) {
	bpfSource, err := os.ReadFile("bpf/lsm_open.bpf.c")
	if err != nil {
		t.Fatal(err)
	}
	goSource, err := os.ReadFile("file_open.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, legacy := range []string{"} policy_rules SEC", "} num_rules SEC", "} default_policy SEC", "struct policy_rule {"} {
		if strings.Contains(string(bpfSource), legacy) {
			t.Fatalf("dead legacy matcher state %q is still declared", legacy)
		}
	}
	for _, legacy := range []string{`Maps["num_rules"]`, `Maps["policy_rules"]`, `Maps["default_policy"]`} {
		if strings.Contains(string(goSource), legacy) {
			t.Fatalf("reload still writes dead legacy map %s", legacy)
		}
	}
}

func commitTestRules() []OpenPolicyRule {
	return []OpenPolicyRule{
		openDirectoryRuleForPath(PolicyAllow, OpOpenRW, policyPathOfLength(90, '/')),
		openRuleForPath(PolicyDeny, OpOpen, policyPathOfLength(93, 'x')),
	}
}

func TestCommitPolicyIndexesIsAllOrNothing(t *testing.T) {
	t.Run("success activates both", func(t *testing.T) {
		mutation, open := newFakeMutationIndexStore(), newFakeOpenIndexStore()
		if err := commitPolicyIndexes(mutation, open, commitTestRules(), false); err != nil {
			t.Fatal(err)
		}
		if mutation.active != 1 || open.active != 1 || len(mutation.allows) == 0 || len(open.prefix) == 0 {
			t.Fatalf("tokens %d/%d, entries %d/%d", mutation.active, open.active, len(mutation.allows), len(open.prefix))
		}
	})
	t.Run("open staging failure leaves mutation untouched", func(t *testing.T) {
		mutation, open := newFakeMutationIndexStore(), newFakeOpenIndexStore()
		open.failPutAt = 1
		if err := commitPolicyIndexes(mutation, open, commitTestRules(), false); err == nil {
			t.Fatal("failed open staging reported success")
		}
		if mutation.active != 0 || open.active != 0 || len(mutation.denies)+len(mutation.allows)+len(mutation.self) != 0 || len(open.prefix)+len(open.exact) != 0 {
			t.Fatalf("failed commit changed state: tokens %d/%d", mutation.active, open.active)
		}
	})
	t.Run("open activation failure rolls mutation back to a fresh token", func(t *testing.T) {
		mutation, open := newFakeMutationIndexStore(), newFakeOpenIndexStore()
		if err := commitPolicyIndexes(mutation, open, commitTestRules(), false); err != nil {
			t.Fatal(err)
		}
		liveAllows := len(mutation.allows)
		open.failActivation = true
		if err := commitPolicyIndexes(mutation, open, nil, true); err == nil {
			t.Fatal("failed open activation reported success")
		}
		// Token 1 -> 2 (activated) -> 3 (rolled back): generation 1 again, but
		// a value no hook can have snapshotted during the failed attempt.
		if mutation.active != 3 || open.active != 1 {
			t.Fatalf("tokens after rollback = %d/%d, want 3/1", mutation.active, open.active)
		}
		if len(mutation.allows) != liveAllows {
			t.Fatalf("rollback lost the live mutation generation: %d allows, want %d", len(mutation.allows), liveAllows)
		}
		for key := range mutation.allows {
			if uint32(key.Domain) != uint32(mutation.active&1) {
				t.Fatalf("staged generation %d not cleaned after rollback", key.Domain)
			}
		}
	})
}

func TestValidateOpenPolicyRulesRejectsUnenforceableShapes(t *testing.T) {
	good := openRuleForPath(PolicyAllow, OpOpenRW, "/ok")
	badAction := good
	badAction.Action = 2
	badOperation := good
	badOperation.Operation = 3
	badDirectory := good
	badDirectory.IsDirectory = 1 // no trailing slash
	for name, rule := range map[string]OpenPolicyRule{"action": badAction, "operation": badOperation, "directory": badDirectory} {
		if err := (&OpenLsm{}).LoadPolicies([]OpenPolicyRule{rule}); err == nil {
			t.Fatalf("rule with invalid %s accepted", name)
		}
	}
	if err := (&OpenLsm{}).LoadPolicies([]OpenPolicyRule{good, openDirectoryRuleForPath(PolicyDeny, OpOpen, "/dir/")}); err != nil {
		t.Fatalf("valid rules rejected: %v", err)
	}
}

func TestValidateKernelPolicyLimitsChecksEveryModuleBeforeUpdate(t *testing.T) {
	execRule := func(length int) PolicyRule {
		r := PolicyRule{Action: PolicyAllow, Operation: OpExec, PathLen: int32(length)}
		copy(r.Path[:], policyPathOfLength(length, 'x'))
		return r
	}
	openRule := PolicyRule{Action: PolicyAllow, Operation: OpOpenRW, PathLen: MaxPolicyPathLength}
	copy(openRule.Path[:], policyPathOfLength(MaxPolicyPathLength, 'x'))
	if err := ValidateKernelPolicyLimits(&PolicySet{Open: []PolicyRule{openRule}, Exec: []PolicyRule{execRule(MaxExecPolicyPathLength)}}); err != nil {
		t.Fatalf("policy at both limits rejected: %v", err)
	}
	if err := ValidateKernelPolicyLimits(&PolicySet{Open: []PolicyRule{openRule}, Exec: []PolicyRule{execRule(MaxExecPolicyPathLength + 1)}}); err == nil {
		t.Fatal("over-limit exec rule passed pre-update validation")
	}
	manager, err := os.ReadFile("manager.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(manager)
	validate, open := strings.Index(body, "ValidateKernelPolicyLimits(policies)"), strings.Index(body, "m.updateOpenLSM(policies); err != nil")
	if validate < 0 || open < 0 || validate > open {
		t.Fatal("UpdateRuntimeRules must validate every module before updating any")
	}
}

func TestLongPolicyPathSortPreservesEqualLengthOrder(t *testing.T) {
	pathA := policyPathOfLength(65, 'a')
	pathB := policyPathOfLength(65, 'b')
	rules := []OpenPolicyRule{
		openRuleForPath(PolicyDeny, OpOpenRW, pathA),
		openRuleForPath(PolicyAllow, OpOpenRW, pathB),
	}
	l := &OpenLsm{}
	if err := l.LoadPolicies(rules); err != nil {
		t.Fatal(err)
	}
	if l.policyRules[0] != rules[0] || l.policyRules[1] != rules[1] {
		t.Fatal("equal-length rule order changed")
	}
}

// legacyOpenDecision is the historical lsm_open matcher (sorted scan, byte
// prefix, directory-self, operation filter, first match wins) WITHOUT its
// 64-byte rule cutoff: the semantics the full-length index must preserve.
func legacyOpenDecision(rules []OpenPolicyRule, defaultAllow bool, path string, operation uint32) uint32 {
	for _, rule := range rules {
		length := int(rule.PathLen)
		rulePath := string(rule.Path[:length])
		matches := false
		if len(path) >= length-1 && path[:length-1] == rulePath[:length-1] {
			if len(path) >= length && path[length-1] == rulePath[length-1] {
				matches = true
			} else if rule.IsDirectory != 0 && len(path) == length-1 {
				matches = true
			}
		}
		if matches && (rule.Operation == OpOpen || rule.Operation == operation) {
			return rule.Action
		}
	}
	if defaultAllow {
		return PolicyAllow
	}
	return PolicyDeny
}

// indexedOpenDecision models check_open_indexed_policy over a compiled index:
// the LPM trie's longest prefix in the operation's domain, the exact
// directory-self entry, specificity then order, else the default.
func indexedOpenDecision(index compiledOpenIndex, defaultAllow bool, path string, operation uint32) uint32 {
	decision := uint32(PolicyDeny)
	if defaultAllow {
		decision = PolicyAllow
	}
	var prefix *openIndexRule
	for length := len(path); length >= 1 && prefix == nil; length-- {
		if value, ok := index.prefix[prefixIndexKey(operation, path[:length])]; ok {
			prefix = &value
		}
	}
	exact, hasExact := index.exact[exactIndexKey(operation, path)]
	switch {
	case hasExact && prefix == nil:
		decision = exact.Action
	case hasExact && exact.Specificity > prefix.Specificity:
		decision = exact.Action
	case hasExact && prefix.Specificity > exact.Specificity:
		decision = prefix.Action
	case hasExact && exact.Order <= prefix.Order:
		decision = exact.Action
	case prefix != nil:
		decision = prefix.Action
	}
	return decision
}

func TestOpenIndexPreservesLegacyByteSemanticsBeyond64Bytes(t *testing.T) {
	rng := rand.New(rand.NewSource(108))
	// Bases of 71 and 247 bytes: rules reach 77 and 253 bytes (plus "/"),
	// probes reach 79 and 255 bytes, the maximum resolvable path.
	for _, base := range []int{71, 247} {
		long := "/" + strings.Repeat("w", base-1)
		checkOpenIndexAgainstLegacy(t, rng, long)
	}
}

func checkOpenIndexAgainstLegacy(t *testing.T, rng *rand.Rand, long string) {
	t.Helper()
	randomTail := func(maxLen int) string {
		var b strings.Builder
		for i := rng.Intn(maxLen + 1); i > 0; i-- {
			b.WriteByte("ab/"[rng.Intn(3)])
		}
		return b.String()
	}
	for iteration := 0; iteration < 20000; iteration++ {
		var rules []OpenPolicyRule
		for i := rng.Intn(10) + 1; i > 0; i-- {
			path := long + randomTail(6)
			if rng.Intn(8) == 0 {
				path = "/"
			}
			rule := openRuleForPath(uint32(rng.Intn(2)), uint32(rng.Intn(3)), path)
			if strings.HasSuffix(path, "/") {
				rule.IsDirectory = 1
			}
			rules = append(rules, rule)
		}
		// Same ordering LoadPolicies applies before compiling.
		sort.SliceStable(rules, func(i, j int) bool { return rules[i].PathLen > rules[j].PathLen })
		defaultAllow := rootPathPolicy(rules)
		index := compileOpenIndex(rules)
		for probe := 0; probe < 8; probe++ {
			path := long + randomTail(8)
			operation := uint32(rng.Intn(3))
			want := legacyOpenDecision(rules, defaultAllow, path, operation)
			got := indexedOpenDecision(index, defaultAllow, path, operation)
			if got != want {
				t.Fatalf("path %q op %d: indexed=%d legacy=%d for rules %+v", path, operation, got, want, rules)
			}
		}
	}
}

func TestExecPolicyRejectsRulesTheKernelWouldSkip(t *testing.T) {
	rule := func(length int) ExecPolicyRule {
		path := policyPathOfLength(length, 'x')
		r := ExecPolicyRule{Action: PolicyDeny, Operation: OpExec, PathLen: int32(length)}
		copy(r.Path[:], path)
		return r
	}
	l := &ExecLsm{}
	if err := l.LoadPolicies([]ExecPolicyRule{rule(MaxExecPolicyPathLength)}); err != nil {
		t.Fatalf("%d-byte exec rule rejected: %v", MaxExecPolicyPathLength, err)
	}
	if err := l.LoadPolicies([]ExecPolicyRule{rule(MaxExecPolicyPathLength + 1)}); err == nil {
		t.Fatalf("%d-byte exec rule accepted; the kernel matcher would skip it", MaxExecPolicyPathLength+1)
	}
	if l.numPolicyRules != 1 || l.policyRules[0].PathLen != MaxExecPolicyPathLength {
		t.Fatal("rejected exec policy changed the loaded state")
	}
	for _, length := range []int{0, -1} {
		r := rule(2)
		r.PathLen = int32(length)
		if err := l.LoadPolicies([]ExecPolicyRule{r}); err == nil {
			t.Fatalf("exec rule with path length %d accepted", length)
		}
	}
	exactly := make([]ExecPolicyRule, MaxExecPolicyRules)
	for i := range exactly {
		exactly[i] = rule(10)
	}
	if err := l.LoadPolicies(exactly); err != nil {
		t.Fatalf("%d exec rules rejected: %v", MaxExecPolicyRules, err)
	}
	tooMany := make([]ExecPolicyRule, MaxExecPolicyRules+1)
	for i := range tooMany {
		tooMany[i] = rule(10)
	}
	if err := l.LoadPolicies(tooMany); err == nil {
		t.Fatalf("%d exec rules accepted; the kernel matcher only evaluates %d", len(tooMany), MaxExecPolicyRules)
	}
}

// The version document advertises the limits this package enforces.
func TestAdvertisedPolicyPathLimitsMatchEnforcement(t *testing.T) {
	if version.FilePolicyRules != MaxPolicyRules || version.ExecPolicyRules != MaxExecPolicyRules {
		t.Fatalf("advertised file/exec rule limits %d/%d, enforced %d/%d", version.FilePolicyRules, version.ExecPolicyRules, MaxPolicyRules, MaxExecPolicyRules)
	}
	if version.FilePolicyPathBytes != MaxPolicyPathLength || version.ExecPolicyPathBytes != MaxExecPolicyPathLength {
		t.Fatalf("advertised file/exec limits %d/%d, enforced %d/%d",
			version.FilePolicyPathBytes, version.ExecPolicyPathBytes, MaxPolicyPathLength, MaxExecPolicyPathLength)
	}
}
