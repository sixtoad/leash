package lsm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"strings"
	"testing"
	"unsafe"
)

type mutationLogCapture struct{ entries []string }

func (c *mutationLogCapture) BroadcastLog(entry string) { c.entries = append(c.entries, entry) }

func TestDirectoryMutationHooksRequireWritableDirectoryRules(t *testing.T) {
	source, err := os.ReadFile("bpf/lsm_open.bpf.c")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, hook := range []string{"lsm/path_mkdir", "lsm/path_unlink", "lsm/path_rmdir", "lsm/path_rename"} {
		if !strings.Contains(text, hook) {
			t.Fatalf("required directory mutation hook %q is absent", hook)
		}
	}
	for _, signature := range []string{
		"int BPF_PROG(lsm_mkdir,",
		"int BPF_PROG(lsm_unlink,",
		"int BPF_PROG(lsm_rmdir,",
		"int BPF_PROG(lsm_rename_source,",
		"int BPF_PROG(lsm_rename_destination,",
	} {
		start := strings.Index(text, signature)
		if start < 0 {
			t.Fatalf("required directory mutation function %q is absent", signature)
		}
		end := start + 700
		if end > len(text) {
			end = len(text)
		}
		if !strings.Contains(text[start:end], "if (ret != 0) return ret;") {
			t.Fatalf("%s does not preserve a prior LSM denial", signature)
		}
	}
	for _, guard := range []string{
		"static __noinline int check_mutation_policy(const char *path)",
		"for (int i = 0; i < MAX_PATH_LEN; i++)",
		"bpf_map_lookup_elem(&mutation_deny_rules, &scratch->prefix)",
		"bpf_map_lookup_elem(&mutation_allow_rules, &scratch->prefix)",
		"bpf_map_lookup_elem(&mutation_self_deny_rules, &scratch->exact)",
		"bpf_map_lookup_elem(&active_mutation_generation, &zero)",
		"u64 activation_token = *token_ptr;",
		"if (!deny) {",
		"if (!self_deny) {",
		"if (!scratch) return 0;",
		"if (!confirmed_token) return 0;",
		"*confirmed_token == scratch->activation_token",
		"if (bpf_probe_read_kernel(&c, sizeof(c), name + (i & (MAX_PATH_LEN - 1))) < 0)",
		"emit_mutation_decision(unresolved_path, operation, 0)",
		"current_is_io_worker()) return -1",
		"bpf_map_update_elem(&overlay_write_context, &pid_tgid, &correlation, BPF_ANY) < 0",
		"int BPF_PROG(lsm_rename_source",
		"int BPF_PROG(lsm_rename_destination",
		"umode_t mode, int ret)",
		"struct dentry *dentry, int ret)",
		"return check_directory_mutation(old_dir, old_dentry, OP_RENAME, false);",
		"ret = check_directory_mutation(new_dir, new_dentry, OP_RENAME, false);",
		"if (ret != 0) return ret;",
		"bpf_map_delete_elem(&overlay_write_context, &pid_tgid);",
		"int allowed = check_mutation_policy(scratch->target);",
	} {
		if !strings.Contains(text, guard) {
			t.Fatalf("directory mutation enforcement is missing %q", guard)
		}
	}
	if strings.Contains(text, "if (deny || self_deny)") {
		t.Fatal("nullable mutation map pointers are merged before the verifier")
	}
	if strings.Contains(text, "check_path_policy(scratch->target, operation)") {
		t.Fatal("mutation hooks still carry ordinary open-policy branches through the verifier")
	}
	if got := strings.Count(text, "bpf_map_lookup_elem(&active_mutation_generation, &zero)"); got != 2 {
		t.Fatalf("mutation decision performs %d activation-token lookups, want snapshot and confirmation", got)
	}
}

type fakeMutationIndexStore struct {
	active     uint64
	denies     map[mutationPrefixRuleKey]uint8
	allows     map[mutationPrefixRuleKey]uint8
	self       map[mutationExactRuleKey]uint8
	putCalls   int
	failPutAt  int
	failActive bool
	failDelete bool
}

func newFakeMutationIndexStore() *fakeMutationIndexStore {
	return &fakeMutationIndexStore{denies: map[mutationPrefixRuleKey]uint8{}, allows: map[mutationPrefixRuleKey]uint8{}, self: map[mutationExactRuleKey]uint8{}}
}
func (s *fakeMutationIndexStore) activeToken() (uint64, error) { return s.active, nil }
func (s *fakeMutationIndexStore) setActiveToken(v uint64) error {
	if s.failActive {
		return errors.New("active")
	}
	s.active = v
	return nil
}
func (s *fakeMutationIndexStore) listDenyKeys() ([]mutationPrefixRuleKey, error) {
	var r []mutationPrefixRuleKey
	for k := range s.denies {
		r = append(r, k)
	}
	return r, nil
}
func (s *fakeMutationIndexStore) listAllowKeys() ([]mutationPrefixRuleKey, error) {
	var r []mutationPrefixRuleKey
	for k := range s.allows {
		r = append(r, k)
	}
	return r, nil
}
func (s *fakeMutationIndexStore) listSelfDenyKeys() ([]mutationExactRuleKey, error) {
	var r []mutationExactRuleKey
	for k := range s.self {
		r = append(r, k)
	}
	return r, nil
}
func (s *fakeMutationIndexStore) fail() error {
	s.putCalls++
	if s.failPutAt > 0 && s.putCalls == s.failPutAt {
		return errors.New("put")
	}
	return nil
}
func (s *fakeMutationIndexStore) putDeny(k mutationPrefixRuleKey, v uint8) error {
	if e := s.fail(); e != nil {
		return e
	}
	s.denies[k] = v
	return nil
}
func (s *fakeMutationIndexStore) putAllow(k mutationPrefixRuleKey, v uint8) error {
	if e := s.fail(); e != nil {
		return e
	}
	s.allows[k] = v
	return nil
}
func (s *fakeMutationIndexStore) putSelfDeny(k mutationExactRuleKey, v uint8) error {
	if e := s.fail(); e != nil {
		return e
	}
	s.self[k] = v
	return nil
}
func (s *fakeMutationIndexStore) deleteDeny(k mutationPrefixRuleKey) error {
	if s.failDelete {
		return errors.New("delete")
	}
	delete(s.denies, k)
	return nil
}
func (s *fakeMutationIndexStore) deleteAllow(k mutationPrefixRuleKey) error {
	if s.failDelete {
		return errors.New("delete")
	}
	delete(s.allows, k)
	return nil
}
func (s *fakeMutationIndexStore) deleteSelfDeny(k mutationExactRuleKey) error {
	if s.failDelete {
		return errors.New("delete")
	}
	delete(s.self, k)
	return nil
}
func mutationPrefixTestKey(path string) mutationPrefixRuleKey {
	k := mutationPrefixRuleKey{PrefixLen: 8 + uint32(len(path))*8}
	copy(k.Path[:], path)
	return k
}
func mutationSelfTestKey(path string) mutationExactRuleKey {
	k := mutationExactRuleKey{PathLen: uint32(len(path))}
	copy(k.Path[:], path)
	return k
}

func TestReplaceMutationIndexTokenAndStaging(t *testing.T) {
	s := newFakeMutationIndexStore()
	idx := compiledMutationIndex{map[mutationPrefixRuleKey]uint8{mutationPrefixTestKey("/deny/"): 1}, map[mutationPrefixRuleKey]uint8{mutationPrefixTestKey("/allow/"): 1}, map[mutationExactRuleKey]uint8{mutationSelfTestKey("/deny"): 1}}
	old := mutationPrefixTestKey("/old/")
	s.allows[old] = 1
	if _, err := replaceMutationIndex(s, idx); err != nil {
		t.Fatal(err)
	}
	if s.active != 1 {
		t.Fatalf("token=%d", s.active)
	}
	if _, ok := s.allows[old]; ok {
		t.Fatal("old generation survived committed replacement")
	}
	for key := range s.denies {
		if key.Domain != 1 {
			t.Fatalf("deny staged in generation %d", key.Domain)
		}
	}
	for key := range s.allows {
		if key.Domain != 1 {
			t.Fatalf("allow staged in generation %d", key.Domain)
		}
	}
	for key := range s.self {
		if key.Generation != 1 {
			t.Fatalf("self deny staged in generation %d", key.Generation)
		}
	}
	s.active = ^uint64(0)
	if _, err := replaceMutationIndex(s, idx); err == nil || !strings.Contains(err.Error(), "exhausted") {
		t.Fatalf("wrap=%v", err)
	}
	for name, configure := range map[string]func(*fakeMutationIndexStore){
		"partial staging": func(store *fakeMutationIndexStore) { store.failPutAt = 2 },
		"activation":      func(store *fakeMutationIndexStore) { store.failActive = true },
	} {
		t.Run(name, func(t *testing.T) {
			failed := newFakeMutationIndexStore()
			failed.allows[old] = 1
			configure(failed)
			if _, err := replaceMutationIndex(failed, idx); err == nil {
				t.Fatal("failed replacement unexpectedly succeeded")
			}
			if failed.active != 0 || failed.allows[old] != 1 {
				t.Fatal("failed replacement changed active authority")
			}
			for key := range failed.denies {
				if key.Domain == 1 {
					t.Fatal("failed replacement retained staged deny")
				}
			}
			for key := range failed.allows {
				if key.Domain == 1 {
					t.Fatal("failed replacement retained staged allow")
				}
			}
			for key := range failed.self {
				if key.Generation == 1 {
					t.Fatal("failed replacement retained staged self deny")
				}
			}
		})
	}

	debt := newFakeMutationIndexStore()
	debt.allows[old] = 1
	debt.failDelete = true
	result, err := replaceMutationIndex(debt, idx)
	if err != nil {
		t.Fatalf("committed replacement returned fatal cleanup error: %v", err)
	}
	if debt.active != 1 || result.cleanupDebt == nil {
		t.Fatalf("post-commit cleanup: token=%d debt=%v", debt.active, result.cleanupDebt)
	}
}

func TestMutationTokenRejectsSameSlotABA(t *testing.T) {
	snapshot, reloaded := uint64(0), uint64(2)
	if snapshot&1 != reloaded&1 {
		t.Fatal("test setup does not reuse the same generation slot")
	}
	if snapshot == reloaded {
		t.Fatal("full token equality accepted an ABA reload")
	}
}

func TestMutationIndexPreservesFullPathBoundaries(t *testing.T) {
	if got := unsafe.Sizeof(mutationPrefixRuleKey{}); got != 260 {
		t.Fatalf("mutation LPM key size = %d, want 260", got)
	}
	for _, length := range []int{64, 65, MaxPolicyPathLength} {
		path := policyPathOfLength(length, '/')
		idx := compileMutationIndex([]OpenPolicyRule{
			openDirectoryRuleForPath(PolicyAllow, OpOpenRW, path),
			openDirectoryRuleForPath(PolicyDeny, OpOpen, path),
		})
		prefix := mutationPrefixTestKey(path)
		if idx.allows[prefix] != 1 || idx.denies[prefix] != 1 {
			t.Fatalf("%d-byte mutation prefix lost allow or deny", length)
		}
		selfPath := path[:len(path)-1]
		if idx.selfDenies[mutationSelfTestKey(selfPath)] != 1 {
			t.Fatalf("%d-byte directory self deny missing", length)
		}
	}
}

func TestLoadPoliciesRejectsOverflowBeforeChangingState(t *testing.T) {
	existing := OpenPolicyRule{Action: PolicyAllow, Operation: OpOpen, PathLen: 1}
	existing.Path[0] = '/'
	l := &OpenLsm{policyRules: []OpenPolicyRule{existing}, numPolicyRules: 1}

	if err := l.LoadPolicies(make([]OpenPolicyRule, MaxPolicyRules+1)); err == nil {
		t.Fatal("257th policy rule was accepted")
	}
	if l.numPolicyRules != 1 || len(l.policyRules) != 1 || l.policyRules[0] != existing {
		t.Fatal("overflow rejection changed OpenLsm state")
	}
}

func TestCompileMutationIndexPreservesDenyAndDirectoryAuthority(t *testing.T) {
	rule := func(action, operation, directory uint32, path string) OpenPolicyRule {
		result := OpenPolicyRule{
			Action:      action,
			Operation:   operation,
			PathLen:     uint32(len(path)),
			IsDirectory: directory,
		}
		copy(result.Path[:], path)
		return result
	}
	rules := []OpenPolicyRule{
		rule(PolicyAllow, OpOpenRW, 1, "/home/agent/.npm/"),
		rule(PolicyDeny, OpOpen, 1, "/home/agent/.npm/"),
		rule(PolicyDeny, OpOpenRW, 1, "/home/agent/private/"),
		rule(PolicyAllow, OpOpenRW, 0, "/home/agent/file"),
		rule(PolicyAllow, OpOpen, 1, "/ignored/"),
		rule(PolicyDeny, OpOpen, 0, "/generic-prefix"),
	}

	idx := compileMutationIndex(rules)
	if idx.denies[mutationPrefixTestKey("/home/agent/.npm/")] != 1 || idx.allows[mutationPrefixTestKey("/home/agent/.npm/")] != 1 {
		t.Fatal("combined deny/allow missing")
	}
	if idx.selfDenies[mutationSelfTestKey("/home/agent/.npm")] != 1 {
		t.Fatal("self deny missing")
	}
	if idx.denies[mutationPrefixTestKey("/home/agent/private/")] != 1 {
		t.Fatal("rw deny missing")
	}
	if _, ok := idx.allows[mutationPrefixTestKey("/home/agent/file")]; ok {
		t.Fatal("writable file rule became directory mutation authority")
	}
	if _, ok := idx.allows[mutationPrefixTestKey("/ignored/")]; ok {
		t.Fatal("generic allow became directory mutation authority")
	}
	if idx.denies[mutationPrefixTestKey("/generic-prefix")] != 1 {
		t.Fatal("generic file deny prefix was not retained")
	}
	malformed := compileMutationIndex([]OpenPolicyRule{rule(PolicyDeny, OpOpen, 1, "/directory-without-slash")})
	if len(malformed.selfDenies) != 0 {
		t.Fatal("malformed directory rule stripped a real path byte into exact-self authority")
	}
}

func TestDirectoryMutationDenialNamesOperationAndPath(t *testing.T) {
	logger, err := NewSharedLogger("")
	if err != nil {
		t.Fatal(err)
	}
	capture := &mutationLogCapture{}
	logger.SetBroadcaster(capture)
	l := &OpenLsm{logger: logger}

	for op, want := range map[uint32]string{
		mutationOpMkdir:  "file.mkdir",
		mutationOpUnlink: "file.unlink",
		mutationOpRmdir:  "file.rmdir",
		mutationOpRename: "file.rename",
	} {
		event := OpenEvent{PID: 42, TGID: 42, Operation: op, Result: -13}
		copy(event.Comm[:], "fixture\x00")
		copy(event.Path[:], "/home/agent/undeclared/child\x00")
		var payload bytes.Buffer
		if err := binary.Write(&payload, binary.LittleEndian, event); err != nil {
			t.Fatal(err)
		}
		l.handleEvent(payload.Bytes())
		got := capture.entries[len(capture.entries)-1]
		if !strings.Contains(got, "event="+want) ||
			!strings.Contains(got, `path="/home/agent/undeclared/child"`) ||
			!strings.Contains(got, "decision=denied") {
			t.Fatalf("mutation denial is not actionable: %s", got)
		}
	}
}

func TestHardlinkComponentReadIsVerifierBoundedAndFailsClosed(t *testing.T) {
	source, err := os.ReadFile("bpf/lsm_open.bpf.c")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, guard := range []string{
		"len == 0 || len >= HL_MAX_COMP",
		"bpf_probe_read_kernel_str(comp, sizeof(comp), name)",
		"read < 0 || read <= (long)len",
		"hl_build_within(old_dentry, mnt_root, s->raw)",
		"if (sstart == -2) {\n        return -13;",
	} {
		if !strings.Contains(text, guard) {
			t.Fatalf("hard-link component read is missing %q", guard)
		}
	}
}
