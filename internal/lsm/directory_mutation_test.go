package lsm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"strings"
	"testing"
)

type mutationLogCapture struct{ entries []string }

func (c *mutationLogCapture) BroadcastLog(entry string) { c.entries = append(c.entries, entry) }

func TestDirectoryMutationHooksRequireWritableDirectoryRules(t *testing.T) {
	source, err := os.ReadFile("bpf/lsm_open.bpf.c")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	if got := strings.Count(text, "if (ret != 0) return ret;"); got < 6 {
		t.Fatalf("only %d chained LSM hooks preserve prior denial, want at least 6", got)
	}
	for _, hook := range []string{"lsm/path_mkdir", "lsm/path_unlink", "lsm/path_rmdir", "lsm/path_rename"} {
		if !strings.Contains(text, hook) {
			t.Fatalf("required directory mutation hook %q is absent", hook)
		}
	}
	for _, guard := range []string{
		"static __noinline int check_mutation_policy(const char *path)",
		"for (u32 i = 0; i < MAX_POLICY_PATH_LEN; i++)",
		"bpf_map_lookup_elem(&mutation_rules, &scratch->key)",
		"bpf_map_lookup_elem(&active_mutation_generation, &zero)",
		"scratch->key.generation = *active_generation;",
		"*flags & (MUTATION_GENERIC_DENY | MUTATION_RW_DIR_DENY)",
		"*flags & MUTATION_RW_DIR_ALLOW",
		"scratch->key.path[i] = '/';",
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
	if strings.Contains(text, "check_path_policy(scratch->target, operation)") {
		t.Fatal("mutation hooks still carry ordinary open-policy branches through the verifier")
	}
}

type fakeMutationRuleStore struct {
	active     uint32
	rules      map[mutationRuleKey]uint32
	putCalls   int
	failPutAt  int
	failActive bool
}

func (s *fakeMutationRuleStore) activeGeneration() (uint32, error) { return s.active, nil }

func (s *fakeMutationRuleStore) setActiveGeneration(generation uint32) error {
	if s.failActive {
		return errors.New("active generation write failed")
	}
	s.active = generation
	return nil
}

func (s *fakeMutationRuleStore) listRuleKeys() ([]mutationRuleKey, error) {
	keys := make([]mutationRuleKey, 0, len(s.rules))
	for key := range s.rules {
		keys = append(keys, key)
	}
	return keys, nil
}

func (s *fakeMutationRuleStore) putRule(key mutationRuleKey, flags uint32) error {
	s.putCalls++
	if s.failPutAt > 0 && s.putCalls == s.failPutAt {
		return errors.New("rule write failed")
	}
	s.rules[key] = flags
	return nil
}

func (s *fakeMutationRuleStore) deleteRule(key mutationRuleKey) error {
	delete(s.rules, key)
	return nil
}

func mutationTestKey(generation uint32, path string) mutationRuleKey {
	key := mutationRuleKey{Generation: generation, PathLen: uint32(len(path))}
	copy(key.Path[:], path)
	return key
}

func TestReplaceMutationRulesFlipsOnlyAfterCompleteStaging(t *testing.T) {
	oldKey := mutationTestKey(0, "/old/")
	store := &fakeMutationRuleStore{
		active: 0,
		rules:  map[mutationRuleKey]uint32{oldKey: mutationRWDirAllow},
	}
	entries := map[mutationRuleKey]uint32{
		mutationTestKey(0, "/new/"):    mutationRWDirAllow,
		mutationTestKey(0, "/denied/"): mutationGenericDeny,
	}

	if err := replaceMutationRules(store, entries); err != nil {
		t.Fatal(err)
	}
	if store.active != 1 {
		t.Fatalf("active generation = %d, want 1", store.active)
	}
	if _, exists := store.rules[oldKey]; exists {
		t.Fatal("old generation remained after successful transition")
	}
	for key, flags := range entries {
		key.Generation = 1
		if got := store.rules[key]; got != flags {
			t.Fatalf("staged flags for %q = %03b, want %03b", key.Path[:key.PathLen], got, flags)
		}
	}
}

func TestReplaceMutationRulesFailedStagingLeavesActiveGenerationIntact(t *testing.T) {
	oldKey := mutationTestKey(0, "/old/")
	store := &fakeMutationRuleStore{
		active:    0,
		rules:     map[mutationRuleKey]uint32{oldKey: mutationRWDirAllow},
		failPutAt: 2,
	}
	entries := map[mutationRuleKey]uint32{
		mutationTestKey(0, "/one/"): mutationRWDirAllow,
		mutationTestKey(0, "/two/"): mutationGenericDeny,
	}

	if err := replaceMutationRules(store, entries); err == nil {
		t.Fatal("failed staging unexpectedly succeeded")
	}
	if store.active != 0 || store.rules[oldKey] != mutationRWDirAllow {
		t.Fatal("failed staging changed active mutation authority")
	}
	for key := range store.rules {
		if key.Generation == 1 {
			t.Fatal("failed staging left partial inactive generation")
		}
	}
}

func TestReplaceMutationRulesFailedFlipLeavesActiveGenerationIntact(t *testing.T) {
	oldKey := mutationTestKey(0, "/old/")
	store := &fakeMutationRuleStore{
		active:     0,
		rules:      map[mutationRuleKey]uint32{oldKey: mutationRWDirAllow},
		failActive: true,
	}
	entries := map[mutationRuleKey]uint32{
		mutationTestKey(0, "/new/"): mutationRWDirAllow,
	}

	if err := replaceMutationRules(store, entries); err == nil {
		t.Fatal("failed generation flip unexpectedly succeeded")
	}
	if store.active != 0 || store.rules[oldKey] != mutationRWDirAllow {
		t.Fatal("failed generation flip changed active mutation authority")
	}
	for key := range store.rules {
		if key.Generation == 1 {
			t.Fatal("failed generation flip left staged inactive authority")
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

func TestCompileMutationRulesPreservesDenyAndDirectoryAuthority(t *testing.T) {
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
	}

	entries := compileMutationRules(rules)
	key := func(path string) mutationRuleKey {
		result := mutationRuleKey{PathLen: uint32(len(path))}
		copy(result.Path[:], path)
		return result
	}
	if got := entries[key("/home/agent/.npm/")]; got != mutationGenericDeny|mutationRWDirAllow {
		t.Fatalf("combined deny/allow flags = %03b", got)
	}
	if got := entries[key("/home/agent/private/")]; got != mutationRWDirDeny {
		t.Fatalf("writable-directory deny flags = %03b", got)
	}
	if _, ok := entries[key("/home/agent/file")]; ok {
		t.Fatal("writable file rule became directory mutation authority")
	}
	if _, ok := entries[key("/ignored/")]; ok {
		t.Fatal("generic allow became directory mutation authority")
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
