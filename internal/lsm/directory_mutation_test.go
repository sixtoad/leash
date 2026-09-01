package lsm

import (
	"bytes"
	"encoding/binary"
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
		"rule->is_directory && !directory_self && rule->operation == OP_OPEN_RW",
		"return mutation_allowed ? 1 : 0;",
		"if (rule->operation == OP_OPEN && rule->action == 0)",
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
	} {
		if !strings.Contains(text, guard) {
			t.Fatalf("directory mutation enforcement is missing %q", guard)
		}
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
