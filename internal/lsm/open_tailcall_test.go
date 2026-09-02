package lsm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

func TestPopulateOpenTailCallRejectsMissingResources(t *testing.T) {
	tests := []struct {
		name string
		coll *ebpf.Collection
		want string
	}{
		{name: "nil collection", want: "collection is nil"},
		{name: "missing map", coll: &ebpf.Collection{Maps: map[string]*ebpf.Map{}, Programs: map[string]*ebpf.Program{}}, want: `map "open_tail_calls" not found`},
		{name: "missing canonicalizer", coll: &ebpf.Collection{Maps: map[string]*ebpf.Map{openTailCallMapName: {}}, Programs: map[string]*ebpf.Program{}}, want: `program "lsm_open_canonicalize" not found`},
		{name: "missing policy", coll: &ebpf.Collection{Maps: map[string]*ebpf.Map{openTailCallMapName: {}}, Programs: map[string]*ebpf.Program{openTailCallCanonicalizerName: {}}}, want: `program "lsm_open_policy" not found`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := populateOpenTailCall(tt.coll)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("populateOpenTailCall() error = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestOpenTailCallFallthroughIsFailClosed(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("bpf", "lsm_open.bpf.c"))
	if err != nil {
		t.Fatal(err)
	}
	body := string(source)
	for _, required := range []string{
		"bpf_tail_call(ctx, &open_tail_calls, 0);\n    return -13;",
		"int BPF_PROG(lsm_open_canonicalize, struct file *file)",
		"bpf_tail_call(ctx, &open_tail_calls, 1);\n    return -13;",
		"int BPF_PROG(lsm_open_policy, struct file *file)",
		"struct open_path_scratch *scratch = bpf_map_lookup_elem(&open_path_scratch_map, &zero);",
		"if (relative_len == 0 || path_len != relative_len) return false;",
		"return (int)pid_len + 12; // /<pid>/setgroups plus NUL",
		"return (int)pid_len + (int)tid_len + 27; // /PID/task/TID/attr/apparmor/exec plus NUL",
		"return (int)pid_len + (int)tid_len + 11; // /PID/task/TID/fd plus NUL",
		"if (path[0] != '/' || path[1] < '0' || path[1] > '9') return false;",
	} {
		if !strings.Contains(body, required) {
			t.Fatalf("file-open BPF source is missing fail-closed tail-call contract %q", required)
		}
	}
}
