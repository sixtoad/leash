package lsm

import (
	"os"
	"strings"
	"testing"
)

// Issue #110: lsm_exec must never evaluate policy over bytes no resolver wrote,
// must deny (audited) when every resolver fails, and the comparison loops must
// keep a constant bound the verifier can see regardless of clang folding.
func TestExecPathResolutionIsInitializedAndFailsClosed(t *testing.T) {
	source, err := os.ReadFile("bpf/lsm_exec.bpf.c")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	resolve := strings.Index(text, "static __always_inline bool resolve_exec_path(")
	hook := strings.Index(text, "int BPF_PROG(lsm_exec,")
	if resolve < 0 || hook < 0 || resolve > hook {
		t.Fatal("lsm_exec must resolve its path through resolve_exec_path")
	}
	body := text[resolve:hook]
	zero := strings.Index(body, "__builtin_memset(path, 0, MAX_PATH_LEN);")
	dpath := strings.Index(body, "bpf_d_path(")
	if zero < 0 || dpath < 0 || zero > dpath {
		t.Fatal("exec path buffer must be fully zeroed before any resolution attempt")
	}
	if strings.Count(body, "if (ret > 1) {") != 3 {
		t.Fatal("every exec path resolver (d_path, filename, dentry) must have its result checked")
	}
	if !strings.Contains(body, `__builtin_memcpy(path, "<unresolved>", sizeof("<unresolved>"));`) {
		t.Fatal("an unresolved exec path must be reset to a fixed audit marker")
	}
	for _, guard := range []string{
		"int policy_result = 0; // deny unless policy evaluation runs and allows",
		"if (resolve_exec_path(bprm, path)) {\n        policy_result = check_exec_policy(path);\n    }",
		"return policy_result ? 0 : -13;",
	} {
		if !strings.Contains(text, guard) {
			t.Fatalf("lsm_exec fail-closed contract missing %q", guard)
		}
	}
}

func TestPathComparisonLoopsKeepVerifierVisibleBounds(t *testing.T) {
	for file, guards := range map[string][]string{
		"bpf/lsm_exec.bpf.c": {
			"if (max_len > 64) max_len = 64;\n",
			"barrier_var(max_len);\n\n    #pragma clang loop unroll(disable)\n    for (int i = 0; i < 64; i++) {",
		},
		"bpf/lsm_open.bpf.c": {
			"if (len == 0 || len >= HL_MAX_COMP) {\n            return -2;\n        }",
			"barrier_var(len);\n        if (off - (int)len - 1 < 1) {",
		},
	} {
		source, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, guard := range guards {
			if !strings.Contains(string(source), guard) {
				t.Errorf("%s is missing verifier bound guard %q", file, guard)
			}
		}
	}
}
