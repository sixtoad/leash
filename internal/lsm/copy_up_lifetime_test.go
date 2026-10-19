package lsm

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

func copyUpBPFSource(t *testing.T) string {
	t.Helper()
	source, err := os.ReadFile("bpf/lsm_open.bpf.c")
	if err != nil {
		t.Fatal(err)
	}
	return string(source)
}

// The overlay correlation must be installed by the program that made the
// allow decision, after that decision. A second program on lsm/file_open runs
// before lsm_open (trampolines run the newest link first), and a marker there
// turned every overlay-rootfs write into an allow (#186/#125).
func TestContainerCopyUpMarkerFollowsTheDecision(t *testing.T) {
	text := copyUpBPFSource(t)
	if strings.Count(text, `SEC("lsm/file_open")`) != 3 {
		t.Fatal("lsm/file_open must carry only lsm_open and its two tail-call stages")
	}
	if strings.Contains(text, "lsm_mark_overlay_write") {
		t.Fatal("separate overlay marker program reintroduced")
	}
	start := strings.Index(text, "static __always_inline int mark_allowed_overlay_open(struct file *file)")
	if start < 0 {
		t.Fatal("overlay open marker helper not found")
	}
	helper := text[start:]
	helper = helper[:strings.Index(helper, "\n}\n")]
	for _, guard := range []string{"FMODE_WRITE", "OVERLAYFS_SUPER_MAGIC", "container_overlay_mode", "current_is_io_worker()", "bpf_map_update_elem(&overlay_write_context"} {
		if !strings.Contains(helper, guard) {
			t.Fatalf("overlay open marker lacks %q", guard)
		}
	}
	policy := text[strings.Index(text, "int BPF_PROG(lsm_open_policy"):]
	policy = policy[:strings.Index(policy, `SEC("raw_tracepoint/sys_exit")`)]
	token := strings.Index(policy, "*confirmed_token != lookup->activation_token")
	mark := strings.Index(policy, "if (policy_result && mark_allowed_overlay_open(file) != 0) {")
	submit := strings.Index(policy, "bpf_ringbuf_submit(event, 0);\n    }\n\n    // Return policy decision")
	if token < 0 || mark < 0 || submit < 0 || !(token < mark && mark < submit) {
		t.Fatal("overlay correlation is not installed only after the final allow decision")
	}
	if !strings.Contains(policy[mark:], "policy_result = 0;") {
		t.Fatal("a failed overlay correlation does not fail closed")
	}
}

func TestContainerCopyUpContextIsClearedAtSyscallExit(t *testing.T) {
	text := copyUpBPFSource(t)
	start := strings.Index(text, `SEC("raw_tracepoint/sys_exit")`)
	if start < 0 {
		t.Fatal("container copy-up correlation is not bounded by syscall exit")
	}
	cleanup := text[start:]
	if !strings.Contains(cleanup, "bpf_map_delete_elem(&overlay_write_context") {
		t.Fatal("syscall-exit hook does not clear container copy-up correlation")
	}
}

func TestContainerCopyUpAttachmentOrderAndRequiredCleanup(t *testing.T) {
	want := []string{"lsm_open", "lsm_mkdir", "lsm_unlink", "lsm_rmdir", "lsm_rename_source", "lsm_rename_destination", "lsm_mknod"}
	if got := (&OpenLsm{}).requiredProgramNames(); !reflect.DeepEqual(got, want) {
		t.Fatalf("native required programs = %v", got)
	}

	container := &OpenLsm{containerOverlay: true}
	if got := container.requiredProgramNames(); !reflect.DeepEqual(got, want) {
		t.Fatalf("container required program order = %v", got)
	}
	if err := container.attachCopyUpExitTracepoint(&ebpf.Collection{}); err == nil {
		t.Fatal("container setup accepted missing required syscall-exit cleanup program")
	}
}

// Both rename halves share lsm/path_rename and the kernel runs the one attached
// last first; the destination half installs the overlay correlation for its
// endpoint, so a correlation skip in the other half let a rename of a
// non-mutable source succeed whenever the destination was permitted.
func TestRenameHalvesNeverSkipOnOverlayCorrelation(t *testing.T) {
	text := copyUpBPFSource(t)
	for _, signature := range []string{"int BPF_PROG(lsm_rename_source,", "int BPF_PROG(lsm_rename_destination,"} {
		start := strings.Index(text, signature)
		if start < 0 {
			t.Fatalf("%s not found", signature)
		}
		body := text[start:]
		body = body[:strings.Index(body, "\n}\n")]
		if strings.Contains(body, "mutation_overlay_context_active()") {
			t.Fatalf("%s skips its endpoint check on the overlay correlation", signature)
		}
		if !strings.Contains(body, "check_directory_mutation(") {
			t.Fatalf("%s does not check its endpoint", signature)
		}
	}
}

// The correlation lets through only opens overlayfs makes on its own behalf
// (under its mounter's credentials). Without the cred check, a second open the
// task issued in the same syscall, such as a second inline io_uring openat
// after an allowed overlay write, skipped policy.
func TestOverlayCorrelationSkipsOnlyOverlayfsCredentialOpens(t *testing.T) {
	text := copyUpBPFSource(t)
	start := strings.Index(text, "int BPF_PROG(lsm_open, struct file *file)")
	if start < 0 {
		t.Fatal("lsm_open not found")
	}
	body := text[start:]
	body = body[:strings.Index(body, "\n}\n")]
	if !strings.Contains(body, "} else if (active && current_creds_overridden()) {\n        return 0;") {
		t.Fatal("lsm_open skips on the overlay correlation without requiring overlayfs's overridden credentials")
	}
	if strings.Contains(body, "} else if (active) {") {
		t.Fatal("lsm_open still skips on the bare overlay correlation")
	}
	if !strings.Contains(text, "return BPF_CORE_READ(task, cred) != BPF_CORE_READ(task, real_cred);") {
		t.Fatal("credential-override check is not a cred/real_cred comparison")
	}
}

// The hard-link decision stage is tail-called. Every OptionalProgramNames entry
// is attached as an LSM program, so the stage must never be listed there: an
// attached lsm_link_policy would run without lsm_link's reconstruction (#29).
func TestHardlinkDecisionStageIsStrippedButNeverAttached(t *testing.T) {
	for _, overlay := range []bool{false, true} {
		config := (&OpenLsm{containerOverlay: overlay}).bpfConfig()
		if !reflect.DeepEqual(config.OptionalProgramNames, []string{"lsm_link"}) {
			t.Fatalf("optional attached programs = %v", config.OptionalProgramNames)
		}
		if !reflect.DeepEqual(config.OptionalStageNames, []string{"lsm_link_policy"}) {
			t.Fatalf("optional tail-called stages = %v", config.OptionalStageNames)
		}
		for _, name := range config.ProgramNames {
			if name == "lsm_link_policy" {
				t.Fatal("decision stage listed as a required attached program")
			}
		}
	}
	if !reflect.DeepEqual(attachProbeOptionalPrograms, []string{"lsm_link", "lsm_link_policy"}) {
		t.Fatalf("attach probe strips %v, want the guard and its stage", attachProbeOptionalPrograms)
	}
}
