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

func TestContainerCopyUpMarkerPreservesDeniedDecision(t *testing.T) {
	text := copyUpBPFSource(t)
	start := strings.Index(text, "int BPF_PROG(lsm_mark_overlay_write")
	if start < 0 {
		t.Fatal("container copy-up marker program not found")
	}
	rest := text[start:]
	end := strings.Index(rest, `SEC("raw_tracepoint/sys_exit")`)
	if end < 0 {
		t.Fatal("syscall-exit cleanup program not found after marker")
	}
	marker := rest[:end]
	deny := strings.Index(marker, "if (ret != 0)")
	mark := strings.Index(marker, "bpf_map_update_elem(&overlay_write_context")
	if deny < 0 || mark < 0 || deny > mark {
		t.Fatal("denied accumulated decision is not preserved before correlation marking")
	}
	if !strings.Contains(marker, "FMODE_WRITE") || !strings.Contains(marker, "OVERLAYFS_SUPER_MAGIC") {
		t.Fatal("marker is not limited to allowed overlay writes")
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
	if got := (&OpenLsm{}).requiredProgramNames(); !reflect.DeepEqual(got, []string{"lsm_open"}) {
		t.Fatalf("native required programs = %v", got)
	}

	container := &OpenLsm{containerOverlay: true}
	if got := container.requiredProgramNames(); !reflect.DeepEqual(got, []string{"lsm_open", "lsm_mark_overlay_write"}) {
		t.Fatalf("container required program order = %v", got)
	}
	if err := container.attachCopyUpExitTracepoint(&ebpf.Collection{}); err == nil {
		t.Fatal("container setup accepted missing required syscall-exit cleanup program")
	}
}
