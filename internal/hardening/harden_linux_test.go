//go:build linux

package hardening

import (
	"testing"

	"golang.org/x/sys/unix"
)

// TestBuildFilterShape verifies the classic-BPF layout: arch guard, one JEQ per
// denied syscall with a correct forward jump to the trailing DENY, then
// ALLOW/DENY. A wrong jump offset would silently allow a denied syscall, so this
// pins the exact structure.
func TestBuildFilterShape(t *testing.T) {
	denied := []uint32{unix.SYS_UNSHARE, unix.SYS_MOUNT, unix.SYS_SETNS}
	f := buildFilter(denied, 0xC000003E)

	// 4 preamble (LD arch, JEQ arch, RET, LD nr) + N JEQ + 2 (RET allow, RET deny).
	if want := 4 + len(denied) + 2; len(f) != want {
		t.Fatalf("filter length = %d, want %d", len(f), want)
	}
	if f[0].Code != unix.BPF_LD|unix.BPF_W|unix.BPF_ABS || f[0].K != 4 {
		t.Fatalf("instr[0] should load seccomp_data.arch (offset 4), got %+v", f[0])
	}
	if f[3].Code != unix.BPF_LD|unix.BPF_W|unix.BPF_ABS || f[3].K != 0 {
		t.Fatalf("instr[3] should load seccomp_data.nr (offset 0), got %+v", f[3])
	}

	// Each JEQ (indices 4..4+N-1) must jump exactly onto the trailing DENY
	// (the final instruction) when it matches.
	denyIdx := len(f) - 1
	for i := range denied {
		jeq := f[4+i]
		if jeq.K != denied[i] {
			t.Fatalf("JEQ[%d] tests nr %d, want %d", i, jeq.K, denied[i])
		}
		target := (4 + i) + 1 + int(jeq.Jt) // pc after this instr + jt
		if target != denyIdx {
			t.Fatalf("JEQ[%d] jumps to instr %d, want DENY at %d", i, target, denyIdx)
		}
	}

	// ALLOW then DENY at the tail.
	allow := f[len(f)-2]
	deny := f[len(f)-1]
	if allow.Code != unix.BPF_RET|unix.BPF_K || allow.K != uint32(unix.SECCOMP_RET_ALLOW) {
		t.Fatalf("penultimate instr should RET ALLOW, got %+v", allow)
	}
	wantDeny := uint32(unix.SECCOMP_RET_ERRNO) | uint32(unix.EPERM)&uint32(unix.SECCOMP_RET_DATA)
	if deny.Code != unix.BPF_RET|unix.BPF_K || deny.K != wantDeny {
		t.Fatalf("final instr should RET ERRNO(EPERM), got %+v", deny)
	}
}

// TestDeniedIncludesMountFamily guards against someone trimming the list below
// what closes the bind-mount bypass.
func TestDeniedIncludesMountFamily(t *testing.T) {
	must := map[uint32]string{
		unix.SYS_UNSHARE: "unshare", unix.SYS_MOUNT: "mount",
		unix.SYS_SETNS: "setns", unix.SYS_MOVE_MOUNT: "move_mount",
	}
	got := map[uint32]bool{}
	for _, nr := range deniedSyscalls() {
		got[nr] = true
	}
	for nr, name := range must {
		if !got[nr] {
			t.Fatalf("deniedSyscalls() must block %s (nr %d)", name, nr)
		}
	}
}
