//go:build linux

// Package hardening locks down a workload process just before it execs the
// agent. It closes the userns→mount-ns→bind-mount bypass of leash's
// cgroup-scoped path LSM: without a way to mount, a process can't alias a
// policy-denied path under an allowed prefix (which defeats path matching).
// Applied via `leash --harden-exec` in the native workload launch, so it is
// inherited across exec and covers the agent and every subprocess it spawns.
package hardening

import (
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Apply sets no-new-privs, drops the capability bounding set, and installs the
// seccomp filter. Order matters: no-new-privs must precede the filter so an
// unprivileged process may install it.
func Apply() error {
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("no_new_privs: %w", err)
	}
	dropCapBounding()
	if err := installSeccomp(); err != nil {
		return fmt.Errorf("seccomp: %w", err)
	}
	return nil
}

// dropCapBounding removes every capability from the bounding set (best-effort;
// invalid cap numbers simply error). Caps mean nothing to the dropped-privilege
// agent today, but this removes the ceiling for any future setuid path.
func dropCapBounding() {
	for c := 0; c <= 63; c++ {
		_ = unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(c), 0, 0, 0)
	}
}

// deniedSyscalls: the mount family + namespace-entry calls, blocked with EPERM.
// Blocking mount defeats the bind-mount alias regardless of namespaces; blocking
// unshare/setns removes the user/mount-namespace entry the agent used. clone and
// clone3 are deliberately NOT denied — breaking them breaks threading/fork, and
// blocking mount already closes the file bypass.
func deniedSyscalls() []uint32 {
	return []uint32{
		unix.SYS_UNSHARE, unix.SYS_SETNS,
		unix.SYS_MOUNT, unix.SYS_UMOUNT2, unix.SYS_PIVOT_ROOT,
		unix.SYS_MOVE_MOUNT, unix.SYS_OPEN_TREE, unix.SYS_FSOPEN,
		unix.SYS_FSCONFIG, unix.SYS_FSMOUNT, unix.SYS_MOUNT_SETATTR,
	}
}

func nativeAuditArch() (uint32, bool) {
	switch runtime.GOARCH {
	case "amd64":
		return 0xC000003E, true // AUDIT_ARCH_X86_64
	case "arm64":
		return 0xC00000B7, true // AUDIT_ARCH_AARCH64
	}
	return 0, false
}

func installSeccomp() error {
	arch, ok := nativeAuditArch()
	if !ok {
		return fmt.Errorf("unsupported arch %s", runtime.GOARCH)
	}
	filter := buildFilter(deniedSyscalls(), arch)
	prog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	return unix.Prctl(unix.PR_SET_SECCOMP, uintptr(unix.SECCOMP_MODE_FILTER), uintptr(unsafe.Pointer(&prog)), 0, 0)
}

// buildFilter emits a classic-BPF seccomp program: reject a foreign arch (blocks
// the 32-bit-syscall bypass), then EPERM each denied syscall, else allow.
func buildFilter(denied []uint32, arch uint32) []unix.SockFilter {
	retAllow := uint32(unix.SECCOMP_RET_ALLOW)
	retEPERM := uint32(unix.SECCOMP_RET_ERRNO) | uint32(unix.EPERM)&uint32(unix.SECCOMP_RET_DATA)

	f := []unix.SockFilter{
		bpfStmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, 4), // A = seccomp_data.arch
		bpfJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, arch, 1, 0),
		bpfStmt(unix.BPF_RET|unix.BPF_K, retEPERM), // arch mismatch → deny
		bpfStmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, 0), // A = seccomp_data.nr
	}
	n := len(denied)
	for i, nr := range denied {
		// On match, jump past the remaining checks + the ALLOW to the trailing
		// DENY: (n-1-i) more JEQs + 1 ALLOW = n-i instructions.
		f = append(f, bpfJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, nr, uint8(n-i), 0))
	}
	f = append(f, bpfStmt(unix.BPF_RET|unix.BPF_K, retAllow))
	f = append(f, bpfStmt(unix.BPF_RET|unix.BPF_K, retEPERM))
	return f
}

func bpfStmt(code uint16, k uint32) unix.SockFilter { return unix.SockFilter{Code: code, K: k} }
func bpfJump(code uint16, k uint32, jt, jf uint8) unix.SockFilter {
	return unix.SockFilter{Code: code, Jt: jt, Jf: jf, K: k}
}
