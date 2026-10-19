//go:build linux

// Package hardening locks down a workload process just before it execs the
// agent. It closes the userns→mount-ns→bind-mount bypass of leash's
// cgroup-scoped path LSM: without a way to mount, a process can't alias a
// policy-denied path under an allowed prefix (which defeats path matching).
// It also leaves the workload with no capability it could ever regain: an
// empty bounding set, empty ambient/inheritable/permitted/effective sets and
// no_new_privs, so neither a setuid-root nor a file-capability binary
// (sudo, iputils ping) can raise privilege inside the box (#203).
// Applied via `leash --harden-exec` in the native workload launch, so it is
// inherited across exec and covers the agent and every subprocess it spawns.
package hardening

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Apply hardens the calling OS thread, which it locks for good so the caller
// execs (or forks) the workload from it: capabilities, no_new_privs and a
// seccomp filter installed with prctl are per-thread.
//
// In order: no_new_privs; every capability dropped from the bounding set and
// the ambient set cleared, which needs CAP_SETPCAP, so it happens while the
// process is still root; then, when drop is set, the switch to that user
// (supplementary groups, gid, uid); then the inheritable, permitted and
// effective sets cleared; then the seccomp filter, which no_new_privs lets an
// unprivileged process install. The result is checked before returning: any
// capability left, or no_new_privs unset, is an error and the workload must
// not run.
func Apply(drop *Identity) error {
	runtime.LockOSThread()
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("no_new_privs: %w", err)
	}
	if err := dropCapBounding(); err != nil {
		return err
	}
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil && !errors.Is(err, unix.EINVAL) {
		return fmt.Errorf("clear the ambient capability set: %w", err)
	}
	if drop != nil {
		if err := switchUser(drop); err != nil {
			return err
		}
	}
	if err := clearCapSets(); err != nil {
		return err
	}
	if err := installSeccomp(); err != nil {
		return fmt.Errorf("seccomp: %w", err)
	}
	st, err := ReadState()
	if err != nil {
		return fmt.Errorf("verify the hardening: %w", err)
	}
	if err := st.Hardened(); err != nil {
		return fmt.Errorf("verify the hardening: %w", err)
	}
	if drop != nil && (os.Getuid() != drop.UID || os.Geteuid() != drop.UID || os.Getgid() != drop.GID || os.Getegid() != drop.GID) {
		return fmt.Errorf("verify the hardening: still uid %d/%d gid %d/%d, want %d/%d", os.Getuid(), os.Geteuid(), os.Getgid(), os.Getegid(), drop.UID, drop.GID)
	}
	return nil
}

// lastCap is the highest capability number this kernel knows.
func lastCap() int {
	if b, err := os.ReadFile("/proc/sys/kernel/cap_last_cap"); err == nil {
		if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && n >= 0 && n < 64 {
			return n
		}
	}
	n := 0
	for c := 0; c < 64; c++ {
		if _, err := unix.PrctlRetInt(unix.PR_CAPBSET_READ, uintptr(c), 0, 0, 0); err != nil {
			break
		}
		n = c
	}
	return n
}

// dropCapBounding removes every capability from the bounding set. It needs
// CAP_SETPCAP: as the dropped user it fails, which is why it runs before the
// user switch (#203: it used to run after runuser and fail silently, leaving
// CapBnd full).
func dropCapBounding() error {
	for c := 0; c <= lastCap(); c++ {
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(c), 0, 0, 0); err != nil && !errors.Is(err, unix.EINVAL) {
			return fmt.Errorf("drop capability %d from the bounding set (needs CAP_SETPCAP, i.e. run before dropping root): %w", c, err)
		}
	}
	return nil
}

// switchUser sets the supplementary groups, gid and uid (real, effective and
// saved; Go applies them to every thread). Leaving uid 0 clears the permitted,
// effective and ambient sets; the inheritable set is cleared by clearCapSets.
func switchUser(id *Identity) error {
	groups := id.Groups
	if groups == nil {
		groups = []int{}
	}
	if err := syscall.Setgroups(groups); err != nil {
		return fmt.Errorf("setgroups for %s: %w", id.Name, err)
	}
	if err := syscall.Setresgid(id.GID, id.GID, id.GID); err != nil {
		return fmt.Errorf("setgid %d for %s: %w", id.GID, id.Name, err)
	}
	if err := syscall.Setresuid(id.UID, id.UID, id.UID); err != nil {
		return fmt.Errorf("setuid %d for %s: %w", id.UID, id.Name, err)
	}
	return nil
}

// clearCapSets empties the thread's inheritable, permitted and effective
// sets. Lowering them needs no privilege.
func clearCapSets() error {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return fmt.Errorf("clear the capability sets: %w", err)
	}
	return nil
}

// State is a thread's capability sets and no_new_privs flag, as the kernel
// reports them in /proc/<pid>/status (CapInh, CapPrm, CapEff, CapBnd, CapAmb,
// NoNewPrivs).
type State struct {
	CapInh, CapPrm, CapEff, CapBnd, CapAmb uint64
	NoNewPrivs                             bool
}

// ReadState reads the calling thread's state with capget/prctl, so it does
// not depend on /proc being mounted.
func ReadState() (State, error) {
	var st State
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return st, fmt.Errorf("capget: %w", err)
	}
	st.CapInh = uint64(data[1].Inheritable)<<32 | uint64(data[0].Inheritable)
	st.CapPrm = uint64(data[1].Permitted)<<32 | uint64(data[0].Permitted)
	st.CapEff = uint64(data[1].Effective)<<32 | uint64(data[0].Effective)
	for c := 0; c <= lastCap(); c++ {
		in, err := unix.PrctlRetInt(unix.PR_CAPBSET_READ, uintptr(c), 0, 0, 0)
		if err != nil {
			return st, fmt.Errorf("read bounding capability %d: %w", c, err)
		}
		if in == 1 {
			st.CapBnd |= 1 << uint(c)
		}
		amb, err := unix.PrctlRetInt(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_IS_SET, uintptr(c), 0, 0)
		if err == nil && amb == 1 {
			st.CapAmb |= 1 << uint(c)
		}
	}
	nnp, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
	if err != nil {
		return st, fmt.Errorf("read no_new_privs: %w", err)
	}
	st.NoNewPrivs = nnp == 1
	return st, nil
}

// Hardened reports what is left that the workload must not have.
func (s State) Hardened() error {
	var left []string
	for _, f := range []struct {
		name string
		v    uint64
	}{{"CapBnd", s.CapBnd}, {"CapAmb", s.CapAmb}, {"CapInh", s.CapInh}, {"CapPrm", s.CapPrm}, {"CapEff", s.CapEff}} {
		if f.v != 0 {
			left = append(left, fmt.Sprintf("%s=%016x", f.name, f.v))
		}
	}
	if !s.NoNewPrivs {
		left = append(left, "NoNewPrivs=0")
	}
	if len(left) > 0 {
		return fmt.Errorf("the workload would keep privilege: %s", strings.Join(left, " "))
	}
	return nil
}

// Run starts the hardened workload from the calling (hardened) thread and
// returns its exit status. Outside a PID namespace it simply execs. As PID 1
// of the box's PID namespace (the native launch's `unshare --pid --fork`) it
// stays as the namespace's init, as runuser did before it: the workload then
// keeps default signal semantics (the kernel ignores signals a PID 1 has no
// handler for), orphans are reaped, and SIGTERM/SIGHUP/SIGUSR1/SIGUSR2 sent
// to the box are forwarded. SIGINT and SIGQUIT are not forwarded: the
// terminal already sends them to the workload's process group, and a second
// copy would read as a double Ctrl-C.
func Run(argv, env []string) (int, error) {
	if len(argv) == 0 {
		return 0, errors.New("no command given")
	}
	path := argv[0]
	if resolved, err := exec.LookPath(path); err == nil {
		path = resolved
	}
	if os.Getpid() != 1 {
		return 0, syscall.Exec(path, argv, env)
	}
	sigs := make(chan os.Signal, 16)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGUSR1, syscall.SIGUSR2)
	pid, err := syscall.ForkExec(path, argv, &syscall.ProcAttr{Env: env, Files: []uintptr{0, 1, 2}})
	if err != nil {
		return 0, fmt.Errorf("start %s: %w", path, err)
	}
	go func() {
		for s := range sigs {
			if s == syscall.SIGINT || s == syscall.SIGQUIT {
				continue
			}
			_ = syscall.Kill(pid, s.(syscall.Signal))
		}
	}()
	for {
		var ws syscall.WaitStatus
		wpid, err := syscall.Wait4(-1, &ws, 0, nil)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			return 0, fmt.Errorf("wait for %s: %w", path, err)
		}
		if wpid != pid {
			continue // a reaped orphan
		}
		switch {
		case ws.Exited():
			return ws.ExitStatus(), nil
		case ws.Signaled():
			return 128 + int(ws.Signal()), nil
		}
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
		bpfStmt(unix.BPF_RET|unix.BPF_K, retEPERM),      // arch mismatch → deny
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
