//go:build linux

package lsm

// Runtime validation for the hard-link guard (audit #3, PR #16).
// Gated behind LEASH_HARDLINK_VALIDATION=1 and root; intended to run inside a
// privileged, --cgroupns=host container on a kernel with bpf in the active LSM
// list AND CONFIG_SECURITY_PATH (path_link hook). It attaches the open LSM
// (which, on this branch, also attaches the optional lsm_link hook), loads a
// policy that denies reading one file, and asserts the hard-link bypass is shut:
//   - a hard link whose SOURCE is policy-denied is refused (EPERM), and
//   - a hard link of a readable source still succeeds.

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

func hlRule(action, op int32, path string) PolicyRule {
	r := PolicyRule{Action: action, Operation: op, PathLen: int32(len(path))}
	copy(r.Path[:], path)
	if strings.HasSuffix(path, "/") {
		r.IsDirectory = 1
	}
	return r
}

// hlAttach starts the open LSM and waits until its attach attempt has SETTLED,
// i.e. every program — including the optional lsm_link hard-link guard, which
// attaches LAST, after all required programs — is attached or skipped.
//
// The tests used to treat "lsm_open denies the secret" as readiness. lsm_open
// is the first program attached and lsm_link the last, so that signal can fire
// before the guard exists, and a link probed in that window is allowed: a false
// FAIL (#144). It then asserts that lsm_link really is attached in this
// process, so a kernel without CONFIG_SECURITY_PATH (or a guard that failed
// verification and was dropped as optional) fails with that diagnosis instead
// of a misleading "hard link SUCCEEDED".
func hlAttach(t *testing.T, l *OpenLsm) <-chan error {
	t.Helper()
	settled := make(chan struct{})
	var once sync.Once
	onLSMAttached = func() { once.Do(func() { close(settled) }) }
	t.Cleanup(func() { onLSMAttached = nil })

	// Count links held before this attach: an earlier guard test in the same
	// process leaves its programs attached, so require NEW links.
	before := hlLinkedProgramNames(t)
	attachErr := make(chan error, 1)
	go func() { attachErr <- l.LoadAndAttach(loadLsmOpen) }()
	select {
	case <-settled:
	case e := <-attachErr:
		t.Fatalf("LSM attach returned early: %v", e)
	case <-time.After(60 * time.Second):
		t.Fatalf("open LSM attach did not settle within 60s")
	}
	linked := hlLinkedProgramNames(t)
	for _, name := range []string{"lsm_open", "lsm_link"} {
		if linked[name] <= before[name] {
			t.Fatalf("%s is not attached after the open LSM settled (linked programs: %v). "+
				"lsm_link needs CONFIG_SECURITY_PATH and must pass the verifier; check stderr for "+
				"'optional LSM hook' messages", name, linked)
		}
	}
	return attachErr
}

// hlLinkedProgramNames counts, by program name, the BPF links this process
// holds, read from /proc/self/fdinfo (each bpf_link fd reports its prog_id).
func hlLinkedProgramNames(t *testing.T) map[string]int {
	t.Helper()
	names := map[string]int{}
	fds, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("list /proc/self/fd: %v", err)
	}
	for _, fd := range fds {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", fd.Name()))
		if err != nil || target != "anon_inode:bpf_link" {
			continue
		}
		info, err := os.ReadFile(filepath.Join("/proc/self/fdinfo", fd.Name()))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(info), "\n") {
			value, ok := strings.CutPrefix(line, "prog_id:")
			if !ok {
				continue
			}
			id, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
			if err != nil {
				continue
			}
			prog, err := ebpf.NewProgramFromID(ebpf.ProgramID(id))
			if err != nil {
				continue
			}
			if pi, err := prog.Info(); err == nil {
				names[pi.Name]++
			}
			prog.Close()
		}
	}
	return names
}

// box cgroup for is_target_cgroup scoping; cgroup v2 line is "0::/<rel>".
func hlCgroupPath() string {
	if data, err := os.ReadFile("/proc/self/cgroup"); err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			p := strings.SplitN(line, ":", 3)
			if len(p) == 3 && p[0] == "0" {
				return filepath.Join("/sys/fs/cgroup", p[2])
			}
		}
	}
	return "/sys/fs/cgroup"
}

func TestHardlinkGuardValidation(t *testing.T) {
	if os.Getenv("LEASH_HARDLINK_VALIDATION") != "1" {
		t.Skip("set LEASH_HARDLINK_VALIDATION=1 (needs root + bpf LSM + CONFIG_SECURITY_PATH)")
	}
	if os.Geteuid() != 0 {
		t.Fatalf("must run as root")
	}

	dir, err := os.MkdirTemp("", "hlguard")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	secret := filepath.Join(dir, "secret")
	readable := filepath.Join(dir, "readable")
	work := filepath.Join(dir, "work")
	for p, mode := range map[string]os.FileMode{secret: 0644, readable: 0644} {
		if err := os.WriteFile(p, []byte("x"), mode); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(work, 0755); err != nil {
		t.Fatal(err)
	}

	rules := ConvertToFileOpenRules([]PolicyRule{
		hlRule(PolicyAllow, OpOpen, "/"),   // default allow
		hlRule(PolicyAllow, OpOpenRW, "/"), // link destinations need rw-directory authority (#29)
		hlRule(PolicyDeny, OpOpen, secret), // deny reading the secret
	})

	logger, err := NewSharedLogger("")
	if err != nil {
		t.Fatal(err)
	}
	cg := hlCgroupPath()
	t.Logf("box cgroup: %s", cg)
	l, err := NewOpenLsm(cg, logger)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.LoadPolicies(rules); err != nil {
		t.Fatal(err)
	}

	attachErr := hlAttach(t, l)

	// Readiness: selective enforcement live — secret denied AND readable allowed.
	ready := false
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case e := <-attachErr:
			t.Fatalf("LSM attach returned early: %v", e)
		default:
		}
		if f, oerr := os.Open(secret); oerr == nil {
			f.Close()
		} else if errors.Is(oerr, syscall.EACCES) {
			if g, rerr := os.Open(readable); rerr == nil {
				g.Close()
				ready = true
				break
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !ready {
		t.Fatalf("enforcement never became live (lsm_open not denying secret) within 10s")
	}
	t.Logf("PASS readiness: lsm_open live (secret denied, readable allowed)")

	// Case 2 — hard link of a policy-denied source must be refused with EPERM.
	alias := filepath.Join(work, "alias")
	switch linkErr := os.Link(secret, alias); {
	case linkErr == nil:
		t.Errorf("FAIL case2: hard link of denied source SUCCEEDED — guard not enforcing (is lsm_link attached? check stderr for 'optional LSM hook \"lsm_link\" not attached')")
	case errors.Is(linkErr, syscall.EPERM):
		t.Logf("PASS case2: hard link of denied source blocked with EPERM")
	default:
		t.Errorf("FAIL case2: hard link blocked but errno=%v, want EPERM", linkErr)
	}

	// Case 4 — read bypass closed: the alias must not exist.
	if _, serr := os.Lstat(alias); serr == nil {
		t.Errorf("FAIL case4: alias %s exists despite guard", alias)
	} else {
		t.Logf("PASS case4: no alias created; read bypass closed")
	}

	// Case 3 — hard link of a readable source must still succeed.
	if lerr := os.Link(readable, filepath.Join(work, "ok")); lerr != nil {
		t.Errorf("FAIL case3: hard link of readable source blocked: %v", lerr)
	} else {
		t.Logf("PASS case3: hard link of readable source allowed")
	}
}

// TestHardlinkGuardNestedMount proves the mount-crossing path resolution: the
// denied file lives on a SEPARATE tmpfs mount, so a simple d_parent walk would
// yield a mount-relative path that misses the policy rule. The guard must
// reconstruct the true absolute path (mount prefix + within-mount path) and still
// block the link. Run one guard test per process (each attaches lsm_open).
func TestHardlinkGuardNestedMount(t *testing.T) {
	if os.Getenv("LEASH_HARDLINK_VALIDATION") != "1" {
		t.Skip("set LEASH_HARDLINK_VALIDATION=1 (needs root + bpf LSM + CONFIG_SECURITY_PATH)")
	}
	if os.Geteuid() != 0 {
		t.Fatalf("must run as root")
	}

	base, err := os.MkdirTemp("", "hlmnt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(base)
	mnt := filepath.Join(base, "mnt")
	if err := os.Mkdir(mnt, 0755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mount("tmpfs", mnt, "tmpfs", 0, ""); err != nil {
		t.Skipf("cannot mount tmpfs (need CAP_SYS_ADMIN): %v", err)
	}
	defer syscall.Unmount(mnt, 0)

	secret := filepath.Join(mnt, "secret") // on the tmpfs, under a separate mount
	work := filepath.Join(mnt, "work")
	if err := os.WriteFile(secret, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(work, 0755); err != nil {
		t.Fatal(err)
	}

	rules := ConvertToFileOpenRules([]PolicyRule{
		hlRule(PolicyAllow, OpOpen, "/"),
		hlRule(PolicyDeny, OpOpen, secret), // absolute path, across the tmpfs mount
	})
	logger, err := NewSharedLogger("")
	if err != nil {
		t.Fatal(err)
	}
	l, err := NewOpenLsm(hlCgroupPath(), logger)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.LoadPolicies(rules); err != nil {
		t.Fatal(err)
	}
	attachErr := hlAttach(t, l)

	ready := false
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case e := <-attachErr:
			t.Fatalf("LSM attach returned early: %v", e)
		default:
		}
		if f, oerr := os.Open(secret); oerr == nil {
			f.Close()
		} else if errors.Is(oerr, syscall.EACCES) {
			ready = true
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !ready {
		t.Fatalf("enforcement never denied the tmpfs secret within 10s")
	}
	t.Logf("PASS readiness: tmpfs secret denied (%s)", secret)

	alias := filepath.Join(work, "alias")
	switch linkErr := os.Link(secret, alias); {
	case linkErr == nil:
		t.Errorf("FAIL: hard link of nested-mount denied source SUCCEEDED — mount-crossing did not resolve the true source path")
	case errors.Is(linkErr, syscall.EPERM):
		t.Logf("PASS: hard link of nested-mount (tmpfs) denied source blocked with EPERM")
	default:
		t.Errorf("FAIL: link blocked but errno=%v, want EPERM", linkErr)
	}
	if _, serr := os.Lstat(alias); serr == nil {
		t.Errorf("FAIL: alias %s exists despite guard", alias)
	}
}
