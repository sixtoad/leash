//go:build linux

package lsm

// Real-kernel load validation for the shipped eBPF LSM objects (issue #110).
//
// The verifier result for a program does not depend on map contents, but the
// manager only loads a module when the policy has rules for it: lsm_exec is
// never handed to the kernel unless the policy contains an exec rule. A gate
// whose policy lacks one (or that loads differently generated objects than the
// ones a binary embeds) can therefore pass while a real run fails. This test
// drives every module's production LoadAndAttach path with a policy containing
// open, exec and connect rules, then executes a binary inside the scoped cgroup
// so the attached exec hook evaluates a real path.
//
// Gated behind LEASH_LSM_KERNEL_LOAD_VALIDATION=1 and root; intended to run as
// a compiled test binary inside a privileged, --cgroupns=host container on a
// kernel with bpf in the active LSM list (see scripts/verify-lsm-kernel-load.sh).

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

// kernelLoadPolicy mirrors the shape of a typical agent policy: default-deny
// file opens with directory allows and a forbid, an exec permit on "/", and
// literal-address connect allows. One exec deny proves the hook enforces.
var kernelLoadPolicy = []string{
	"allow file.open /usr/",
	"allow file.open /lib/",
	"allow file.open /lib64/",
	"allow file.open /bin/",
	"allow file.open /etc/",
	"allow file.open /proc/",
	"allow file.open /dev/",
	"allow file.open:rw /tmp/",
	"deny file.open /etc/shadow",
	"allow proc.exec /",
	"deny proc.exec /usr/bin/false",
	"allow net.send 1.1.1.1:443",
	"allow net.send 8.8.8.8",
}

func kernelLoadPolicySet(t *testing.T) *PolicySet {
	t.Helper()
	set := &PolicySet{}
	for i, line := range kernelLoadPolicy {
		rule, err := parsePolicyLine(line, i+1)
		if err != nil {
			t.Fatalf("policy line %q: %v", line, err)
		}
		switch rule.Operation {
		case OpExec:
			set.Exec = append(set.Exec, rule)
		case OpConnect:
			set.Connect = append(set.Connect, rule)
		default:
			set.Open = append(set.Open, rule)
		}
	}
	if !set.HasOpenPolicies() || !set.HasExecPolicies() || !set.HasConnectPolicies() {
		t.Fatalf("validation policy must exercise open, exec and connect modules")
	}
	return set
}

func TestKernelLoadAllModulesWithExecRule(t *testing.T) {
	if os.Getenv("LEASH_LSM_KERNEL_LOAD_VALIDATION") != "1" {
		t.Skip("set LEASH_LSM_KERNEL_LOAD_VALIDATION=1 (needs root + bpf LSM; run via scripts/verify-lsm-kernel-load.sh)")
	}
	if os.Geteuid() != 0 {
		t.Fatalf("must run as root")
	}

	// Scope enforcement to an empty child cgroup so the default-deny open
	// policy cannot affect this test process or the container around it.
	box := filepath.Join(hlCgroupPath(), fmt.Sprintf("leash-kernel-load-%d", os.Getpid()))
	if err := os.Mkdir(box, 0o755); err != nil {
		t.Fatalf("create scoped cgroup %s: %v", box, err)
	}
	defer os.Remove(box)

	// Every shipped program, optional ones included, must pass the verifier.
	// The production loader silently drops an optional hook (lsm_link) that
	// fails verification, so this is the only place such a regression shows.
	// This is deliberately stricter than production: the gate host must be a
	// kernel where the hard-link guard verifies (CONFIG_SECURITY_PATH).
	objects := []struct {
		name   string
		loader func() (*ebpf.CollectionSpec, error)
	}{
		{"lsm_open", loadLsmOpen}, {"lsm_exec", loadLsmExec}, {"lsm_connect", loadLsmConnect},
	}
	for _, object := range objects {
		spec, err := object.loader()
		if err != nil {
			t.Errorf("%s spec: %v", object.name, err)
			continue
		}
		coll, err := ebpf.NewCollection(spec)
		if err != nil {
			t.Errorf("%s object does not verify on this kernel: %v", object.name, err)
			continue
		}
		t.Logf("%s object verified (%d programs)", object.name, len(coll.Programs))
		coll.Close()
	}
	if t.Failed() {
		t.FailNow()
	}

	policies := kernelLoadPolicySet(t)
	logger, err := NewSharedLogger("")
	if err != nil {
		t.Fatal(err)
	}

	openLsm, err := NewOpenLsm(box, logger)
	if err != nil {
		t.Fatal(err)
	}
	if err := openLsm.LoadPolicies(ConvertToFileOpenRules(policies.Open)); err != nil {
		t.Fatal(err)
	}
	execLsm, err := NewExecLsm(box, logger)
	if err != nil {
		t.Fatal(err)
	}
	if err := execLsm.LoadPolicies(ConvertToExecRules(policies.Exec)); err != nil {
		t.Fatal(err)
	}
	connectLsm, err := NewConnectLsm(box, logger)
	if err != nil {
		t.Fatal(err)
	}
	if err := connectLsm.LoadPolicies(ConvertToConnectRules(policies.Connect), nil); err != nil {
		t.Fatal(err)
	}

	modules := []struct {
		name   string
		attach func() error
	}{
		{"file-open", func() error { return openLsm.LoadAndAttach(loadLsmOpen) }},
		{"exec", func() error { return execLsm.LoadAndAttach(loadLsmExec) }},
		{"connect", func() error { return connectLsm.LoadAndAttach(loadLsmConnect) }},
	}

	// Every LoadAndAttach settles exactly once (attached or failed) and, on
	// success, then blocks in its event loop until the process exits. A failed
	// attempt returns promptly after settling.
	var settled sync.WaitGroup
	settled.Add(len(modules))
	onLSMAttached = settled.Done
	defer func() { onLSMAttached = nil }()

	errs := make(chan error, len(modules))
	for _, module := range modules {
		module := module
		go func() {
			if err := module.attach(); err != nil {
				errs <- fmt.Errorf("%s: %w", module.name, err)
			}
		}()
	}

	done := make(chan struct{})
	go func() { settled.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatalf("LSM modules did not settle within 60s")
	}

	var failures []error
	grace := time.After(3 * time.Second)
collect:
	for {
		select {
		case err := <-errs:
			failures = append(failures, err)
		case <-grace:
			break collect
		}
	}
	if len(failures) > 0 {
		t.Fatalf("real-kernel LSM load failed: %v", errors.Join(failures...))
	}
	t.Logf("lsm_open, lsm_exec and lsm_connect loaded and attached with %d open, %d exec and %d connect rules",
		len(policies.Open), len(policies.Exec), len(policies.Connect))

	// Exercise the attached exec hook on real, resolvable paths inside the
	// scoped cgroup: the "/" exec permit must allow true, and the exec deny
	// must refuse false.
	cgroupDir, err := os.Open(box)
	if err != nil {
		t.Fatalf("open scoped cgroup: %v", err)
	}
	defer cgroupDir.Close()
	trueBin, err := exec.LookPath("true")
	if err != nil {
		t.Fatalf("locate true: %v", err)
	}
	cmd := exec.Command(trueBin)
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cgroupDir.Fd())}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("exec %s in scoped cgroup under exec permit failed: %v (%s)", trueBin, err, out)
	}
	denied := exec.Command("/usr/bin/false")
	denied.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cgroupDir.Fd())}
	if err := denied.Run(); !errors.Is(err, syscall.EACCES) {
		t.Fatalf("exec /usr/bin/false under an exec deny: want EACCES, got %v", err)
	}
}
