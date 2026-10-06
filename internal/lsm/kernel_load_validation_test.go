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
	"regexp"
	"sort"
	"strings"
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

// Long policy paths (issues #108/#109). The rules below sit at and beyond the
// historical 64-byte kernel cutoff, which silently dropped a longer rule: a
// dropped permit denied its whole tree and a dropped forbid failed open under a
// shorter parent permit.
const longPathSegment = "long-policy-segment-" // 20 bytes

// longPathRoot is a tmpfs mounted for the test. The container's own rootfs is
// overlayfs, whose backing-store re-evaluation is a separate concern (#98);
// a plain filesystem keeps these cases about path length alone.
const longPathRoot = "/lp"

type longPathTrees struct {
	parentA, blockedA, okA string // short generic parent permit + 93-byte exact forbid
	roSecretA              string // 95-byte read-only forbid under the generic parent
	sealedA                string // 89-byte directory forbid ("<dir>/"), checked on the dir itself
	forbid64, forbid65     string // exact forbids at the old boundary, under parentA
	forbid255              string // 255-byte exact forbid under parentA
	permit64, permit65     string // exact rw permits at the old boundary (default deny)
	dirB, siblingB         string // 90-byte rw dir permit + same-85-byte-prefix sibling
	file200, sibling200    string // 200-byte exact rw file permit + same-length sibling
	file255, sibling255    string // 255-byte exact rw file permit + same-length sibling
	mountM                 string // 146-byte mount point of a second tmpfs (generic permit)
	deepM, shallowM        string // a >255-byte file and a short file inside mountM
}

func newLongPathTrees() longPathTrees {
	tail := func(prefix string, n int, fill byte) string {
		return prefix + strings.Repeat(string(fill), n-len(prefix))
	}
	// Tree A and mount M keep every component under the hard-link guard's
	// 40-byte and 4-deep reconstruction bounds (#29) so link cases exercise policy.
	component := (longPathSegment + longPathSegment)[:37]
	treeA := longPathRoot + "/a/" + component + "/" + component + "/"
	dirC := longPathRoot + "/c/" + strings.Repeat(longPathSegment, 9) + "/"
	dirD := longPathRoot + "/d/" + strings.Repeat(longPathSegment, 12) + "/"
	mountM := longPathRoot + "/m/" + strings.Repeat("mount-point-segment-", 7)
	component39 := (longPathSegment + longPathSegment)[:39]
	return longPathTrees{
		parentA:    longPathRoot + "/a/",
		blockedA:   treeA + "blocked.txt",
		okA:        treeA + "ok.txt",
		roSecretA:  treeA + "ro-secret.txt",
		sealedA:    treeA + "sealed",
		forbid64:   tail(longPathRoot+"/a/", 64, 'q'),
		forbid65:   tail(longPathRoot+"/a/", 65, 'q'),
		forbid255:  tail(longPathRoot+"/a/", MaxPolicyPathLength, 'z'),
		permit64:   tail(longPathRoot+"/e/", 64, 'p'),
		permit65:   tail(longPathRoot+"/e/", 65, 'r'),
		dirB:       longPathRoot + "/b/" + strings.Repeat(longPathSegment, 4) + "dir/",
		siblingB:   longPathRoot + "/b/" + strings.Repeat(longPathSegment, 4) + "dix/",
		file200:    tail(dirC, 200, 'f'),
		sibling200: tail(dirC, 199, 'f') + "g",
		file255:    tail(dirD, MaxPolicyPathLength, 'f'),
		sibling255: tail(dirD, MaxPolicyPathLength-1, 'f') + "g",
		mountM:     mountM,
		deepM:      mountM + "/" + component39 + "/" + component39 + "/" + component39 + "/" + component39,
		shallowM:   mountM + "/ok.txt",
	}
}

func (l longPathTrees) policy() []string {
	return []string{
		"allow file.open " + l.parentA,
		"deny file.open " + l.blockedA,
		"deny file.open:ro " + l.roSecretA,
		"deny file.open " + l.sealedA + "/",
		"deny file.open " + l.forbid64,
		"deny file.open " + l.forbid65,
		"deny file.open " + l.forbid255,
		"allow file.open:rw " + l.permit64,
		"allow file.open:rw " + l.permit65,
		"allow file.open:rw " + l.dirB,
		"allow file.open:rw " + longPathRoot + "/s/",
		"allow file.open:rw " + l.file200,
		"allow file.open:rw " + l.file255,
		"allow file.open " + l.mountM + "/",
	}
}

// reloadPolicy is applied live in phase 2: a root allow (default allow) with
// forbids that a fail-open path would bypass.
func (l longPathTrees) reloadPolicy() []string {
	return []string{
		"allow file.open /",
		"deny file.open " + l.mountM + "/",
		"deny file.open:ro /etc/passwd",
	}
}

// prepare creates the trees (as root, outside the scoped cgroup) so policy
// paths resolve and the mutation and link cases have targets.
func (l longPathTrees) prepare(t *testing.T) {
	t.Helper()
	mount := func(dir string) {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mount("tmpfs", dir, "tmpfs", 0, "mode=0755"); err != nil {
			t.Fatalf("mount tmpfs at %s: %v", dir, err)
		}
	}
	mount(longPathRoot)
	mount(l.mountM)
	t.Cleanup(func() {
		_ = syscall.Unmount(l.mountM, syscall.MNT_DETACH)
		_ = syscall.Unmount(longPathRoot, syscall.MNT_DETACH)
	})
	for _, dir := range []string{longPathRoot + "/s", longPathRoot + "/e", filepath.Dir(l.blockedA), l.sealedA, l.sealedA + "x",
		l.dirB, l.siblingB, filepath.Dir(l.file200), filepath.Dir(l.file255), filepath.Dir(l.deepM)} {
		if err := os.MkdirAll(dir, 0o777); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{l.blockedA, l.roSecretA, l.forbid64, l.forbid65, l.forbid255,
		l.dirB + "victim.txt", l.siblingB + "victim.txt", l.dirB + "from.txt", l.deepM, l.shallowM} {
		if err := os.WriteFile(file, []byte("x"), 0o666); err != nil {
			t.Fatal(err)
		}
	}
	for name, want := range map[string][2]int{
		"blockedA": {len(l.blockedA), 93}, "roSecretA": {len(l.roSecretA), 95}, "sealedA/": {len(l.sealedA) + 1, 89},
		"forbid64": {len(l.forbid64), 64}, "forbid65": {len(l.forbid65), 65}, "forbid255": {len(l.forbid255), 255},
		"permit64": {len(l.permit64), 64}, "permit65": {len(l.permit65), 65}, "dirB": {len(l.dirB), 90},
		"file200": {len(l.file200), 200}, "file255": {len(l.file255), 255}, "mountM": {len(l.mountM), 146},
	} {
		if want[0] != want[1] {
			t.Fatalf("%s is %d bytes, want %d", name, want[0], want[1])
		}
	}
	if len(l.deepM) <= MaxPolicyPathLength || len(l.shallowM) > MaxPolicyPathLength {
		t.Fatalf("mount M paths: deep=%d (want >255) shallow=%d", len(l.deepM), len(l.shallowM))
	}
}

// boxShell runs a POSIX shell snippet inside the scoped cgroup.
func boxShell(cgroupFD int, script string, args ...string) (string, error) {
	cmd := exec.Command("/bin/sh", append([]string{"-c", script, "sh"}, args...)...)
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: cgroupFD}
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

type boxCase struct {
	name   string
	script string
	args   []string
	allow  bool
	denial string // expected error text when denied (default EACCES)
}

const (
	boxWrite = `: > "$1"`
	boxRead  = `cat "$1" > /dev/null`
	boxLink  = `ln "$1" "$2"`
	eperm    = "Operation not permitted"
)

func runBoxCases(t *testing.T, cgroupFD int, cases []boxCase) {
	t.Helper()
	for _, c := range cases {
		denial := c.denial
		if denial == "" {
			denial = "Permission denied"
		}
		out, err := boxShell(cgroupFD, c.script, c.args...)
		switch {
		case c.allow && err != nil:
			t.Errorf("FAIL %s: want allowed, got %v (%s)", c.name, err, out)
		case !c.allow && err == nil:
			t.Errorf("FAIL %s: want %q, operation SUCCEEDED", c.name, denial)
		case !c.allow && !strings.Contains(out, denial):
			t.Errorf("FAIL %s: want %q, got %v (%s)", c.name, denial, err, out)
		default:
			t.Logf("PASS %s (allowed=%v)", c.name, c.allow)
		}
	}
}

func (l longPathTrees) verify(t *testing.T, cgroupFD int) {
	t.Helper()
	runBoxCases(t, cgroupFD, []boxCase{
		{"write under short generic parent, beside long forbid", boxWrite, []string{l.okA}, true, ""},
		{"write to 93-byte exact forbid (#108 fail-open)", boxWrite, []string{l.blockedA}, false, ""},
		{"unlink 93-byte exact forbid (#109)", `rm "$1"`, []string{l.blockedA}, false, ""},
		{"write to 64-byte exact forbid", boxWrite, []string{l.forbid64}, false, ""},
		{"write to 65-byte exact forbid", boxWrite, []string{l.forbid65}, false, ""},
		{"write to 255-byte exact forbid", boxWrite, []string{l.forbid255}, false, ""},
		{"read 95-byte read-only forbid", boxRead, []string{l.roSecretA}, false, ""},
		{"write 95-byte read-only forbid (rw still permitted)", boxWrite, []string{l.roSecretA}, true, ""},
		{"list 89-byte forbidden directory itself (dir-self)", `ls "$1"`, []string{l.sealedA}, false, ""},
		{"list same-prefix sibling of forbidden directory", `ls "$1"`, []string{l.sealedA + "x"}, true, ""},
		{"hard-link 93-byte forbidden source into permitted dir", boxLink, []string{l.blockedA, l.parentA + "alias"}, false, eperm},
		{"hard-link 95-byte read-only-forbidden source", boxLink, []string{l.roSecretA, l.parentA + "ro-alias"}, false, eperm},
		{"hard-link permitted long source into permitted dir", boxLink, []string{l.okA, l.parentA + "ok-alias"}, true, ""},
		{"write 64-byte exact file permit", boxWrite, []string{l.permit64}, true, ""},
		{"write 64-byte same-length sibling", boxWrite, []string{l.permit64[:63] + "x"}, false, ""},
		{"write 65-byte exact file permit", boxWrite, []string{l.permit65}, true, ""},
		{"write 65-byte same-length sibling", boxWrite, []string{l.permit65[:64] + "x"}, false, ""},
		{"write 65-byte path the 64-byte file permit is a byte prefix of", boxWrite, []string{l.permit64 + "x"}, true, ""},
		{"control: mkdir+rmdir inside short rw dir", `mkdir "$1" && rmdir "$1"`, []string{longPathRoot + "/s/sub"}, true, ""},
		{"write inside 90-byte rw dir permit (#108)", boxWrite, []string{l.dirB + "ok.txt"}, true, ""},
		{"write inside same-prefix undeclared sibling", boxWrite, []string{l.siblingB + "ok.txt"}, false, ""},
		{"mkdir inside 90-byte rw dir (#109)", `mkdir "$1"`, []string{l.dirB + "sub"}, true, ""},
		{"rmdir inside 90-byte rw dir (#109)", `rmdir "$1"`, []string{l.dirB + "sub"}, true, ""},
		{"rename inside 90-byte rw dir (#109)", `mv "$1" "$2"`, []string{l.dirB + "from.txt", l.dirB + "to.txt"}, true, ""},
		{"unlink inside 90-byte rw dir (#109)", `rm "$1"`, []string{l.dirB + "victim.txt"}, true, ""},
		{"unlink inside same-prefix undeclared sibling", `rm "$1"`, []string{l.siblingB + "victim.txt"}, false, ""},
		{"write 200-byte exact file permit", boxWrite, []string{l.file200}, true, ""},
		{"write 200-byte same-length sibling", boxWrite, []string{l.sibling200}, false, ""},
		{"write 255-byte exact file permit", boxWrite, []string{l.file255}, true, ""},
		{"write 255-byte same-length sibling", boxWrite, []string{l.sibling255}, false, ""},
		{"read short file under 146-byte mount permit", boxRead, []string{l.shallowM}, true, ""},
		{"hard-link short source within 146-byte mount", boxLink, []string{l.shallowM, l.mountM + "/ok-alias"}, true, ""},
		{"read >255-byte path under permitted mount (unresolvable)", boxRead, []string{l.deepM}, false, ""},
		{"hard-link >255-byte source to a short alias", boxLink, []string{l.deepM, l.mountM + "/deep-alias"}, false, eperm},
	})
}

// verifyReload applies reloadPolicy live and checks the cases a root allow
// would let through if any path failed open.
func (l longPathTrees) verifyReload(t *testing.T, openLsm *OpenLsm, cgroupFD int) {
	t.Helper()
	set := &PolicySet{}
	for i, line := range l.reloadPolicy() {
		rule, err := parsePolicyLine(line, i+1)
		if err != nil {
			t.Fatalf("reload policy line %q: %v", line, err)
		}
		if rule.PathLen > 1 && rule.Path[rule.PathLen-1] == '/' {
			rule.IsDirectory = 1
		}
		set.Open = append(set.Open, rule)
	}
	if err := openLsm.LoadPolicies(ConvertToFileOpenRules(set.Open)); err != nil {
		t.Fatalf("live reload: %v", err)
	}
	runBoxCases(t, cgroupFD, []boxCase{
		{"reload: read short file outside forbidden mount (root allow)", boxRead, []string{l.okA}, true, ""},
		{"reload: read short file under forbidden 146-byte mount", boxRead, []string{l.shallowM}, false, ""},
		{"reload: read >255-byte path under forbidden mount (no basename fallback)", boxRead, []string{l.deepM}, false, ""},
		{"reload: read /etc/passwd under read-only forbid", boxRead, []string{"/etc/passwd"}, false, ""},
		{"reload: hard-link read-only-forbidden file into / (mount root)", boxLink, []string{"/etc/passwd", "/passwd-alias"}, false, eperm},
		{"reload: hard-link readable file into / (mount root)", boxLink, []string{"/etc/debian_version", "/debian-alias"}, true, ""},
	})
}

func kernelLoadPolicySet(t *testing.T, extra ...string) *PolicySet {
	t.Helper()
	set := &PolicySet{}
	for i, line := range append(append([]string(nil), kernelLoadPolicy...), extra...) {
		rule, err := parsePolicyLine(line, i+1)
		if err != nil {
			t.Fatalf("policy line %q: %v", line, err)
		}
		// The Cedar transpiler (the production policy path) marks a trailing-
		// slash resource as a directory; the line parser does not.
		if rule.PathLen > 1 && rule.Path[rule.PathLen-1] == '/' {
			rule.IsDirectory = 1
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
		// Verifier budget headroom (1M processed instructions per program).
		names := make([]string, 0, len(coll.Programs))
		for name := range coll.Programs {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			if info, err := coll.Programs[name].Info(); err == nil {
				if insns, ok := info.VerifiedInstructions(); ok {
					t.Logf("  %s/%s: %d verifier-processed instructions", object.name, name, insns)
				}
			}
		}
		coll.Close()
	}
	if t.Failed() {
		t.FailNow()
	}

	longPaths := newLongPathTrees()
	longPaths.prepare(t)
	policies := kernelLoadPolicySet(t, longPaths.policy()...)
	eventLog := filepath.Join(t.TempDir(), "events.log")
	logger, err := NewSharedLogger(eventLog)
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

	// Long policy paths must be enforced byte-for-byte by the attached
	// file-open and directory-mutation hooks (issues #108/#109).
	longPaths.verify(t, int(cgroupDir.Fd()))
	longPaths.verifyReload(t, openLsm, int(cgroupDir.Fd()))

	// The audit trail must carry the complete long paths with the operation
	// and decision on the same record.
	required := []string{
		`event=file.open:rw .*path="` + regexp.QuoteMeta(longPaths.file255) + `" decision=allowed`,
		`event=file.open:rw .*path="` + regexp.QuoteMeta(longPaths.sibling255) + `" decision=denied`,
		`event=file.open:rw .*path="` + regexp.QuoteMeta(longPaths.blockedA) + `" decision=denied`,
		`event=file.unlink .*path="` + regexp.QuoteMeta(longPaths.dirB+"victim.txt") + `" decision=allowed`,
	}
	var events []byte
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(250 * time.Millisecond) {
		events, _ = os.ReadFile(eventLog)
		missing := 0
		for _, pattern := range required {
			if !regexp.MustCompile(pattern).Match(events) {
				missing++
			}
		}
		if missing == 0 {
			break
		}
	}
	for _, pattern := range required {
		if !regexp.MustCompile(pattern).Match(events) {
			t.Errorf("FAIL audit: no record matching %s", pattern)
		}
	}
	for _, line := range strings.Split(string(events), "\n") {
		if strings.Contains(line, longPathRoot+"/") && !strings.Contains(line, "proc.exec") {
			t.Logf("audit: %s", line)
		}
	}
}
