package runner

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/strongdm/leash/internal/enforcement"
	"github.com/strongdm/leash/internal/entrypoint"
)

func TestRunnerLauncherSelectsNative(t *testing.T) {
	r := &runner{runtime: newNativeRuntime()}
	l := r.launcher()
	if _, ok := l.(nativeLauncher); !ok {
		t.Fatalf("launcher() = %T, want nativeLauncher for --runtime native", l)
	}
	if l.Name() != "native" {
		t.Fatalf("Name() = %q, want native", l.Name())
	}
}

func TestSanitizeNativeName(t *testing.T) {
	cases := map[string]string{
		"My_Project":     "my-project",
		"  spaced name ": "spacedname",
		"weird/.:chars":  "weirdchars",
		"--edge--":       "edge",
		"":               "",
	}
	for in, want := range cases {
		if got := sanitizeNativeName(in); got != want {
			t.Errorf("sanitizeNativeName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNativeUnitAndNetnsNames(t *testing.T) {
	pid := os.Getpid()
	r := &runner{}
	r.cfg.targetContainer = "Acme_App"
	n := nativeLauncher{r: r}
	// The per-run PID suffix is what lets concurrent same-project native runs
	// coexist (distinct netns/unit/subnet); it's stable within a process.
	wantBase := fmt.Sprintf("leash-native-acme-app-%d", pid)
	if got := n.netnsName(); got != wantBase {
		t.Fatalf("netnsName = %q, want %q", got, wantBase)
	}
	if got := n.unitName(); got != wantBase+".service" {
		t.Fatalf("unitName = %q, want %q", got, wantBase+".service")
	}
	// Empty target falls back to a stable base (no naked "leash-native--<pid>").
	if got := (nativeLauncher{r: &runner{}}).netnsName(); got != fmt.Sprintf("leash-native-session-%d", pid) {
		t.Fatalf("fallback netnsName = %q", got)
	}
}

func TestNativePullImagesNoop(t *testing.T) {
	if err := (nativeLauncher{r: &runner{}}).PullImages(context.Background()); err != nil {
		t.Fatalf("PullImages = %v, want nil", err)
	}
}

func TestNativeEgressResolversReturnsExactCopy(t *testing.T) {
	t.Parallel()
	got := NativeEgressResolvers()
	if strings.Join(got, ",") != "1.1.1.1,8.8.8.8" {
		t.Fatalf("NativeEgressResolvers = %v", got)
	}
	got[0] = "192.0.2.53"
	if strings.Join(NativeEgressResolvers(), ",") != "1.1.1.1,8.8.8.8" {
		t.Fatal("caller mutated the native resolver source")
	}
	for _, address := range NativeEgressResolvers() {
		if !strings.Contains(nativeEgressResolvConf, "nameserver "+address+"\n") {
			t.Fatalf("native resolv.conf omitted %s: %q", address, nativeEgressResolvConf)
		}
	}
}

func TestNativeHostLeashdArgv(t *testing.T) {
	r := &runner{}
	r.cfg.proxyPort = "18000"
	r.nativeEgressFailed = true // force the LSM-only path deterministically (independent of euid)
	n := nativeLauncher{r: r}

	argv := n.hostLeashdArgv("/usr/local/bin/leash", "/run/netns/leash-native-x", "/sys/fs/cgroup/scope")
	joined := strings.Join(argv, " ")
	// LSM-only: host netns, no nsenter, --lsm-only. No posture flag: leashd
	// always fails closed.
	want := "/usr/local/bin/leash --daemon --host --lsm-only --cgroup /sys/fs/cgroup/scope --proxy-port 18000"
	if joined != want {
		t.Fatalf("argv = %q\nwant   %q", joined, want)
	}
}

// On this (rootless) box enforcement can't start; StartEnforcement must say why
// and surface the exact command it would run, not fail opaquely.
func TestNativeStartEnforcementRequiresPrivilege(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root; the no-privilege blocker does not apply")
	}
	err := (nativeLauncher{r: &runner{}}).StartEnforcement(context.Background(), "/sys/fs/cgroup/x")
	if err == nil {
		t.Fatal("expected an actionable error when unprivileged")
	}
	msg := err.Error()
	for _, want := range []string{"requires root", "would run:", "--daemon --host", "LEASHD-HOST-MODE.md"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error %q missing %q", msg, want)
		}
	}
}

// TestNativeRuntimeSkipsContainerPrelaunch locks in Step 3: the pre-launcher
// orchestration steps must not touch the container CLI under --runtime native.
// nativeRuntime.Output errors on any container verb, so an accidental call here
// would fail this test rather than only surfacing in a live run.
func TestNativeRuntimeSkipsContainerPrelaunch(t *testing.T) {
	r := &runner{runtime: newNativeRuntime()}
	r.cfg.targetContainer = "tgt"
	r.cfg.leashContainer = "tgt-leash"
	ctx := context.Background()

	if err := r.assignContainerNames(ctx); err != nil {
		t.Fatalf("assignContainerNames: %v", err)
	}
	if r.cfg.targetContainer != "tgt" || r.cfg.leashContainer != "tgt-leash" {
		t.Fatalf("native names = %q/%q, want the base names unprobed", r.cfg.targetContainer, r.cfg.leashContainer)
	}
	if err := r.launcher().EnsureNotRunning(ctx); err != nil {
		t.Fatalf("EnsureNotRunning: %v", err)
	}
	if sig, err := r.launcher().StopSignal(ctx); err != nil || sig != "SIGTERM" {
		t.Fatalf("StopSignal = %q, %v; want SIGTERM, nil", sig, err)
	}
	if err := r.ensurePortFree(ctx, "18080"); err != nil {
		t.Fatalf("ensurePortFree: %v", err)
	}
	if err := r.expandPublishAll(ctx); err != nil {
		t.Fatalf("expandPublishAll (no publish-all): %v", err)
	}
	// --publish-all is unsupported for native and must error clearly.
	r.opts.publishAll = true
	if err := r.expandPublishAll(ctx); err == nil || !strings.Contains(err.Error(), "publish-all") {
		t.Fatalf("expandPublishAll with --publish-all = %v, want an unsupported error", err)
	}
}

// TestNativeBoxLifecycle_Integration drives the real box on this machine:
// Provision a delegated cgroup, run a workload placed into it, confirm the
// workload's cgroup is the box's, then Remove and confirm teardown. Rootless via
// the per-user systemd manager. Skips where that is unavailable (CI, macOS).
func TestNativeBoxLifecycle_Integration(t *testing.T) {
	if _, err := exec.LookPath("systemd-run"); err != nil {
		t.Skip("systemd-run not available")
	}
	if os.Getenv("XDG_RUNTIME_DIR") == "" {
		t.Skip("no XDG_RUNTIME_DIR — no user systemd manager")
	}

	r := &runner{runtime: newNativeRuntime()}
	r.cfg.targetContainer = "step21-" + sanitizeNativeName(t.Name())
	n := nativeLauncher{r: r}
	ctx := context.Background()

	cgroupPath, err := n.Provision(ctx, "")
	if err != nil {
		t.Skipf("user box unavailable in this environment: %v", err)
	}
	t.Cleanup(func() { n.Remove(ctx) })

	if !strings.HasPrefix(cgroupPath, "/sys/fs/cgroup/") || !strings.HasSuffix(cgroupPath, n.unitName()) {
		t.Fatalf("box cgroup = %q, want /sys/fs/cgroup/...%s", cgroupPath, n.unitName())
	}

	// Run a workload in the box; it must report the box's cgroup. Rootless
	// placement writes the delegated cgroup.procs, which returns EIO on kernels
	// where the user manager has enabled domain controllers on the delegated
	// hierarchy (cgroup-v2 "no internal processes"). Native is root-only anyway
	// (see preflightNativeRuntime) and root/system-scope placement is unaffected,
	// so treat that specific case as a skip rather than a failure.
	out, err := n.execInBox(ctx, cgroupPath, "cat", "/proc/self/cgroup").CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "I/O error") {
			t.Skipf("rootless cgroup.procs placement unavailable on this kernel/session (EIO); root path is covered by the smoke test")
		}
		t.Fatalf("execInBox: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	workloadCgroup := strings.TrimSpace(string(out))
	if !strings.HasSuffix(workloadCgroup, n.unitName()) {
		t.Fatalf("workload cgroup = %q, want it to end in the box unit %s", workloadCgroup, n.unitName())
	}
	t.Logf("workload ran in the container-free box cgroup: %s", workloadCgroup)

	// Teardown removes the unit.
	n.Remove(ctx)
	// Query the manager the box was created under: as root that is the system
	// manager, and `systemctl --user` there fails to connect to the bus, which
	// would read as a leftover unit (#180).
	show := append(n.userFlag(), "show", "-p", "ControlGroup", "--value", n.unitName())
	rel, _ := hostOutput(ctx, "systemctl", show...)
	if strings.TrimSpace(rel) != "" {
		t.Fatalf("unit %s still present after Remove (ControlGroup=%q)", n.unitName(), strings.TrimSpace(rel))
	}
}

func TestNativeWorkloadScript(t *testing.T) {
	cg := "/sys/fs/cgroup/system.slice/leash-native-x.service"

	// Unhardened (rootless path): plain placement — no ns/mask/scrub/harden.
	plain := nativeWorkloadScript(cg, "/wd", "bash", nativeWorkloadShellFlag, "claude", "", "", "/opt/leash", hardenOpts{})
	if !strings.Contains(plain, "cgroup.procs") || !strings.Contains(plain, "exec bash -lc") {
		t.Fatalf("plain script missing cgroup join / exec: %s", plain)
	}
	for _, unexpected := range []string{"unshare", "runuser", "mount -t tmpfs", "NODE_EXTRA_CA_CERTS", "env -u", "--harden-exec"} {
		if strings.Contains(plain, unexpected) {
			t.Fatalf("plain script must not contain %q: %s", unexpected, plain)
		}
	}

	// Hardened default (root): masks + fresh PID+IPC ns + full scrub + CA export +
	// the seccomp re-exec wrapper (blocks the userns→bind-mount path-LSM bypass).
	h := nativeWorkloadScript(cg, "/wd", "bash", nativeWorkloadShellFlag, "claude", "alice", "/share/ca-cert.pem",
		"/opt/leash", hardenOpts{enabled: true, uid: "1000"})
	for _, want := range []string{
		"mount -t tmpfs -o uid=1000,mode=0700 tmpfs /run/user/1000",
		"/tmp/.X11-unix",
		"cgroup.procs",
		"exec unshare --ipc --pid --fork --mount-proc --",
		// harden-exec drops to the user itself: the bounding set can only be
		// emptied before leaving root (#203).
		"/opt/leash --harden-exec --user alice -- env -u",
		"env -u DBUS_SESSION_BUS_ADDRESS -u DISPLAY -u XAUTHORITY",
		// CA trust is exported for every tool family (Node, OpenSSL/curl, python-requests,
		// git), not just Node — see the MITM-CA-for-non-Node change.
		"export NODE_EXTRA_CA_CERTS=/share/ca-cert.pem SSL_CERT_FILE=/share/ca-cert.pem " +
			"CURL_CA_BUNDLE=/share/ca-cert.pem REQUESTS_CA_BUNDLE=/share/ca-cert.pem " +
			"GIT_SSL_CAINFO=/share/ca-cert.pem; exec claude",
	} {
		if !strings.Contains(h, want) {
			t.Fatalf("hardened script missing %q: %s", want, h)
		}
	}
	if strings.Index(h, "cgroup.procs") > strings.Index(h, "unshare") {
		t.Fatalf("cgroup write must come before the unshare: %s", h)
	}
	// The seccomp filter must be applied AFTER leash's own unshare/mount (so leash's
	// setup succeeds) but is inherited by the agent: harden-exec sits inside
	// unshare and does the user drop itself, so runuser (which would run it
	// without CAP_SETPCAP, leaving CapBnd full) is not in the hardened chain.
	if strings.Index(h, "unshare") > strings.Index(h, "--harden-exec") {
		t.Fatalf("harden-exec must nest inside unshare: %s", h)
	}
	if strings.Contains(h, "runuser") {
		t.Fatalf("the hardened script must drop the user in harden-exec, not runuser: %s", h)
	}

	// Explicit --user root (no drop user): harden-exec still runs, with no --user.
	root := nativeWorkloadScript(cg, "/wd", "bash", nativeWorkloadShellFlag, "claude", "", "", "/opt/leash", hardenOpts{enabled: true, uid: "1000"})
	if !strings.Contains(root, "/opt/leash --harden-exec -- ") || strings.Contains(root, "--user") || strings.Contains(root, "runuser") {
		t.Fatalf("root script must harden without a user switch: %s", root)
	}

	// Hardened but no self path (os.Executable failed): degrade gracefully — the
	// session isolation and the runuser drop still apply, but no harden re-exec.
	noSelf := nativeWorkloadScript(cg, "/wd", "bash", nativeWorkloadShellFlag, "claude", "alice", "", "", hardenOpts{enabled: true, uid: "1000"})
	if strings.Contains(noSelf, "--harden-exec") || !strings.Contains(noSelf, "runuser -u alice --") {
		t.Fatalf("no-self script must drop with runuser and not harden-exec: %s", noSelf)
	}

	// GUI opt-outs: --allow-display + --share-ipc → no X11 mask, DISPLAY kept, no
	// IPC ns; but D-Bus stays masked/scrubbed (not opted out).
	gui := nativeWorkloadScript(cg, "/wd", "bash", nativeWorkloadShellFlag, "app", "alice", "",
		"/opt/leash", hardenOpts{enabled: true, uid: "1000", allowDisplay: true, shareIPC: true})
	for _, unexpected := range []string{"/tmp/.X11-unix", "--ipc", "-u DISPLAY", "-u XAUTHORITY"} {
		if strings.Contains(gui, unexpected) {
			t.Fatalf("GUI script must not contain %q: %s", unexpected, gui)
		}
	}
	for _, want := range []string{
		"unshare --pid --fork --mount-proc --",                      // PID ns still on
		"env -u DBUS_SESSION_BUS_ADDRESS",                           // D-Bus still scrubbed
		"mount -t tmpfs -o uid=1000,mode=0700 tmpfs /run/user/1000", // D-Bus dir still masked
	} {
		if !strings.Contains(gui, want) {
			t.Fatalf("GUI script missing %q: %s", want, gui)
		}
	}

	// --allow-namespaces opts out of ONLY the seccomp block: no harden-exec, but
	// the session isolation (PID/IPC ns, masks, runuser) stays on.
	ns := nativeWorkloadScript(cg, "/wd", "bash", nativeWorkloadShellFlag, "claude", "alice", "",
		"/opt/leash", hardenOpts{enabled: true, uid: "1000", allowNamespaces: true})
	if strings.Contains(ns, "--harden-exec") {
		t.Fatalf("allow-namespaces script must not seccomp-harden: %s", ns)
	}
	for _, want := range []string{
		"exec unshare --ipc --pid --fork --mount-proc --", // leash's own isolation still on
		"runuser -u alice --",
	} {
		if !strings.Contains(ns, want) {
			t.Fatalf("allow-namespaces script missing %q: %s", want, ns)
		}
	}
}

func TestNativeLeashdDied(t *testing.T) {
	r := &runner{}
	n := nativeLauncher{r: r}
	if n.leashdDied() {
		t.Fatal("no leashd → not died")
	}
	ch := make(chan struct{})
	r.leashd = &injectedProc{done: ch}
	if n.leashdDied() {
		t.Fatal("open channel → not died")
	}
	close(ch)
	if !n.leashdDied() {
		t.Fatal("closed channel → died")
	}
}

// A leashd that exited before the enforcement-ready marker means nothing
// enforces (leashd is also the L7 proxy), so WaitReady must refuse (issue
// #162: a policy that failed to load used to warn and run the workload
// unenforced). Uses the leashd-died fast path so the test doesn't sit through
// the readiness timeout.
func TestNativeWaitReadyFailClosed(t *testing.T) {
	exited := make(chan struct{})
	close(exited) // simulate leashd already gone → WaitReady stops on the first poll

	r := &runner{}
	r.cfg.shareDir = t.TempDir() // present but no enforcement-ready marker
	r.leashd = &injectedProc{done: exited}
	r.logger = log.New(io.Discard, "", 0)
	err := (nativeLauncher{r: r}).WaitReady(context.Background())
	if err == nil {
		t.Fatal("WaitReady must refuse when leashd died before ready")
	}
	if !strings.Contains(err.Error(), "fail-closed") || !strings.Contains(err.Error(), "exited before enforcement was ready") {
		t.Fatalf("error should say leashd exited and fail-closed: %v", err)
	}
}

// The refusal for a dead leashd names its FATAL reason (e.g. the Cedar error),
// or falls back to the log tail when leashd printed no FATAL line.
func TestLeashdExitedVerdictReason(t *testing.T) {
	dir := t.TempDir()
	fatalLog := filepath.Join(dir, "fatal.log")
	if err := os.WriteFile(fatalLog, []byte("leashd_mounts public=/x\n2026/10/16 error: invalid Cedar policy\nleash: FATAL: error: invalid Cedar policy; file: /p/bad.cedar:1:1; hint: Review the Cedar syntax\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := leashdExitedVerdict(fatalLog)
	if err == nil || !strings.Contains(err.Error(), "invalid Cedar policy; file: /p/bad.cedar:1:1") {
		t.Fatalf("want the FATAL reason in the refusal: %v", err)
	}

	plainLog := filepath.Join(dir, "plain.log")
	if err := os.WriteFile(plainLog, []byte("something broke\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	err = leashdExitedVerdict(plainLog)
	if err == nil || !strings.Contains(err.Error(), "something broke") {
		t.Fatalf("want the log tail when there is no FATAL line: %v", err)
	}

	if err := leashdExitedVerdict(filepath.Join(dir, "missing.log")); err == nil {
		t.Fatal("a missing log must still refuse")
	}
}

// Unconfirmed native enforcement is always refused, whether or not the L7
// proxy is up: there is no proxy-only release.
func TestNotReadyVerdict(t *testing.T) {
	err := notReadyVerdict("not ready", "/tmp/x.log")
	if err == nil {
		t.Fatal("notReadyVerdict must always refuse")
	}
	for _, want := range []string{"not ready", "fail-closed", enforcement.FailClosedRemedy, "/tmp/x.log"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error missing %q: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "allow-proxy-only") {
		t.Fatalf("error must not suggest a proxy-only opt-out: %v", err)
	}
}

// Native readiness refuses when leashd stays alive but never publishes the
// marker, whether or not the L7 proxy is up.
func TestNativeWaitReadyTimeoutRefusesWithAndWithoutProxy(t *testing.T) {
	for _, egressFailed := range []bool{false, true} {
		r := &runner{}
		r.cfg.shareDir = t.TempDir()
		r.cfg.bootstrapTimeout = 2 * caCertWaitDelay
		r.nativeEgressFailed = egressFailed
		r.leashd = &injectedProc{done: make(chan struct{})} // alive, never ready
		r.logger = log.New(io.Discard, "", 0)
		err := (nativeLauncher{r: r}).WaitReady(context.Background())
		if err == nil || !strings.Contains(err.Error(), "fail-closed") {
			t.Fatalf("egressFailed=%t: WaitReady must refuse, got %v", egressFailed, err)
		}
	}
}

// The native readiness wait honors the bootstrap timeout instead of a fixed
// 10s: a slow LSM attach (large rule sets on a loaded host) must not be refused
// while leashd is still alive and attaching.
func TestNativeWaitReadyWaitsForSlowAttach(t *testing.T) {
	r := &runner{}
	r.cfg.shareDir = t.TempDir()
	r.cfg.bootstrapTimeout = 5 * time.Second
	r.leashd = &injectedProc{done: make(chan struct{})} // alive
	r.logger = log.New(io.Discard, "", 0)
	go func() {
		time.Sleep(3 * caCertWaitDelay)
		_ = os.WriteFile(filepath.Join(r.cfg.shareDir, entrypoint.EnforcementReadyFileName), []byte("ok"), 0o644)
	}()
	if err := (nativeLauncher{r: r}).WaitReady(context.Background()); err != nil {
		t.Fatalf("WaitReady must succeed once enforcement is ready: %v", err)
	}
}

func TestNativeWaitReadyTimesOutAtBootstrapTimeout(t *testing.T) {
	r := &runner{}
	r.cfg.shareDir = t.TempDir()
	r.cfg.bootstrapTimeout = 2 * caCertWaitDelay
	r.leashd = &injectedProc{done: make(chan struct{})} // alive, never ready
	r.logger = log.New(io.Discard, "", 0)
	start := time.Now()
	err := (nativeLauncher{r: r}).WaitReady(context.Background())
	if err == nil || !strings.Contains(err.Error(), "LEASH_BOOTSTRAP_TIMEOUT") || !strings.Contains(err.Error(), "fail-closed") {
		t.Fatalf("want a fail-closed timeout naming LEASH_BOOTSTRAP_TIMEOUT: %v", err)
	}
	if elapsed := time.Since(start); elapsed < r.cfg.bootstrapTimeout {
		t.Fatalf("gave up after %s, before the configured %s", elapsed, r.cfg.bootstrapTimeout)
	}
}

func TestNativeReadyTimeoutDefault(t *testing.T) {
	if got := nativeReadyTimeout(0); got != defaultBootstrapTimeout {
		t.Fatalf("default = %s, want %s", got, defaultBootstrapTimeout)
	}
	if got := nativeReadyTimeout(42 * time.Second); got != 42*time.Second {
		t.Fatalf("configured = %s", got)
	}
}

func TestNativeEgressDerivation(t *testing.T) {
	n := nativeLauncher{r: &runner{}}
	e1, e2 := n.egress(), n.egress()
	if e1 != e2 {
		t.Fatalf("egress not deterministic: %+v vs %+v", e1, e2)
	}
	if !strings.HasPrefix(e1.subnet, "10.") || e1.hostIP != e1.subnet+".1" || e1.nsIP != e1.subnet+".2" {
		t.Fatalf("bad addressing: %+v", e1)
	}
	if len(e1.vethHost) > 15 || len(e1.vethNS) > 15 { // Linux iface name limit
		t.Fatalf("veth name exceeds 15 chars: %+v", e1)
	}
	if e1.vethHost == e1.vethNS {
		t.Fatalf("veth host/ns names collide: %s", e1.vethHost)
	}
}

func TestNativeLayer2Wrap(t *testing.T) {
	n := nativeLauncher{r: &runner{}}
	argv := n.layer2Wrap("echo hi")
	joined := strings.Join(argv, " ")
	for _, want := range []string{"nsenter", "--net=", "unshare --mount --propagation private", "mount --bind", "/etc/resolv.conf", "echo hi"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("layer2Wrap missing %q in %q", want, joined)
		}
	}
	if argv[len(argv)-2] != "-c" {
		t.Fatalf("expected `sh -c <script>` tail, got %v", argv[len(argv)-3:])
	}
}

// egress must be DEFAULT-DENY: only DNS-to-resolvers and the proxy's :80/:443 out,
// everything else (SSH :22, arbitrary TCP, non-resolver DNS) dropped. Regression
// guard for the exfil hole where FORWARD blanket-ACCEPTed the box's egress.
func TestEgressNATRulesDefaultDeny(t *testing.T) {
	t.Parallel()

	e := egressNet{ns: "box", vethHost: "lhabc", subnet: "10.123.4", prefix: 30}
	var lines []string
	for _, r := range egressNATRules(e) {
		lines = append(lines, strings.Join(r, " "))
	}
	joined := strings.Join(lines, "\n")

	if strings.Contains(joined, "-A FORWARD -i lhabc -j ACCEPT") {
		t.Fatalf("blanket egress ACCEPT must be gone (that was the exfil hole):\n%s", joined)
	}
	if lines[len(lines)-1] != "-A FORWARD -i lhabc -j DROP" {
		t.Fatalf("the default-deny DROP must be the LAST forward rule:\n%s", joined)
	}
	for _, want := range []string{
		"-t nat -A POSTROUTING -s 10.123.4.0/30 -j MASQUERADE",
		"-A FORWARD -i lhabc -p tcp --dport 80 -j ACCEPT",
		"-A FORWARD -i lhabc -p tcp --dport 443 -j ACCEPT",
		"-A FORWARD -i lhabc -p udp -d 1.1.1.1 --dport 53 -j ACCEPT",
		"-A FORWARD -i lhabc -p tcp -d 8.8.8.8 --dport 53 -j ACCEPT",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing required rule %q in:\n%s", want, joined)
		}
	}
	// No DNS allowance for a non-resolver.
	if strings.Contains(joined, "-d 9.9.9.9") {
		t.Fatalf("DNS must be restricted to the configured resolvers:\n%s", joined)
	}
}
