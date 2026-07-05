package runner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
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

func TestNativeHostLeashdArgv(t *testing.T) {
	r := &runner{}
	r.cfg.proxyPort = "18000"
	r.nativeEgressFailed = true // force the LSM-only path deterministically (independent of euid)
	n := nativeLauncher{r: r}

	argv := n.hostLeashdArgv("/usr/local/bin/leash", "/run/netns/leash-native-x", "/sys/fs/cgroup/scope")
	joined := strings.Join(argv, " ")
	// LSM-only: host netns, no nsenter, --lsm-only, and no --require-lsm by default.
	want := "/usr/local/bin/leash --daemon --host --lsm-only --cgroup /sys/fs/cgroup/scope --proxy-port 18000"
	if joined != want {
		t.Fatalf("argv = %q\nwant   %q", joined, want)
	}

	// --require-lsm on the client propagates to the daemon args (fail-closed).
	r.opts.requireLSM = true
	joined = strings.Join(n.hostLeashdArgv("/usr/local/bin/leash", "/run/netns/leash-native-x", "/sys/fs/cgroup/scope"), " ")
	want = "/usr/local/bin/leash --daemon --host --lsm-only --require-lsm --cgroup /sys/fs/cgroup/scope --proxy-port 18000"
	if joined != want {
		t.Fatalf("with --require-lsm argv = %q\nwant   %q", joined, want)
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
	rel, _ := hostOutput(ctx, "systemctl", "--user", "show", "-p", "ControlGroup", "--value", n.unitName())
	if strings.TrimSpace(rel) != "" {
		t.Fatalf("unit %s still present after Remove (ControlGroup=%q)", n.unitName(), strings.TrimSpace(rel))
	}
}

func TestNativeWorkloadScript(t *testing.T) {
	cg := "/sys/fs/cgroup/system.slice/leash-native-x.service"

	// Unhardened (rootless path): plain placement — no ns/mask/scrub/harden.
	plain := nativeWorkloadScript(cg, "/wd", "bash", "claude", "", "", "/opt/leash", hardenOpts{})
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
	h := nativeWorkloadScript(cg, "/wd", "bash", "claude", "alice", "/share/ca-cert.pem",
		"/opt/leash", hardenOpts{enabled: true, uid: "1000"})
	for _, want := range []string{
		"mount -t tmpfs -o uid=1000,mode=0700 tmpfs /run/user/1000",
		"/tmp/.X11-unix",
		"cgroup.procs",
		"exec unshare --ipc --pid --fork --mount-proc --",
		"runuser -u alice --",
		"/opt/leash --harden-exec --",
		"env -u DBUS_SESSION_BUS_ADDRESS -u DISPLAY -u XAUTHORITY",
		"export NODE_EXTRA_CA_CERTS=/share/ca-cert.pem; exec claude",
	} {
		if !strings.Contains(h, want) {
			t.Fatalf("hardened script missing %q: %s", want, h)
		}
	}
	if strings.Index(h, "cgroup.procs") > strings.Index(h, "unshare") {
		t.Fatalf("cgroup write must come before the unshare: %s", h)
	}
	// The seccomp filter must be applied AFTER leash's own unshare/mount (so leash's
	// setup succeeds) but is inherited by the agent: harden-exec sits inside runuser,
	// which sits inside unshare.
	if !(strings.Index(h, "unshare") < strings.Index(h, "runuser") &&
		strings.Index(h, "runuser") < strings.Index(h, "--harden-exec")) {
		t.Fatalf("harden-exec must nest inside runuser inside unshare: %s", h)
	}

	// Hardened but no self path (os.Executable failed): degrade gracefully — the
	// session isolation still applies, but no seccomp re-exec.
	noSelf := nativeWorkloadScript(cg, "/wd", "bash", "claude", "alice", "", "", hardenOpts{enabled: true, uid: "1000"})
	if strings.Contains(noSelf, "--harden-exec") {
		t.Fatalf("no-self script must not contain harden-exec: %s", noSelf)
	}

	// GUI opt-outs: --allow-display + --share-ipc → no X11 mask, DISPLAY kept, no
	// IPC ns; but D-Bus stays masked/scrubbed (not opted out).
	gui := nativeWorkloadScript(cg, "/wd", "bash", "app", "alice", "",
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
