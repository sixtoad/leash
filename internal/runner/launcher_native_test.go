package runner

import (
	"context"
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
	r := &runner{}
	r.cfg.targetContainer = "Acme_App"
	n := nativeLauncher{r: r}
	if got := n.unitName(); got != "leash-native-acme-app.service" {
		t.Fatalf("unitName = %q", got)
	}
	if got := n.netnsName(); got != "leash-native-acme-app" {
		t.Fatalf("netnsName = %q", got)
	}
	// Empty target falls back to a stable name (no naked "leash-native-").
	if got := (nativeLauncher{r: &runner{}}).unitName(); got != "leash-native-session.service" {
		t.Fatalf("fallback unitName = %q", got)
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
	n := nativeLauncher{r: r}

	argv := n.hostLeashdArgv("/usr/local/bin/leash", "/run/netns/leash-native-x", "/sys/fs/cgroup/scope")
	joined := strings.Join(argv, " ")
	want := "nsenter --net=/run/netns/leash-native-x -- /usr/local/bin/leash --daemon --host --cgroup /sys/fs/cgroup/scope --proxy-port 18000"
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
	for _, want := range []string{"requires root", "would run:", "nsenter", "--daemon --host", "LEASHD-HOST-MODE.md"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error %q missing %q", msg, want)
		}
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

	// Run a workload in the box; it must report the box's cgroup.
	out, err := n.execInBox(ctx, cgroupPath, "cat", "/proc/self/cgroup").CombinedOutput()
	if err != nil {
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
