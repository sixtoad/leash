package runner

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestNewRuntimeResolvesNative(t *testing.T) {
	rt, err := newRuntime("native")
	if err != nil {
		t.Fatalf("newRuntime(native): %v", err)
	}
	if _, ok := rt.(nativeRuntime); !ok {
		t.Fatalf("native resolved to %T, want nativeRuntime", rt)
	}
	if rt.Name() != "native" {
		t.Fatalf("Name() = %q, want native", rt.Name())
	}
}

func TestNativeScopeArgs(t *testing.T) {
	n := newNativeRuntime() // userScope=true by default
	got := n.scopeArgs("bash", "-c", "echo hi")

	want := []string{
		"--user", "--scope", "--quiet", "--collect", "--property=Delegate=yes",
		"--", "bash", "-c", "echo hi",
	}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("scopeArgs = %v, want %v", got, want)
	}
}

func TestNativeScopeArgsSystemScopeWithProps(t *testing.T) {
	n := nativeRuntime{systemdRun: "systemd-run", userScope: false, extraProps: []string{"MemoryMax=512M", "--property=CPUWeight=50"}}
	got := n.scopeArgs("agent")

	// No --user (system scope); both properties normalized to --property=.
	joined := strings.Join(got, " ")
	for _, want := range []string{"--scope", "--property=Delegate=yes", "--property=MemoryMax=512M", "--property=CPUWeight=50", "-- agent"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("scopeArgs %q missing %q", joined, want)
		}
	}
	if strings.Contains(joined, "--user") {
		t.Fatalf("system scope should not contain --user: %q", joined)
	}
	if strings.Contains(joined, "--property=--property=") {
		t.Fatalf("property double-prefixed: %q", joined)
	}
}

func TestNativeCmdWrapsInScope(t *testing.T) {
	n := nativeRuntime{systemdRun: "/usr/bin/systemd-run", userScope: true}
	cmd := n.Cmd(context.Background(), "claude", "--help")

	if cmd.Path != "/usr/bin/systemd-run" {
		t.Fatalf("Cmd.Path = %q, want systemd-run", cmd.Path)
	}
	joined := strings.Join(cmd.Args, " ")
	if !strings.Contains(joined, "--scope") || !strings.HasSuffix(joined, "-- claude --help") {
		t.Fatalf("Cmd.Args = %q, want a scope wrapping the workload", joined)
	}
}

// The container-CLI verbs must fail clearly (not silently no-op), naming the
// verb, so the launch path's container assumptions surface at the call site.
func TestNativeContainerVerbsNotWired(t *testing.T) {
	n := newNativeRuntime()
	ctx := context.Background()

	if err := n.Run(ctx, "run", "--rm", "img"); err == nil || !strings.Contains(err.Error(), `"run"`) {
		t.Fatalf("Run err = %v, want a not-wired error naming run", err)
	}
	if _, err := n.Output(ctx, "inspect", "x"); err == nil || !strings.Contains(err.Error(), `"inspect"`) {
		t.Fatalf("Output err = %v, want a not-wired error naming inspect", err)
	}
	if err := n.ExecWithInput(ctx, "container", "echo hi", nil); err == nil || !strings.Contains(err.Error(), `"exec"`) {
		t.Fatalf("ExecWithInput err = %v, want a not-wired error naming exec", err)
	}
}

// TestNativeScopeLandsInCgroup_Integration runs the backend's real scope argv
// against systemd-run and asserts the child lands in its own delegated scope
// cgroup — the live proof that nativeRuntime builds an enforceable box without a
// container. Skips when there is no usable user systemd manager (CI, macOS).
func TestNativeScopeLandsInCgroup_Integration(t *testing.T) {
	if _, err := exec.LookPath("systemd-run"); err != nil {
		t.Skip("systemd-run not available")
	}
	if os.Getenv("XDG_RUNTIME_DIR") == "" {
		t.Skip("no XDG_RUNTIME_DIR — no user systemd manager")
	}

	n := newNativeRuntime() // --user scope, no root needed
	argv := n.scopeArgs("bash", "-c", `sed 's#^0::#/sys/fs/cgroup#' /proc/self/cgroup`)
	out, err := exec.CommandContext(context.Background(), n.systemdRun, argv...).CombinedOutput()
	if err != nil {
		t.Skipf("user scope unavailable in this environment: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	got := strings.TrimSpace(string(out))
	if !strings.Contains(got, ".scope") || !strings.HasPrefix(got, "/sys/fs/cgroup/") {
		t.Fatalf("workload cgroup = %q, want a /sys/fs/cgroup/...scope path", got)
	}
	t.Logf("native backend placed workload in delegated cgroup: %s", got)
}
