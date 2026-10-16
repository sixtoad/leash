package runner

import (
	"context"
	"errors"
	"io"
	"log"
	"os/exec"
	"strings"
	"testing"

	"github.com/strongdm/leash/internal/enforcement"
	"github.com/strongdm/leash/internal/enforcerd"
)

// infoRuntime answers `info` like a podman/docker engine.
type infoRuntime struct {
	name, info string
	infoErr    error
}

func (f infoRuntime) Run(ctx context.Context, args ...string) error { return nil }
func (f infoRuntime) Output(ctx context.Context, args ...string) (string, error) {
	if len(args) > 0 && args[0] == "info" {
		return f.info, f.infoErr
	}
	return "", nil
}
func (f infoRuntime) ExecWithInput(ctx context.Context, container, shellCommand string, input io.Reader) error {
	return nil
}
func (f infoRuntime) Cmd(ctx context.Context, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, "true")
}
func (f infoRuntime) Name() string { return f.name }

func withDaemon(t *testing.T, rep enforcerd.Report) *int {
	t.Helper()
	calls := 0
	orig := checkEnforcerDaemon
	checkEnforcerDaemon = func(ctx context.Context, socket string) enforcerd.Report {
		calls++
		rep.Socket = socket
		return rep
	}
	t.Cleanup(func() { checkEnforcerDaemon = orig })
	t.Setenv("DOCKER_HOST", "")
	t.Setenv("CONTAINER_HOST", "")
	t.Setenv(enforcerd.EnvSocket, "")
	origOS := rootlessHostOS
	rootlessHostOS = "linux"
	t.Cleanup(func() { rootlessHostOS = origOS })
	return &calls
}

func rootlessRunner(rt Runtime, requireLSM bool) *runner {
	return &runner{runtime: rt, logger: log.New(io.Discard, "", 0), cfg: config{requireLSM: requireLSM}}
}

func TestRootlessPodmanWithoutDaemonIsRefused(t *testing.T) {
	withDaemon(t, enforcerd.Report{Error: "dial unix /run/leash/enforcerd.sock: connect: no such file or directory", Remedy: enforcerd.RemedyFor(errors.New("no such file or directory"))})
	r := rootlessRunner(infoRuntime{name: "podman", info: "true\n"}, true)
	err := r.preflightRootless(context.Background())
	if err == nil {
		t.Fatal("a rootless run without a usable daemon must be refused")
	}
	for _, want := range []string{"rootless podman", "fail-closed", "sudo leash daemon install", "leash daemon status", "--allow-proxy-only", "no such file or directory"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal lacks %q:\n%s", want, err)
		}
	}
	if r.enforcerSocket != "" {
		t.Fatal("no socket may be configured for a refused run")
	}
}

func TestRootlessPodmanPermissionDeniedNamesTheGroup(t *testing.T) {
	withDaemon(t, enforcerd.Report{Error: "connect: permission denied", Remedy: enforcerd.RemedyFor(errors.New("connect: permission denied"))})
	err := rootlessRunner(infoRuntime{name: "podman", info: "true"}, true).preflightRootless(context.Background())
	if err == nil || !strings.Contains(err.Error(), "usermod -aG leash") {
		t.Fatalf("permission denied must name the group fix: %v", err)
	}
}

func TestRootlessPodmanAllowProxyOnlyProceedsWithoutDaemon(t *testing.T) {
	withDaemon(t, enforcerd.Report{Error: "no such file or directory"})
	r := rootlessRunner(infoRuntime{name: "podman", info: "true"}, false)
	if err := r.preflightRootless(context.Background()); err != nil {
		t.Fatalf("--allow-proxy-only must proceed: %v", err)
	}
	if r.enforcerSocket != "" || len(r.enforcerDaemonArgs()) != 0 {
		t.Fatal("proxy-only must not wire the daemon")
	}
}

func TestRootlessPodmanUsesUsableDaemon(t *testing.T) {
	withDaemon(t, enforcerd.Report{Reachable: true, Usable: true, Status: &enforcerd.Status{Version: "v1", BPFLSM: "active"}})
	r := rootlessRunner(infoRuntime{name: "podman", info: "true"}, true)
	if err := r.preflightRootless(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.enforcerSocket != enforcerd.DefaultSocketPath {
		t.Fatalf("enforcerSocket = %q", r.enforcerSocket)
	}
	args := strings.Join(r.enforcerDaemonArgs(), " ")
	for _, want := range []string{"-v /run/leash:/run/leash-enforcer", "--group-add keep-groups", "-e LEASH_ENFORCER_SOCKET=/run/leash-enforcer/enforcerd.sock"} {
		if !strings.Contains(args, want) {
			t.Errorf("leash container args lack %q: %s", want, args)
		}
	}
}

func TestRootfulAndUndetectableEnginesSkipTheDaemon(t *testing.T) {
	calls := withDaemon(t, enforcerd.Report{})
	for _, rt := range []Runtime{
		infoRuntime{name: "podman", info: "false"},
		infoRuntime{name: "podman", infoErr: errors.New("boom")}, // leashd still fails closed on its own
		infoRuntime{name: "docker", info: `["name=apparmor","name=seccomp,profile=builtin"]`},
	} {
		r := rootlessRunner(rt, true)
		if err := r.preflightRootless(context.Background()); err != nil {
			t.Fatalf("%s: %v", rt.Name(), err)
		}
		if r.enforcerSocket != "" {
			t.Fatalf("%s: rootful must not use the daemon", rt.Name())
		}
	}
	if *calls != 0 {
		t.Fatal("the daemon must only be consulted for rootless podman")
	}
}

func TestRootlessDockerIsRefusedUnlessProxyOnly(t *testing.T) {
	withDaemon(t, enforcerd.Report{})
	rt := infoRuntime{name: "docker", info: `["name=seccomp,profile=builtin","name=rootless","name=cgroupns"]`}
	err := rootlessRunner(rt, true).preflightRootless(context.Background())
	if err == nil || !strings.Contains(err.Error(), "rootless docker") || !strings.Contains(err.Error(), "--allow-proxy-only") {
		t.Fatalf("rootless docker: %v", err)
	}
	if err := rootlessRunner(rt, false).preflightRootless(context.Background()); err != nil {
		t.Fatalf("rootless docker with --allow-proxy-only: %v", err)
	}
}

func TestEnforcementLineNamesTheDaemon(t *testing.T) {
	st := enforcement.Describe(true, true, true)
	if got := formatEnforcementLine(st); got != "leash: enforcement=lsm layer1=active layer2=active" {
		t.Fatalf("rootful line changed: %q", got)
	}
	st.Layer1Via = enforcement.Layer1ViaEnforcerDaemon
	if got := formatEnforcementLine(st); got != "leash: enforcement=lsm layer1=active layer2=active via=enforcer-daemon" {
		t.Fatalf("daemon line = %q", got)
	}
}
