package runner

import (
	"context"
	"errors"
	"io"
	"log"
	"os"
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

func rootlessRunner(rt Runtime) *runner {
	return &runner{runtime: rt, logger: log.New(io.Discard, "", 0)}
}

func TestRootlessPodmanWithoutDaemonIsRefused(t *testing.T) {
	withDaemon(t, enforcerd.Report{Error: "dial unix /run/leash/enforcerd.sock: connect: no such file or directory", Remedy: enforcerd.RemedyFor(errors.New("no such file or directory"))})
	r := rootlessRunner(infoRuntime{name: "podman", info: "true\n"})
	err := r.preflightRootless(context.Background())
	if err == nil {
		t.Fatal("a rootless run without a usable daemon must be refused")
	}
	for _, want := range []string{"rootless podman", "fail-closed", "sudo leash daemon install", "leash daemon status", "no such file or directory"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal lacks %q:\n%s", want, err)
		}
	}
	if strings.Contains(err.Error(), "allow-proxy-only") || strings.Contains(err.Error(), "L7 proxy") {
		t.Errorf("refusal must not offer a proxy-only way out:\n%s", err)
	}
	if r.enforcerSocket != "" {
		t.Fatal("no socket may be configured for a refused run")
	}
}

func TestRootlessPodmanPermissionDeniedNamesTheGroup(t *testing.T) {
	withDaemon(t, enforcerd.Report{Error: "connect: permission denied", Remedy: enforcerd.RemedyFor(errors.New("connect: permission denied"))})
	err := rootlessRunner(infoRuntime{name: "podman", info: "true"}).preflightRootless(context.Background())
	if err == nil || !strings.Contains(err.Error(), "usermod -aG leash") {
		t.Fatalf("permission denied must name the group fix: %v", err)
	}
}

func TestRootlessPodmanUsesUsableDaemon(t *testing.T) {
	withDaemon(t, enforcerd.Report{Reachable: true, Usable: true, Status: &enforcerd.Status{Version: "v1", BPFLSM: "active"}})
	r := rootlessRunner(infoRuntime{name: "podman", info: "true"})
	if err := r.preflightRootless(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.enforcerSocket != enforcerd.DefaultSocketPath {
		t.Fatalf("enforcerSocket = %q", r.enforcerSocket)
	}
	daemonArgs, err := r.enforcerDaemonArgs("/sys/fs/cgroup/w")
	if err != nil {
		t.Fatal(err)
	}
	args := strings.Join(daemonArgs, " ")
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
		r := rootlessRunner(rt)
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

var rootlessDockerInfo = `["name=seccomp,profile=builtin","name=rootless","name=cgroupns"]`

// Rootless Docker without a usable daemon is refused with the install hint
// (#207), never run with only the proxy.
func TestRootlessDockerWithoutDaemonIsRefused(t *testing.T) {
	withDaemon(t, enforcerd.Report{Error: "dial unix /run/leash/enforcerd.sock: connect: no such file or directory", Remedy: enforcerd.RemedyFor(errors.New("no such file or directory"))})
	r := rootlessRunner(infoRuntime{name: "docker", info: rootlessDockerInfo})
	err := r.preflightRootless(context.Background())
	if err == nil {
		t.Fatal("rootless docker without a usable daemon must be refused")
	}
	for _, want := range []string{"rootless docker", "fail-closed", "sudo leash daemon install", "leash daemon status"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal lacks %q:\n%s", want, err)
		}
	}
	if strings.Contains(err.Error(), "allow-proxy-only") || strings.Contains(err.Error(), "issues/207") {
		t.Fatalf("rootless docker refusal: %v", err)
	}
	if r.enforcerSocket != "" || r.enforcerViaBroker {
		t.Fatal("no daemon may be configured for a refused run")
	}
}

// Rootless Docker with a usable daemon goes through the client-side broker:
// the leash container gets a private broker directory and no group or daemon
// socket.
func TestRootlessDockerUsesTheBroker(t *testing.T) {
	withDaemon(t, enforcerd.Report{Reachable: true, Usable: true, Status: &enforcerd.Status{Version: "v1", BPFLSM: "active"}})
	var got enforcerd.BrokerConfig
	orig := startEnforcerBroker
	startEnforcerBroker = func(cfg enforcerd.BrokerConfig) (*enforcerd.Broker, error) {
		got = cfg
		return nil, nil
	}
	t.Cleanup(func() { startEnforcerBroker = orig })

	r := rootlessRunner(infoRuntime{name: "docker", info: rootlessDockerInfo})
	if err := r.preflightRootless(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.enforcerSocket != enforcerd.DefaultSocketPath || !r.enforcerViaBroker {
		t.Fatalf("enforcerSocket = %q, viaBroker = %v", r.enforcerSocket, r.enforcerViaBroker)
	}
	daemonArgs, err := r.enforcerDaemonArgs("/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/user.slice/docker-abc.scope")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.closeEnforcerBroker)
	args := strings.Join(daemonArgs, " ")
	if r.enforcerBrokerDir == "" || !strings.HasPrefix(r.enforcerBrokerDir, "/tmp/leash-enforcer-") {
		t.Fatalf("broker dir = %q", r.enforcerBrokerDir)
	}
	for _, want := range []string{"-v " + r.enforcerBrokerDir + ":/run/leash-enforcer", "-e LEASH_ENFORCER_BROKER=/run/leash-enforcer/broker.sock"} {
		if !strings.Contains(args, want) {
			t.Errorf("leash container args lack %q: %s", want, args)
		}
	}
	for _, bad := range []string{"keep-groups", "LEASH_ENFORCER_SOCKET", "/run/leash:"} {
		if strings.Contains(args, bad) {
			t.Errorf("leash container args must not carry %q: %s", bad, args)
		}
	}
	if got.DaemonSocket != enforcerd.DefaultSocketPath || got.Dir != r.enforcerBrokerDir || !strings.HasSuffix(got.Workload, "docker-abc.scope") {
		t.Fatalf("broker config = %+v", got)
	}
	dir := r.enforcerBrokerDir
	r.closeEnforcerBroker()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("broker dir %s not removed: %v", dir, err)
	}
}

func TestEnforcementLineNamesTheDaemon(t *testing.T) {
	st := enforcement.Describe(true, true)
	if got := formatEnforcementLine(st); got != "leash: enforcement=lsm layer1=active layer2=active" {
		t.Fatalf("rootful line changed: %q", got)
	}
	st.Layer1Via = enforcement.Layer1ViaEnforcerDaemon
	if got := formatEnforcementLine(st); got != "leash: enforcement=lsm layer1=active layer2=active via=enforcer-daemon" {
		t.Fatalf("daemon line = %q", got)
	}
}
