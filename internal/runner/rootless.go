package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"

	"github.com/strongdm/leash/internal/enforcement"
	"github.com/strongdm/leash/internal/enforcerd"
)

// Rootless container engines cannot load leash's eBPF LSM (Layer 1): the
// leash container is root only inside a user namespace. The leash enforcer
// daemon attaches it instead (docs/ROOTLESS.md), and the run reports
// enforcement=lsm exactly as a rootful one. leashd reaches the daemon in one
// of two ways:
//
//   - rootless podman: the daemon's socket directory is mounted into the leash
//     container, which keeps the caller's leash group (--group-add
//     keep-groups), and leashd dials the socket;
//   - rootless Docker, whose containers cannot keep supplementary groups: the
//     leash client dials the daemon itself and hands the connected socket to
//     leashd through a single-use broker socket mounted only into the leash
//     container (enforcerd.StartBroker). The daemon then authenticates the
//     client, a host process of the calling user outside every governed
//     cgroup, with its usual checks.
//
// Without a usable daemon a rootless run is refused before anything starts:
// leash never runs a workload with only the L7 proxy enforcing.

// enforcerSocketDirInContainer is where the daemon's socket directory (podman)
// or the broker's directory (Docker) is mounted in the leash container.
const enforcerSocketDirInContainer = "/run/leash-enforcer"

// rootlessHostOS is runtime.GOOS; tests replace it.
var rootlessHostOS = runtime.GOOS

// checkEnforcerDaemon is replaced in tests.
var checkEnforcerDaemon = func(ctx context.Context, socket string) enforcerd.Report {
	return enforcerd.Check(ctx, socket)
}

// startEnforcerBroker is replaced in tests.
var startEnforcerBroker = enforcerd.StartBroker

// detectRootlessEngine reports whether the container engine runs rootless.
func (r *runner) detectRootlessEngine(ctx context.Context) (bool, error) {
	switch r.rt().Name() {
	case "podman":
		out, err := r.rt().Output(ctx, "info", "--format", "{{.Host.Security.Rootless}}")
		if err != nil {
			// Not knowing is not a hole: a rootless leashd that cannot load
			// the eBPF LSM still fails closed on its own; only the early,
			// actionable refusal is lost.
			r.debugf("podman info: %v; cannot tell whether podman is rootless", err)
			return false, nil
		}
		return strings.TrimSpace(out) == "true", nil
	case "docker":
		out, err := r.rt().Output(ctx, "info", "--format", "{{json .SecurityOptions}}")
		if err != nil {
			return false, nil // engine probing errors surface elsewhere
		}
		return strings.Contains(out, "name=rootless"), nil
	default:
		return false, nil
	}
}

// rootlessRefusal is the error for a rootless run that cannot get kernel
// enforcement. It names the exact commands that fix it.
func rootlessRefusal(engine string, rep enforcerd.Report) error {
	var b strings.Builder
	fmt.Fprintf(&b, "rootless %s cannot load the eBPF LSM (Layer 1) itself, so leash will not start (fail-closed).\n", engine)
	fmt.Fprintf(&b, "Kernel enforcement for rootless runs comes from the leash enforcer daemon, which is not usable: %s.\n", rep.Error)
	if rep.Remedy != "" && !strings.Contains(rep.Remedy, "leash daemon install") {
		fmt.Fprintf(&b, "  fix: %s\n", rep.Remedy)
	}
	b.WriteString("Install it once with:  sudo leash daemon install\n")
	b.WriteString("Check it with:         leash daemon status")
	return errors.New(b.String())
}

// preflightRootless decides how a rootless run is enforced: through the
// enforcer daemon (r.enforcerSocket), or not at all.
func (r *runner) preflightRootless(ctx context.Context) error {
	if r.usingNativeRuntime() || rootlessHostOS != "linux" {
		return nil
	}
	if strings.TrimSpace(os.Getenv("DOCKER_HOST")) != "" || strings.TrimSpace(os.Getenv("CONTAINER_HOST")) != "" {
		return nil // remote engine: the kernel that matters is not this host's
	}
	rootless, err := r.detectRootlessEngine(ctx)
	if err != nil || !rootless {
		return err
	}
	engine := r.rt().Name()
	// The check runs as this client. For rootless Docker the client is also
	// the daemon's caller for the run (see enforcerDaemonArgs), so this is
	// exactly the identity the daemon will authenticate.
	rep := checkEnforcerDaemon(ctx, enforcerd.SocketPath())
	if rep.Usable {
		r.enforcerSocket = rep.Socket
		r.enforcerViaBroker = engine == "docker"
		r.debugf("rootless %s: eBPF LSM enforcement through the leash enforcer daemon at %s (daemon %s)", engine, rep.Socket, rep.Status.Version)
		return nil
	}
	return rootlessRefusal(engine, rep)
}

// enforcerDaemonArgs are the leash container's extra arguments for a run
// enforced through the daemon. workload is the governed cgroup.
//
// Rootless podman: the socket's directory, the caller's supplementary groups
// (the socket is group "leash", mode 0660; rootless podman drops host groups
// otherwise) and the socket path for leashd.
//
// Rootless Docker: a private broker directory and the broker socket path for
// leashd. The broker serves one connection: the one leashd attaches with.
func (r *runner) enforcerDaemonArgs(workload string) ([]string, error) {
	if r.enforcerSocket == "" {
		return nil, nil
	}
	if !r.enforcerViaBroker {
		dir, base := filepath.Split(r.enforcerSocket)
		return []string{
			"-v", filepath.Clean(dir) + ":" + enforcerSocketDirInContainer,
			"--group-add", "keep-groups",
			"-e", enforcerd.EnvSocket + "=" + filepath.Join(enforcerSocketDirInContainer, base),
		}, nil
	}
	if r.enforcerBroker == nil {
		if strings.TrimSpace(workload) == "" {
			return nil, errors.New("rootless Docker: no workload cgroup to govern through the leash enforcer daemon")
		}
		// /tmp, not $TMPDIR: unix socket paths are limited to ~104 bytes.
		// MkdirTemp creates the directory 0700: only this user can reach it
		// (a rootless Docker container's root is this user).
		dir, err := os.MkdirTemp("/tmp", "leash-enforcer-")
		if err != nil {
			return nil, fmt.Errorf("rootless Docker: create the enforcer broker directory: %w", err)
		}
		b, err := startEnforcerBroker(enforcerd.BrokerConfig{
			Dir:          dir,
			DaemonSocket: r.enforcerSocket,
			Workload:     workload,
			Logf:         r.debugf,
		})
		if err != nil {
			_ = os.RemoveAll(dir)
			return nil, fmt.Errorf("rootless Docker: %w", err)
		}
		r.enforcerBroker = b
		r.enforcerBrokerDir = dir
	}
	return []string{
		"-v", r.enforcerBrokerDir + ":" + enforcerSocketDirInContainer,
		"-e", enforcerd.EnvBroker + "=" + filepath.Join(enforcerSocketDirInContainer, enforcerd.BrokerSocketName),
	}, nil
}

// closeEnforcerBroker stops the broker (if leashd never took its connection)
// and removes its directory.
func (r *runner) closeEnforcerBroker() {
	if r.enforcerBroker != nil {
		_ = r.enforcerBroker.Close()
		r.enforcerBroker = nil
	}
	if r.enforcerBrokerDir != "" {
		_ = os.RemoveAll(r.enforcerBrokerDir)
		r.enforcerBrokerDir = ""
	}
}

// workloadFinishedFlag is embedded in runner (see runner.workloadFinished).
type workloadFinishedFlag = atomic.Bool

// enforcementVia renders Layer1Via for the enforcement line.
func enforcementVia(st enforcement.Status) string {
	if st.Layer1Via == "" {
		return ""
	}
	return " via=" + st.Layer1Via
}
