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
// leash container is root only inside a user namespace. With rootless podman
// the leash enforcer daemon attaches it instead (docs/ROOTLESS.md): leashd
// reaches the daemon through the daemon's socket, mounted into the leash
// container, and the run reports enforcement=lsm exactly as a rootful one.
// Without a usable daemon a rootless run is refused before anything starts:
// leash never runs a workload with only the L7 proxy enforcing.

// enforcerSocketInContainer is where the daemon's socket directory is mounted
// in the leash container.
const enforcerSocketDirInContainer = "/run/leash-enforcer"

// rootlessHostOS is runtime.GOOS; tests replace it.
var rootlessHostOS = runtime.GOOS

// checkEnforcerDaemon is replaced in tests.
var checkEnforcerDaemon = func(ctx context.Context, socket string) enforcerd.Report {
	return enforcerd.Check(ctx, socket)
}

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
func rootlessRefusal(engine string, rep *enforcerd.Report) error {
	var b strings.Builder
	fmt.Fprintf(&b, "rootless %s cannot load the eBPF LSM (Layer 1) itself, so leash will not start (fail-closed).\n", engine)
	if rep == nil {
		b.WriteString("The leash enforcer daemon, which gives rootless runs the same kernel enforcement, supports rootless podman only (rootless Docker: https://github.com/sixtoad/leash/issues/207).\n")
		b.WriteString("Use rootless podman with the daemon (sudo leash daemon install), or rootful Docker or podman.")
	} else {
		fmt.Fprintf(&b, "Kernel enforcement for rootless runs comes from the leash enforcer daemon, which is not usable: %s.\n", rep.Error)
		if rep.Remedy != "" && !strings.Contains(rep.Remedy, "leash daemon install") {
			fmt.Fprintf(&b, "  fix: %s\n", rep.Remedy)
		}
		b.WriteString("Install it once with:  sudo leash daemon install\n")
		b.WriteString("Check it with:         leash daemon status")
	}
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
	if engine != "podman" {
		return rootlessRefusal(engine, nil)
	}
	rep := checkEnforcerDaemon(ctx, enforcerd.SocketPath())
	if rep.Usable {
		r.enforcerSocket = rep.Socket
		r.debugf("rootless podman: eBPF LSM enforcement through the leash enforcer daemon at %s (daemon %s)", rep.Socket, rep.Status.Version)
		return nil
	}
	return rootlessRefusal(engine, &rep)
}

// enforcerDaemonArgs are the leash container's extra arguments for a run
// enforced through the daemon: the socket's directory, the caller's
// supplementary groups (the socket is group "leash", mode 0660; rootless
// podman drops host groups otherwise) and the socket path for leashd.
func (r *runner) enforcerDaemonArgs() []string {
	if r.enforcerSocket == "" {
		return nil
	}
	dir, base := filepath.Split(r.enforcerSocket)
	return []string{
		"-v", filepath.Clean(dir) + ":" + enforcerSocketDirInContainer,
		"--group-add", "keep-groups",
		"-e", enforcerd.EnvSocket + "=" + filepath.Join(enforcerSocketDirInContainer, base),
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
