package runner

import (
	"context"
	"io"
	"path/filepath"
	"time"
)

// CA-cert readiness wait — extracted verbatim from the previous inline values in
// startContainers so behavior is unchanged.
const (
	caCertWaitAttempts = 50
	caCertWaitDelay    = 200 * time.Millisecond
)

// caCertPath is where leash writes the MITM CA cert in the shared dir.
func caCertPath(shareDir string) string { return filepath.Join(shareDir, "ca-cert.pem") }

// removeContainer force-removes a container, discarding output — the teardown
// primitive shared by Remove and stopContainers.
func (r *runner) removeContainer(ctx context.Context, name string) {
	cmd := r.rt().Cmd(ctx, "rm", "-f", name)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	_ = cmd.Run()
}

// launcher owns the backend-specific enforcement-session lifecycle: stand up the
// box (workload + cgroup), attach enforcement, wait for it to be live, and tear
// it down. Everything backend-agnostic (naming, ports, dirs, policy sync, the
// exec UX) stays in the runner. This is the seam a non-container backend plugs
// into — see docs/LAUNCHER-ABSTRACTION.md.
//
// Step 1 (this change) introduces the seam with a single implementation,
// containerLauncher, that delegates 1:1 to the existing runner methods, so
// docker/podman behavior is unchanged. A nativeLauncher (systemd scope + host
// leashd) implements the same interface in a later step; r.launcher() is where
// selection by runtime happens.
type launcher interface {
	// Name reports the backend identity (for logs/errors).
	Name() string
	// PullImages ensures any images the backend needs are present locally.
	// Container backends pull the target and leash images; image-less backends
	// (native) no-op.
	PullImages(ctx context.Context) error
	// Provision starts the workload and returns the cgroup path that enforcement
	// (Layer 1) will attach to. It owns any launch-time retry (e.g. listen-port
	// conflicts).
	Provision(ctx context.Context, stopSignal string) (cgroupPath string, err error)
	// StartEnforcement attaches leash (eBPF LSM + proxy) to the provisioned box.
	StartEnforcement(ctx context.Context, cgroupPath string) error
	// WaitReady blocks until enforcement is live — the fail-closed gate. The
	// workload must not run until this returns nil.
	WaitReady(ctx context.Context) error
	// Remove stops and reclaims the workload + enforcement. Backend-agnostic
	// filesystem cleanup remains the runner's responsibility.
	Remove(ctx context.Context)
}

// launcher returns the configured backend launcher, selected by the runtime:
// the container-free nativeLauncher for --runtime native, else the container
// launcher (the default, so runners constructed directly in tests work without
// wiring). This mirrors r.rt().
func (r *runner) launcher() launcher {
	if _, ok := r.rt().(nativeRuntime); ok {
		return nativeLauncher{r: r}
	}
	return containerLauncher{r: r}
}

// containerLauncher implements launcher for docker/podman by delegating to the
// runner's existing container methods. It is a pure extraction — no behavior
// change — driving whatever Runtime r.rt() resolves to.
type containerLauncher struct {
	r *runner
}

func (c containerLauncher) Name() string { return c.r.rt().Name() }

func (c containerLauncher) PullImages(ctx context.Context) error {
	if err := c.r.ensureLocalImage(ctx, c.r.cfg.targetImage); err != nil {
		return err
	}
	return c.r.ensureLocalImage(ctx, c.r.cfg.leashImage)
}

func (c containerLauncher) Provision(ctx context.Context, stopSignal string) (string, error) {
	for {
		err := c.r.launchTargetContainer(ctx, stopSignal)
		if err == nil {
			break
		}
		retry, retryErr := c.r.handleListenPortRetry(ctx, err)
		if retryErr != nil {
			return "", retryErr
		}
		if retry {
			continue
		}
		return "", err
	}
	return c.r.resolveCgroupPath()
}

func (c containerLauncher) StartEnforcement(ctx context.Context, cgroupPath string) error {
	return c.r.launchLeashContainer(ctx, cgroupPath)
}

func (c containerLauncher) WaitReady(ctx context.Context) error {
	caCert := caCertPath(c.r.cfg.shareDir)
	if err := c.r.waitForFile(caCert, caCertWaitAttempts, caCertWaitDelay); err != nil {
		c.r.logger.Println("Warning: Leash CA certificate was not detected after waiting.")
	} else if c.r.verbose {
		c.r.logger.Printf("Leash CA certificate is available at %s\n", caCert)
	}
	return c.r.waitForBootstrap(ctx)
}

func (c containerLauncher) Remove(ctx context.Context) {
	c.r.removeContainer(ctx, c.r.cfg.leashContainer)
	c.r.removeContainer(ctx, c.r.cfg.targetContainer)
}
