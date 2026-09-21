package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/strongdm/leash/internal/leashd/listen"
	"golang.org/x/term"
)

// CA-cert readiness wait — extracted verbatim from the previous inline values in
// startContainers so behavior is unchanged.
const (
	caCertWaitAttempts = 50
	caCertWaitDelay    = 200 * time.Millisecond

	shellProbeDiagnosticLimit = 4 * 1024
	shellProbeDiagnosticLines = 3
	shellProbeWaitDelay       = time.Second
)

// containerShellProbeTimeout is deliberately independent for each candidate.
// A var keeps the timeout path fast and deterministic in unit tests.
var containerShellProbeTimeout = 5 * time.Second

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

	// DetectShell returns the shell to run the workload with (container: probed
	// inside the container; native: the host shell).
	DetectShell(ctx context.Context) (string, error)
	// ExecCommand builds the command that runs `shellBin -lc "exec cmd"` inside
	// the enforced box. The runner runs it and handles the exit code, so the exec
	// UX stays backend-agnostic. interactive requests a TTY.
	ExecCommand(ctx context.Context, shellBin, cmd string, interactive bool) *exec.Cmd
	// Precheck validates the interactive exec path before starting a session
	// (container: catches Docker-Desktop setns issues; native: no-op).
	Precheck(ctx context.Context, shellBin, cmd string) error
	// InstallPromptAssets installs the leash shell prompt (container: into the
	// container filesystem; native: no-op — the workload runs on the host).
	InstallPromptAssets(ctx context.Context) error

	// Preflight validates the backend can run before anything is provisioned
	// (native: Linux + systemd + root; container: nil).
	Preflight() error
	// RequiredCommands lists host binaries that must be on PATH (container: the
	// runtime binary; native: systemd-run + systemctl).
	RequiredCommands() []string
	// EnsureNotRunning fails/cleans up if a prior session is still present
	// (container: inspects/removes the containers; native: no-op — Provision
	// clears any stale box).
	EnsureNotRunning(ctx context.Context) error
	// AssignNames resolves the workload/leash identity from the base names
	// (container: probes the registry to avoid collisions; native: uses the base
	// names directly — the box is a systemd unit).
	AssignNames(ctx context.Context, baseTarget, baseLeash string) error
	// StopSignal is the signal used to stop the workload (container: the image's
	// StopSignal; native: SIGTERM — the holder is stopped via systemctl).
	StopSignal(ctx context.Context) (string, error)
	// PublishesPorts reports whether the backend maps host↔container ports.
	// Native runs on the host and has none.
	PublishesPorts() bool
	// ControlUIURL is the reachable Control-UI URL for this backend (container:
	// localhost:published-port; native Layer 2: the netns IP, since leashd runs
	// inside the workload's netns; native LSM-only: localhost).
	ControlUIURL(cfg listen.Config) string
}

// launcher returns the configured backend launcher, selected by the runtime:
// the container-free nativeLauncher for --runtime native, else the container
// launcher (the default, so runners constructed directly in tests work without
// wiring). This mirrors r.rt().
func (r *runner) launcher() launcher {
	if r.usingNativeRuntime() {
		return nativeLauncher{r: r}
	}
	return containerLauncher{r: r}
}

// usingNativeRuntime reports whether the container-free native backend is
// selected. Backend-agnostic orchestration in startContainers uses this to skip
// the container-CLI–specific steps (image/name/ps probing) that have no native
// equivalent, so a native run reaches the launcher.
func (r *runner) usingNativeRuntime() bool {
	_, ok := r.rt().(nativeRuntime)
	return ok
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
	if err := c.r.ensureLocalImage(ctx, c.r.cfg.leashImage); err != nil {
		return err
	}
	// Validate the privileged manager immediately after it is available and
	// before Provision can create or bootstrap the target container.
	return c.r.validateManagerImage(ctx)
}

func (c containerLauncher) Provision(ctx context.Context, stopSignal string) (string, error) {
	// Capture the image's workload identity before replacing its entrypoint and
	// temporarily starting that bootstrap process as root.
	if err := c.r.captureTargetContainerUser(ctx); err != nil {
		return "", err
	}
	// Spawn the --inject-service plugins exactly once, before the launch retry loop
	// (a port-conflict retry re-runs launchTargetContainer, which must not respawn
	// them). Fail-closed: abort the run if any plugin can't start. The resulting
	// r.injectedDockerArgs are appended to each target-container launch.
	if err := c.r.spawnInjectServicesContainer(ctx); err != nil {
		return "", err
	}
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
	if err := c.r.prepareIDMapVolumes(ctx); err != nil {
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
	return c.r.waitForEnforcementReady(ctx)
}

func (c containerLauncher) Remove(ctx context.Context) {
	// Stop any injected plugins and remove their sockets/config files before the
	// containers (mirrors native teardown).
	c.r.teardownInjectedPlugins()
	c.r.removeContainer(ctx, c.r.cfg.leashContainer)
	c.r.removeContainer(ctx, c.r.cfg.targetContainer)
}

func (c containerLauncher) DetectShell(ctx context.Context) (string, error) {
	var failures []string
	for _, shellBin := range []string{"bash", "sh"} {
		if err := c.probeShell(ctx, shellBin, false); err == nil {
			if cancelErr := ctx.Err(); cancelErr != nil {
				return "", fmt.Errorf("detect shell in %s: %w", c.r.cfg.targetContainer, cancelErr)
			}
			return shellBin, nil
		} else {
			// Parent cancellation is terminal. In particular, do not mistake
			// its inherited deadline for a candidate-local timeout and try the
			// fallback shell.
			if ctx.Err() != nil {
				return "", err
			}
			failures = append(failures, err.Error())
			// Killing the runtime client does not guarantee that a timed-out
			// docker exec process has stopped server-side. Do not overlap a
			// fallback probe with it; return so normal lifecycle cleanup removes
			// the disposable container and terminates the exec.
			if errors.Is(err, context.DeadlineExceeded) {
				return "", fmt.Errorf("failed to locate a usable shell inside %s: %w", c.r.cfg.targetContainer, err)
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("detect shell in %s: %w", c.r.cfg.targetContainer, err)
	}
	return "", fmt.Errorf("failed to locate a usable shell inside %s: %s", c.r.cfg.targetContainer, strings.Join(failures, "; "))
}

// probeShell validates a shell without reading login profiles. Each call owns
// its timeout, so one hung candidate cannot consume the fallback's budget.
// interactive preserves the existing TTY precheck path while sharing the same
// bounded stderr and cancellation behavior as detection.
func (c containerLauncher) probeShell(ctx context.Context, shellBin string, interactive bool) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%s shell probe in %s canceled: %w", shellBin, c.r.cfg.targetContainer, err)
	}

	probeCtx, cancel := context.WithTimeout(ctx, containerShellProbeTimeout)
	defer cancel()
	ioFlag := ""
	if interactive {
		ioFlag = "-it"
	}
	shellArgs := []string{"-c", "true"}
	if shellBin == "bash" {
		shellArgs = []string{"--noprofile", "--norc", "-c", "true"}
	}
	cmd := c.r.rt().Cmd(probeCtx, c.r.targetWorkloadProbeArgs(ioFlag, append([]string{shellBin}, shellArgs...)...)...)
	if interactive {
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
	} else {
		cmd.Stdout = io.Discard
	}
	var stderr cappedProbeOutput
	cmd.Stderr = &stderr
	// A runtime CLI may leave a helper holding its stderr descriptor. Keep
	// cancellation bounded even in that case.
	cmd.WaitDelay = shellProbeWaitDelay
	runErr := cmd.Run()
	probeErr := probeCtx.Err()
	if runErr == nil {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("%s shell probe in %s canceled: %w", shellBin, c.r.cfg.targetContainer, err)
		}
		return nil
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%s shell probe in %s canceled: %w", shellBin, c.r.cfg.targetContainer, err)
	}
	if errors.Is(probeErr, context.DeadlineExceeded) {
		return fmt.Errorf("%s timed out after %s: %w", shellBin, containerShellProbeTimeout, context.DeadlineExceeded)
	}

	detail := firstLines(stderr.String(), shellProbeDiagnosticLines)
	if stderr.truncated {
		if detail != "" {
			detail += " "
		}
		detail += "[stderr truncated]"
	}
	if detail == "" {
		detail = runErr.Error()
	}
	return fmt.Errorf("%s failed: %s", shellBin, detail)
}

// cappedProbeOutput keeps a runtime failure useful without letting a noisy
// engine grow the launcher's memory use or final error without bound.
type cappedProbeOutput struct {
	data      []byte
	truncated bool
}

func (w *cappedProbeOutput) Write(p []byte) (int, error) {
	written := len(p)
	remaining := shellProbeDiagnosticLimit - len(w.data)
	if remaining <= 0 {
		w.truncated = w.truncated || len(p) > 0
		return written, nil
	}
	if len(p) > remaining {
		w.data = append(w.data, p[:remaining]...)
		w.truncated = true
		return written, nil
	}
	w.data = append(w.data, p...)
	return written, nil
}

func (w *cappedProbeOutput) String() string { return string(w.data) }

func (c containerLauncher) ExecCommand(ctx context.Context, shellBin, cmd string, interactive bool) *exec.Cmd {
	return c.execCommandWithStdinKind(ctx, shellBin, cmd, interactive, containerStdinIsTerminal(os.Stdin))
}

func containerStdinIsTerminal(stdin *os.File) bool {
	return stdin != nil && term.IsTerminal(int(stdin.Fd()))
}

func (c containerLauncher) execCommandWithStdinKind(ctx context.Context, shellBin, cmd string, interactive, stdinIsTerminal bool) *exec.Cmd {
	flag := "-i"
	if interactive {
		flag = "-it"
	} else if stdinIsTerminal {
		// A non-interactive command running on the left side of a pipeline may
		// belong to a background process group while still inheriting the
		// controlling terminal. Asking Docker to read it would stop the process
		// group with SIGTTIN. Pipes and redirected files retain -i below.
		flag = ""
	}
	return c.r.rt().Cmd(ctx, c.r.targetWorkloadExecArgs(flag, shellBin, "-lc", "exec "+cmd)...)
}

func (c containerLauncher) Precheck(ctx context.Context, shellBin, cmd string) error {
	if err := c.probeShell(ctx, shellBin, true); err != nil {
		fmt.Fprintln(os.Stderr, "Interactive docker exec precheck failed; stopping containers.")
		fmt.Fprintln(os.Stderr, err)
		return fmt.Errorf("docker exec precheck failed: %w", err)
	}
	return nil
}

func (c containerLauncher) InstallPromptAssets(ctx context.Context) error {
	// System-wide prompt hooks are optional decoration. A non-root image user
	// cannot maintain them, and attempting the writes after enforcement is live
	// produces policy denials that obscure the workload startup result.
	if !c.r.targetWorkloadIsRoot() {
		c.r.debugf("skipping system prompt installation for non-root target user %q", c.r.targetWorkloadUser())
		return nil
	}
	return c.r.installPromptAssetsContainer(ctx)
}

func (c containerLauncher) Preflight() error { return c.r.validateIDMapVolumes() }

func (c containerLauncher) RequiredCommands() []string { return []string{c.r.rt().Name()} }

func (c containerLauncher) EnsureNotRunning(ctx context.Context) error {
	return c.r.ensureNotRunningContainer(ctx)
}

func (c containerLauncher) AssignNames(ctx context.Context, baseTarget, baseLeash string) error {
	return c.r.assignContainerNamesContainer(ctx, baseTarget, baseLeash)
}

func (c containerLauncher) StopSignal(ctx context.Context) (string, error) {
	return c.r.getImageStopSignalContainer(ctx)
}

func (c containerLauncher) PublishesPorts() bool { return true }

// ControlUIURL: the container publishes the UI port to the host, so the standard
// localhost URL is reachable.
func (c containerLauncher) ControlUIURL(cfg listen.Config) string { return cfg.DisplayURL() }
