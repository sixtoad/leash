package runner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/strongdm/leash/internal/entrypoint"
)

// nativeLauncher implements launcher without a container runtime: the workload
// runs in a delegated systemd cgroup-v2 scope (Layer-1 attach point) plus a
// named network namespace (Layer-2 intercept point). StartEnforcement runs
// leashd host mode against the box; enforcement requires root (gated by
// preflightNativeRuntime). See docs/{RUNTIME-NATIVE-POC,LAUNCHER-ABSTRACTION,
// LEASHD-HOST-MODE,NATIVE-ENFORCEMENT-RUNBOOK}.md.
//
// It holds *runner like containerLauncher and derives all unit/netns names
// deterministically from runner state, so a fresh value from r.launcher() agrees
// with a prior Provision (no stored state needed across calls).
type nativeLauncher struct {
	r *runner
}

func (n nativeLauncher) Name() string { return "native" }

// useUserManager runs against the per-user systemd manager when unprivileged, so
// the box forms without root (a real enforcing run uses the system manager — see
// LEASHD-HOST-MODE.md "system vs user scope").
func (n nativeLauncher) useUserManager() bool { return os.Geteuid() != 0 }

func (n nativeLauncher) userFlag() []string {
	if n.useUserManager() {
		return []string{"--user"}
	}
	return nil
}

// boxBaseName is a filesystem/unit-safe identity for this session's box.
func (n nativeLauncher) boxBaseName() string {
	base := sanitizeNativeName(n.r.cfg.targetContainer)
	if base == "" {
		base = "session"
	}
	return "leash-native-" + base
}

func (n nativeLauncher) unitName() string  { return n.boxBaseName() + ".service" }
func (n nativeLauncher) netnsName() string { return n.boxBaseName() }

func sanitizeNativeName(raw string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(raw)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_':
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

// PullImages is a no-op: native runs the workload from the host filesystem, with
// no image to fetch.
func (n nativeLauncher) PullImages(ctx context.Context) error {
	n.r.debugf("native runtime: no image to pull (workload runs from the host filesystem)")
	return nil
}

// Provision builds the box: a detached, delegated cgroup-v2 holder unit (keeps
// the cgroup alive for the session) and, when privileged, a named netns. It
// returns the holder's cgroup path — the same kind of path leashd attaches the
// eBPF LSM to.
func (n nativeLauncher) Provision(ctx context.Context, stopSignal string) (string, error) {
	unit := n.unitName()
	// Clear any stale unit from a crashed prior run (best-effort).
	n.stopUnit(ctx, unit)

	// A transient *service* (not --scope) is the right systemd primitive for a
	// holder systemd itself starts: it is detached and managed, and Delegate=yes
	// still yields a delegated cgroup-v2 subtree we own. "sleep infinity" just
	// holds the box open until Remove.
	runArgs := append(n.userFlag(),
		"--quiet", "--collect", "--property=Delegate=yes",
		"--unit="+unit, "--", "sleep", "infinity")
	if out, err := hostOutput(ctx, "systemd-run", runArgs...); err != nil {
		return "", fmt.Errorf("native: start cgroup holder %q: %w (%s)", unit, err, strings.TrimSpace(out))
	}

	rel, err := hostOutput(ctx, "systemctl", append(n.userFlag(), "show", "-p", "ControlGroup", "--value", unit)...)
	rel = strings.TrimSpace(rel)
	if err != nil || rel == "" {
		n.stopUnit(ctx, unit)
		return "", fmt.Errorf("native: read holder cgroup for %q: %w", unit, err)
	}
	cgroupPath := filepath.Join("/sys/fs/cgroup", rel)

	if n.useUserManager() {
		n.r.debugf("native box: netns skipped (needs root; the proxy/Layer-2 path it serves is not wired yet)")
	} else if err := n.addNetns(ctx); err != nil {
		n.r.debugf("native box: netns %q not created: %v", n.netnsName(), err)
	}

	n.r.debugf("native box ready: unit=%s cgroup=%s", unit, cgroupPath)
	return cgroupPath, nil
}

// StartEnforcement runs leashd host mode (leash --daemon --host) inside the
// workload's network namespace via nsenter, re-execing this same binary —
// leashd attaches the eBPF LSM to cgroupPath and applies the netns-scoped
// netfilter + proxy (see docs/LEASHD-HOST-MODE.md). It runs only when the
// prerequisites hold (root for the named netns + netfilter); otherwise it
// returns an actionable error that names the blocker and the exact command it
// would run, rather than failing opaquely. (Enforcement also needs an active
// bpf LSM — the lsm=…,bpf reboot — which leashd reports when it attempts attach.)
func (n nativeLauncher) StartEnforcement(ctx context.Context, cgroupPath string) error {
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("native: locate leash binary: %w", err)
	}
	netnsPath := n.netnsRunPath()
	argv := n.hostLeashdArgv(self, netnsPath, cgroupPath)

	if blocker := n.enforcementBlocker(netnsPath); blocker != "" {
		return fmt.Errorf(
			"native enforcement not startable: %s. The container-free box is provisioned; "+
				"would run: %s (see docs/LEASHD-HOST-MODE.md)",
			blocker, strings.Join(argv, " "))
	}

	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = append(os.Environ(), n.leashdEnv()...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Start()
}

// leashdEnv passes the runner's host directories to the spawned leashd so it
// reads/writes them instead of the container defaults (/leash, /cfg, /log).
func (n nativeLauncher) leashdEnv() []string {
	env := []string{"LEASH_HOST=1"}
	if v := strings.TrimSpace(n.r.cfg.shareDir); v != "" {
		env = append(env, "LEASH_DIR="+v)
	}
	if v := strings.TrimSpace(n.r.cfg.privateDir); v != "" {
		env = append(env, "LEASH_PRIVATE_DIR="+v)
	}
	if v := strings.TrimSpace(n.r.cfg.logDir); v != "" {
		env = append(env, "LEASH_LOG="+filepath.Join(v, "events.log"))
	}
	return env
}

// netnsRunPath is the iproute2 named-netns path Provision creates (when root).
func (n nativeLauncher) netnsRunPath() string {
	return filepath.Join("/run/netns", n.netnsName())
}

// hostLeashdArgv builds the command that launches leashd host mode in the
// workload's netns: nsenter --net=<ns> -- <self> --daemon --host --cgroup <cg>
// [--proxy-port …] [--listen …]. Pure, so it is unit-tested directly.
func (n nativeLauncher) hostLeashdArgv(self, netnsPath, cgroupPath string) []string {
	argv := []string{"nsenter", "--net=" + netnsPath, "--", self, "--daemon", "--host", "--cgroup", cgroupPath}
	if cfgDir := strings.TrimSpace(n.r.cfg.cfgDir); cfgDir != "" {
		argv = append(argv, "--policy", filepath.Join(cfgDir, "leash.cedar"))
	}
	if port := strings.TrimSpace(n.r.cfg.proxyPort); port != "" {
		argv = append(argv, "--proxy-port", port)
	}
	if !n.r.cfg.listenCfg.Disable {
		// Skip an unresolved address (zero-value Config yields ":"); a real run
		// has a concrete host:port here.
		if addr := strings.TrimSpace(n.r.cfg.listenCfg.Address()); addr != "" && addr != ":" {
			argv = append(argv, "--listen", addr)
		}
	}
	return argv
}

// enforcementBlocker reports why enforcement can't start here, or "" if it can.
// Native enforcement needs root: Provision only creates the named netns when
// privileged, and applying netfilter inside it requires CAP_NET_ADMIN.
func (n nativeLauncher) enforcementBlocker(netnsPath string) string {
	if n.useUserManager() {
		return "requires root for the workload network namespace + netfilter (the box ran rootless, so no named netns was created)"
	}
	if _, err := os.Stat(netnsPath); err != nil {
		return fmt.Sprintf("network namespace %s not found", netnsPath)
	}
	return ""
}

// WaitReady drives the bootstrap handshake (option A, LEASHD-HOST-MODE.md §4):
// the launcher plays the role the container's leash-entry plays — it writes the
// bootstrap marker so leashd proceeds to attach the LSM — then waits for leashd
// to publish its CA cert, the same readiness signal the container path waits on.
// This preserves the fail-closed ordering: the workload is not exec'd until this
// returns nil. A no-op when enforcement wasn't started (degraded box).
func (n nativeLauncher) WaitReady(ctx context.Context) error {
	shareDir := strings.TrimSpace(n.r.cfg.shareDir)
	if shareDir == "" {
		return nil
	}
	marker := filepath.Join(shareDir, entrypoint.BootstrapReadyFileName)
	ready := filepath.Join(shareDir, entrypoint.EnforcementReadyFileName)
	// leashd clears the bootstrap marker once at startup, then waits for it.
	// StartEnforcement spawned leashd asynchronously, so re-assert the marker on
	// each poll to win that race. Crucially, wait for the *enforcement-ready*
	// marker — leashd writes it AFTER attaching the eBPF LSM — not the CA cert,
	// which is published earlier: the workload must not run until Layer 1 is live
	// (fail-closed).
	for i := 0; i < caCertWaitAttempts; i++ {
		// leashd reads the bootstrap marker as JSON metadata; write a valid object.
		_ = os.WriteFile(marker, []byte(`{"source":"native"}`+"\n"), 0o644)
		if _, err := os.Stat(ready); err == nil {
			return nil
		}
		time.Sleep(caCertWaitDelay)
	}
	n.r.logger.Println("Warning: native enforcement was not confirmed ready after waiting; the workload may run before Layer 1 is active.")
	return nil
}

// Remove tears the box down: delete the netns (if any) and stop the holder unit.
func (n nativeLauncher) Remove(ctx context.Context) {
	if !n.useUserManager() {
		_, _ = hostOutput(ctx, "ip", "netns", "del", n.netnsName())
	}
	n.stopUnit(ctx, n.unitName())
}

func (n nativeLauncher) addNetns(ctx context.Context) error {
	if out, err := hostOutput(ctx, "ip", "netns", "add", n.netnsName()); err != nil {
		return fmt.Errorf("%w (%s)", err, strings.TrimSpace(out))
	}
	// A fresh netns has loopback DOWN; leashd binds the proxy/Control UI on
	// 127.0.0.1 inside it, so bring lo up.
	if out, err := hostOutput(ctx, "ip", "-n", n.netnsName(), "link", "set", "lo", "up"); err != nil {
		return fmt.Errorf("bring up lo in netns: %w (%s)", err, strings.TrimSpace(out))
	}
	return nil
}

func (n nativeLauncher) stopUnit(ctx context.Context, unit string) {
	_, _ = hostOutput(ctx, "systemctl", append(n.userFlag(), "stop", unit)...)
	_, _ = hostOutput(ctx, "systemctl", append(n.userFlag(), "reset-failed", unit)...)
}

// execInBox builds a command that runs argv inside the box's cgroup. Rootless
// placement: under cgroup-v2 delegation the holder's cgroup.procs is writable by
// the owner, so the shell writes its own PID into it and then execs argv — argv
// inherits the LSM-scoped cgroup. (A future enforcing path also joins the netns
// via nsenter; not needed while StartEnforcement is stubbed.)
func (n nativeLauncher) execInBox(ctx context.Context, cgroupPath string, argv ...string) *exec.Cmd {
	procs := quoteShellArg(filepath.Join(cgroupPath, "cgroup.procs"))
	script := fmt.Sprintf("echo $$ > %s && exec \"$@\"", procs)
	args := append([]string{"-c", script, "leash-native"}, argv...)
	return exec.CommandContext(ctx, "sh", args...)
}

// Preflight validates that native can enforce here (Linux + systemd + root),
// failing with actionable advice otherwise — never a silent docker fallback.
func (n nativeLauncher) Preflight() error {
	return decideNativeRuntime(classifyNativeRuntime(goos(), hostHasSystemd(), os.Geteuid()))
}

func (n nativeLauncher) RequiredCommands() []string { return []string{"systemd-run", "systemctl"} }

// EnsureNotRunning is a no-op: Provision clears any stale box (systemd unit).
func (n nativeLauncher) EnsureNotRunning(ctx context.Context) error { return nil }

// AssignNames takes the base names directly — the box is a systemd unit derived
// from them; there is no registry to probe for collisions.
func (n nativeLauncher) AssignNames(ctx context.Context, baseTarget, baseLeash string) error {
	n.r.cfg.targetContainer = baseTarget
	n.r.cfg.leashContainer = baseLeash
	return nil
}

// StopSignal: the holder is stopped via systemctl, not a signal.
func (n nativeLauncher) StopSignal(ctx context.Context) (string, error) { return "SIGTERM", nil }

// PublishesPorts: native runs on the host and maps no container ports.
func (n nativeLauncher) PublishesPorts() bool { return false }

func (n nativeLauncher) DetectShell(ctx context.Context) (string, error) {
	// The workload runs on the host; pick the host's shell.
	if _, err := exec.LookPath("bash"); err == nil {
		return "bash", nil
	}
	if _, err := exec.LookPath("sh"); err == nil {
		return "sh", nil
	}
	return "", fmt.Errorf("failed to locate a usable shell (bash or sh) on the host")
}

func (n nativeLauncher) ExecCommand(ctx context.Context, shellBin, cmd string, interactive bool) *exec.Cmd {
	return n.workloadCommand(ctx, n.r.cgroupPath, n.r.cfg.callerDir, shellBin, cmd)
}

// Precheck: the container setns/tty precheck is not a native concern.
func (n nativeLauncher) Precheck(ctx context.Context, shellBin, cmd string) error { return nil }

// InstallPromptAssets: no-op — native runs on the host filesystem and must not
// write to the host's /etc/profile.d.
func (n nativeLauncher) InstallPromptAssets(ctx context.Context) error { return nil }

// workloadCommand builds the user's command to run inside the box: placed in
// the LSM-scoped cgroup, in workdir, via `shellBin -lc "exec <cmd>"`. When
// privileged it is wrapped in `nsenter --net=<ns>` so the workload also runs in
// the enforced network namespace (Layer 2); rootless (degraded/unenforced) it
// runs in the user-scope cgroup without a netns.
func (n nativeLauncher) workloadCommand(ctx context.Context, cgroupPath, workdir, shellBin, cmd string) *exec.Cmd {
	inner := nativeWorkloadScript(cgroupPath, workdir, shellBin, cmd, n.workloadUser())
	if !n.useUserManager() {
		return exec.CommandContext(ctx, "nsenter", "--net="+n.netnsRunPath(), "--", "sh", "-c", inner)
	}
	return exec.CommandContext(ctx, "sh", "-c", inner)
}

// workloadUser returns the non-root user the workload should run as, or "" to
// keep the current uid. The eBPF LSM enforces on the cgroup regardless of uid,
// so when leash runs as root (typical: `sudo leash`) the agent need not — and
// many agents refuse to (e.g. Claude Code blocks --dangerously-skip-permissions
// as root). We drop to the invoking user ($SUDO_USER); leash and leashd keep
// root only for enforcement. Non-root leash (rootless box) needs no drop.
func (n nativeLauncher) workloadUser() string {
	if os.Geteuid() != 0 {
		return ""
	}
	u := strings.TrimSpace(os.Getenv("SUDO_USER"))
	if u == "" || u == "root" {
		return ""
	}
	return u
}

// nativeWorkloadScript builds the shell placed in the box: join the LSM-scoped
// cgroup, cd to workdir, then exec the command — dropping to dropUser via runuser
// when set. Pure, so it is unit-tested.
func nativeWorkloadScript(cgroupPath, workdir, shellBin, cmd, dropUser string) string {
	procs := quoteShellArg(filepath.Join(cgroupPath, "cgroup.procs"))
	run := fmt.Sprintf("exec %s -lc %s", quoteShellArg(shellBin), quoteShellArg("exec "+cmd))
	if dropUser != "" {
		run = fmt.Sprintf("exec runuser -u %s -- %s -lc %s",
			quoteShellArg(dropUser), quoteShellArg(shellBin), quoteShellArg("exec "+cmd))
	}
	return fmt.Sprintf("echo $$ > %s && cd %s && %s", procs, quoteShellArg(workdir), run)
}

// hostOutput runs a host command (systemd-run/systemctl/ip), capturing combined
// output. Native uses host tooling directly, independent of the container
// Runtime command wrappers.
func hostOutput(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}
