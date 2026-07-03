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
	caCert := caCertPath(shareDir)
	// leashd clears the marker once at startup, then waits for it. StartEnforcement
	// spawned leashd asynchronously, so re-assert the marker on each poll to win
	// that race; stop once leashd publishes its CA cert (the readiness signal).
	for i := 0; i < caCertWaitAttempts; i++ {
		// leashd reads the marker as JSON metadata; write a valid object so it
		// doesn't log a parse error.
		_ = os.WriteFile(marker, []byte(`{"source":"native"}`+"\n"), 0o644)
		if _, err := os.Stat(caCert); err == nil {
			return nil
		}
		time.Sleep(caCertWaitDelay)
	}
	n.r.logger.Println("Warning: leash CA certificate was not detected after waiting (native).")
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

// workloadCommand builds the user's command to run inside the box: placed in
// the LSM-scoped cgroup, in workdir, via `shellBin -lc "exec <cmd>"`. When
// privileged it is wrapped in `nsenter --net=<ns>` so the workload also runs in
// the enforced network namespace (Layer 2); rootless (degraded/unenforced) it
// runs in the user-scope cgroup without a netns.
func (n nativeLauncher) workloadCommand(ctx context.Context, cgroupPath, workdir, shellBin, cmd string) *exec.Cmd {
	procs := quoteShellArg(filepath.Join(cgroupPath, "cgroup.procs"))
	inner := fmt.Sprintf("echo $$ > %s && cd %s && exec %s -lc %s",
		procs, quoteShellArg(workdir), quoteShellArg(shellBin), quoteShellArg("exec "+cmd))
	if !n.useUserManager() {
		return exec.CommandContext(ctx, "nsenter", "--net="+n.netnsRunPath(), "--", "sh", "-c", inner)
	}
	return exec.CommandContext(ctx, "sh", "-c", inner)
}

// hostOutput runs a host command (systemd-run/systemctl/ip), capturing combined
// output. Native uses host tooling directly, independent of the container
// Runtime command wrappers.
func hostOutput(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}
