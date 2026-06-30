package runner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// nativeLauncher implements launcher without a container runtime: the workload
// runs in a delegated systemd cgroup-v2 scope (Layer-1 attach point) plus, when
// privileged, a named network namespace (Layer-2 intercept point). It proves the
// box is Docker-free and is fully runnable here; enforcement (StartEnforcement)
// is stubbed pending leashd host mode. See docs/{RUNTIME-NATIVE-POC,
// LAUNCHER-ABSTRACTION,LEASHD-HOST-MODE}.md.
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
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Start()
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

// WaitReady has nothing to wait on until leashd host mode provides a readiness
// signal (LEASHD-HOST-MODE.md §4).
func (n nativeLauncher) WaitReady(ctx context.Context) error { return nil }

// Remove tears the box down: delete the netns (if any) and stop the holder unit.
func (n nativeLauncher) Remove(ctx context.Context) {
	if !n.useUserManager() {
		_, _ = hostOutput(ctx, "ip", "netns", "del", n.netnsName())
	}
	n.stopUnit(ctx, n.unitName())
}

func (n nativeLauncher) addNetns(ctx context.Context) error {
	_, err := hostOutput(ctx, "ip", "netns", "add", n.netnsName())
	return err
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

// hostOutput runs a host command (systemd-run/systemctl/ip), capturing combined
// output. Native uses host tooling directly, independent of the container
// Runtime command wrappers.
func hostOutput(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}
