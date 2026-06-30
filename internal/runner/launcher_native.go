package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// errHostModeNotBuilt is returned by nativeLauncher.StartEnforcement. The box
// lifecycle below is real and runnable, but the enforcement engine it would
// attach (leashd --host: eBPF LSM + proxy on a host process) is specified, not
// yet implemented — see docs/LEASHD-HOST-MODE.md.
var errHostModeNotBuilt = errors.New(
	"native runtime: the container-free box is provisioned, but enforcement is not wired yet — " +
		"leashd host mode (leash --daemon --host) is specified in docs/LEASHD-HOST-MODE.md but not built. " +
		"Use --runtime docker|podman for an enforced run.")

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

// StartEnforcement is intentionally unimplemented: see errHostModeNotBuilt.
func (n nativeLauncher) StartEnforcement(ctx context.Context, cgroupPath string) error {
	return errHostModeNotBuilt
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
