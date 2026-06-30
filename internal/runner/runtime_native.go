package runner

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// nativeRuntime is a proof-of-concept Runtime backend that runs the workload
// directly on the host — no container image, no container runtime — inside a
// transient, delegated cgroup-v2 scope created by systemd-run. It exists to
// prove that leash's enforcement *box* (the cgroup that Layer 1's eBPF LSM
// attaches to, plus a network namespace the Layer 2 proxy intercepts in) does
// not actually require Docker: only kernel primitives that exist on any modern
// Linux host.
//
// What this backend demonstrates against the seam:
//
//   - Cmd() wraps a command in `systemd-run --scope --property=Delegate=yes`,
//     yielding a process inside its own delegated cgroup. That cgroup path is
//     exactly what leashd would hand to link.AttachLSM — see the runnable
//     end-to-end proof in scratch-native-poc/.
//
// Where the Runtime seam LEAKS (the honest finding of this PoC):
//
//   - Run/Output/ExecWithInput are container-CLI verbs (run/pull/inspect/ps,
//     `exec <container>`). Native mode has no container daemon to drive and no
//     container object to address, so these return errNativeNotWired naming the
//     verb. The current launch path in runner.go (launchTargetContainer +
//     launchLeashContainer do `docker run <image>` and `--network container:…`)
//     calls these, so `--runtime native` fails *clearly, at exactly the call
//     sites that assume a container*. Wiring a real native path means leashd
//     runs as a privileged host process (not a sibling container) attaching the
//     eBPF LSM to the scope's cgroup and running the proxy in a shared netns —
//     i.e. a launch path above the Runtime interface, not just a new Runtime.
//
// In other words: the seam cleanly accepts a non-cliRuntime backend (this type
// is proof), but a production native backend needs a launcher abstraction wider
// than the container-CLI-shaped Runtime. Captured in docs and the briefing.
type nativeRuntime struct {
	// systemdRun is the systemd-run binary (overridable for tests).
	systemdRun string
	// userScope runs the scope under the calling user's systemd manager
	// (--user) instead of the system manager. The PoC defaults to a user scope
	// because it needs no root to demonstrate the cgroup; a real enforcing run
	// uses a system scope so leashd (with CAP_BPF) and the workload share a
	// host-visible cgroup path.
	userScope bool
	// extraProps are additional `--property=…` settings appended to the scope.
	extraProps []string
}

// newNativeRuntime builds the PoC native backend with safe defaults.
func newNativeRuntime() nativeRuntime {
	return nativeRuntime{systemdRun: "systemd-run", userScope: true}
}

func (n nativeRuntime) Name() string { return "native" }

// scopeArgs builds the systemd-run argv that wraps command (name + args) in a
// transient, delegated cgroup-v2 scope. Pure and unit-tested; this is the one
// Runtime method that maps cleanly onto the native model.
func (n nativeRuntime) scopeArgs(command ...string) []string {
	args := []string{"--scope", "--quiet", "--collect", "--property=Delegate=yes"}
	if n.userScope {
		args = append([]string{"--user"}, args...)
	}
	for _, p := range n.extraProps {
		args = append(args, "--property="+strings.TrimPrefix(p, "--property="))
	}
	args = append(args, "--")
	return append(args, command...)
}

// Cmd builds the workload command, wrapped in a delegated scope. This is the
// native analog of "run the agent" — the resulting process lives in its own
// cgroup with no container in sight.
func (n nativeRuntime) Cmd(ctx context.Context, args ...string) *exec.Cmd {
	full := n.scopeArgs(args...)
	cmd := exec.CommandContext(ctx, n.systemdRun, full...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd
}

// errNativeNotWired is returned by the container-CLI verbs that have no native
// equivalent. It names the offending verb so the failure points precisely at a
// container-centric assumption in the launch path.
func errNativeNotWired(verb string, args []string) error {
	return fmt.Errorf(
		"native runtime (PoC): container verb %q is not wired — native mode has no container daemon or image to drive (args: %s); "+
			"the box primitive works, but the launch path in runner.go still assumes a container. "+
			"Run with --runtime docker|podman, or see docs/RUNTIME-NATIVE-POC.md",
		verb, strings.Join(args, " "))
}

func verbOf(args []string) string {
	if len(args) == 0 {
		return "(empty)"
	}
	return args[0]
}

func (n nativeRuntime) Run(ctx context.Context, args ...string) error {
	return errNativeNotWired(verbOf(args), args)
}

func (n nativeRuntime) Output(ctx context.Context, args ...string) (string, error) {
	return "", errNativeNotWired(verbOf(args), args)
}

func (n nativeRuntime) ExecWithInput(ctx context.Context, container, shellCommand string, input io.Reader) error {
	_ = input
	return errNativeNotWired("exec", []string{container, shellCommand})
}
