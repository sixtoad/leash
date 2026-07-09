package runner

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// goos reports the target OS; a package var so runtime-selection logic is
// unit-testable without a build matrix.
var goos = func() string { return runtime.GOOS }

// Runtime abstracts the container CLI so leash can drive docker, podman, or
// (later) other backends. docker and podman are CLI-compatible — same verbs and
// flags — so they share cliRuntime, differing only by binary name. Backends
// whose command surface differs fundamentally (lxc/incus, apple container,
// firecracker) will provide their own Runtime implementation; remote daemons
// additionally need host paths copied in (bind mounts don't exist on the remote
// host), which is why they are a separate effort rather than a binary swap.
type Runtime interface {
	// Run executes a command and streams stdout/stderr (run, rm, pull).
	Run(ctx context.Context, args ...string) error
	// Output executes a command and captures combined output (inspect, ps, logs).
	Output(ctx context.Context, args ...string) (string, error)
	// ExecWithInput runs a shell command inside a container with optional stdin.
	ExecWithInput(ctx context.Context, container, shellCommand string, input io.Reader) error
	// Cmd builds a configured *exec.Cmd for callers that need direct control
	// (e.g. the interactive tty exec path).
	Cmd(ctx context.Context, args ...string) *exec.Cmd
	// Name reports the runtime identity (the binary), used in logs and errors.
	Name() string
}

// cliRuntime drives a docker-compatible CLI (docker or podman). It delegates to
// the package-level command wrappers so existing test seams keep intercepting.
// env carries extra environment (e.g. DOCKER_HOST) for a future remote backend;
// it is empty for the local docker/podman case.
type cliRuntime struct {
	bin string
	env []string
}

func (c cliRuntime) Run(ctx context.Context, args ...string) error {
	return runCommand(ctx, c.bin, args...)
}

func (c cliRuntime) Output(ctx context.Context, args ...string) (string, error) {
	return commandOutput(ctx, c.bin, args...)
}

func (c cliRuntime) ExecWithInput(ctx context.Context, container, shellCommand string, input io.Reader) error {
	return execWithInput(ctx, c.bin, container, shellCommand, input)
}

func (c cliRuntime) Cmd(ctx context.Context, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, c.bin, args...)
	if len(c.env) > 0 {
		cmd.Env = append(os.Environ(), c.env...)
	}
	return cmd
}

func (c cliRuntime) Name() string { return c.bin }

const defaultRuntime = "docker"

// supportedRuntimes lists the CLI-compatible runtimes this seam handles today.
var supportedRuntimes = []string{"docker", "podman"}

// nativeRuntimeName selects the container-free PoC backend (nativeRuntime). It
// is intentionally kept out of supportedRuntimes: it is not a CLI-compatible
// swap and its launch path is not wired (see runtime_native.go), so it should
// not be advertised alongside docker/podman — but newRuntime resolves it so the
// seam can be exercised end to end against a non-cliRuntime backend.
const nativeRuntimeName = "native"

// newRuntime resolves a runtime name to a Runtime. An empty name defaults to
// docker. Unsupported names return an error rather than failing later at the
// first container command.
func newRuntime(name string) (Runtime, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		name = defaultRuntime
	}
	if name == nativeRuntimeName {
		return newNativeRuntime(), nil
	}
	for _, s := range supportedRuntimes {
		if name == s {
			return cliRuntime{bin: name}, nil
		}
	}
	return nil, fmt.Errorf("unsupported runtime %q; supported runtimes: %s", name, strings.Join(supportedRuntimes, ", "))
}
