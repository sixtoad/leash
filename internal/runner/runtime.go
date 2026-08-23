package runner

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
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
	bin    string
	env    []string
	stdout io.Writer
	stderr io.Writer
}

func (c cliRuntime) Run(ctx context.Context, args ...string) error {
	stdout := c.stdout
	if stdout == nil {
		stdout = os.Stdout
	}
	stderr := c.stderr
	if stderr == nil {
		stderr = os.Stderr
	}
	return runCommand(ctx, stdout, stderr, c.bin, args...)
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

// withRuntimeWriters assigns ownership of lifecycle-command output without
// changing workload commands built through Cmd. Non-CLI runtimes capture or
// discard their own lifecycle output and are returned unchanged.
func withRuntimeWriters(rt Runtime, stdout, stderr io.Writer) Runtime {
	switch cli := rt.(type) {
	case cliRuntime:
		cli.stdout = stdout
		cli.stderr = stderr
		return cli
	case *cliRuntime:
		copy := *cli
		copy.stdout = stdout
		copy.stderr = stderr
		return &copy
	}
	return rt
}

const defaultRuntime = "docker"

// supportedRuntimes lists the CLI-compatible runtimes this seam handles today.
var supportedRuntimes = []string{"docker", "podman"}

// nativeRuntimeName selects the container-free PoC backend (nativeRuntime). It
// is intentionally kept out of supportedRuntimes: it is not a CLI-compatible
// swap and its launch path is not wired (see runtime_native.go), so it should
// not be advertised alongside docker/podman — but newRuntime resolves it so the
// seam can be exercised end to end against a non-cliRuntime backend.
const nativeRuntimeName = "native"

// containerEngineProbeTimeout bounds the daemon reachability check. `docker
// info` against a dead or hung daemon can block indefinitely (socket accepted,
// never answered), and doctor must always return a verdict.
// A var so the timeout path itself is testable in milliseconds rather than
// seconds; nothing outside tests reassigns it.
var containerEngineProbeTimeout = 5 * time.Second

// DetectContainerEngine returns the container CLI a container-runtime `leash
// run` would use — the first supported engine found on PATH, which is also the
// order newRuntime resolves — together with an error when that engine's daemon
// does not answer. It returns ("", nil) when no supported engine is installed.
//
// It reports the *container* engine, not the runtime a bare `leash run`
// selects: in this build defaultRuntimeName() is `native` and native never
// falls back to docker, so reaching this engine takes an explicit
// `--runtime docker` / `--runtime podman` (or LEASH_RUNTIME). Doctor reports
// that separately (see DefaultRuntimeName).
//
// Exported for `leash doctor` (internal/doctor). It reports on the *first*
// engine rather than the first *working* one on purpose: that is the engine
// newRuntime resolves for an unqualified container runtime, and doctor exists
// so its verdict and a real run cannot disagree. An engine on PATH whose daemon
// is unreachable is not a runtime leash can enforce with, so the error is part
// of the answer, not a detail the caller has to go and re-derive.
func DetectContainerEngine() (engine string, err error) {
	for _, name := range supportedRuntimes {
		if _, lookErr := exec.LookPath(name); lookErr != nil {
			continue
		}
		return name, containerEngineReachable(name)
	}
	return "", nil
}

// containerEngineReachable runs `<engine> info` under a bounded timeout. `info`
// is the cheapest command that requires the daemon to answer — LookPath only
// proves a client binary exists, which on a machine with a stopped daemon or a
// socket the user cannot open is exactly the false positive issue #23 asks
// doctor to stop producing.
func containerEngineReachable(bin string) error {
	ctx, cancel := context.WithTimeout(context.Background(), containerEngineProbeTimeout)
	defer cancel()

	var stderr strings.Builder
	cmd := exec.CommandContext(ctx, bin, "info")
	cmd.Stdout = io.Discard
	cmd.Stderr = &stderr
	// Without WaitDelay, killing the CLI on timeout is not enough: Wait blocks
	// until every writer to the stderr pipe closes it, and a docker client that
	// spawned a helper leaves that pipe open. The timeout has to bound the wait
	// too, or doctor hangs on exactly the broken daemon it is there to report.
	cmd.WaitDelay = time.Second
	runErr := cmd.Run()
	if runErr == nil {
		return nil
	}
	if ctx.Err() != nil {
		return fmt.Errorf("%s info did not answer within %s", bin, containerEngineProbeTimeout)
	}
	if detail := firstLines(stderr.String(), 3); detail != "" {
		return fmt.Errorf("%s info failed: %s", bin, detail)
	}
	return fmt.Errorf("%s info failed: %w", bin, runErr)
}

// ansiEscape matches the escape sequences container CLIs emit on stderr: the
// CSI form (colour/SGR, cursor movement), the OSC form (terminal title,
// hyperlinks, terminated by BEL or ST), and the bare two-byte forms.
var ansiEscape = regexp.MustCompile("\x1b\\][^\x07\x1b]*(?:\x07|\x1b\\\\)?|\x1b\\[[0-?]*[ -/]*[@-~]|\x1b[@-Z\\\\-_]")

// firstLines trims a command's stderr down to something that fits in a doctor
// issue: engines are chatty and the actionable part is at the top.
//
// It also sanitizes. This text is pasted verbatim into a doctor issue, which
// reaches both a terminal and the JSON document, and engine clients decorate
// their stderr: ANSI colour, cursor movement, and carriage returns for progress
// redraws. Passed through, those bytes let a failing daemon's output move the
// cursor around the readiness report a reader is consulting precisely because
// they do not trust the machine. Carriage returns become line breaks (that is
// what they meant on a terminal), escape sequences are removed, and any
// remaining control character collapses to a space.
func firstLines(s string, n int) string {
	var kept []string
	for _, line := range strings.FieldsFunc(s, func(r rune) bool { return r == '\n' || r == '\r' }) {
		line = sanitizeControl(line)
		if line == "" {
			continue
		}
		kept = append(kept, line)
		if len(kept) == n {
			break
		}
	}
	return strings.Join(kept, " ")
}

// sanitizeControl strips escape sequences and control characters from one line
// of command output, collapsing the whitespace it leaves behind. Invalid UTF-8
// goes too: the report is JSON-encoded, and a replacement character adds
// nothing a reader can act on.
func sanitizeControl(s string) string {
	s = ansiEscape.ReplaceAllString(s, "")
	s = strings.Map(func(r rune) rune {
		if r == utf8.RuneError || unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
	return strings.Join(strings.Fields(s), " ")
}

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
