package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

type identityRecordingRuntime struct {
	imageUserOutput string
	imageUserErr    error
	runs            [][]string
	runErrors       []error
	commands        [][]string
	commandCtxErrs  []error
	execCommands    []string
}

func (rt *identityRecordingRuntime) Run(_ context.Context, args ...string) error {
	rt.runs = append(rt.runs, append([]string(nil), args...))
	if len(rt.runErrors) > 0 {
		err := rt.runErrors[0]
		rt.runErrors = rt.runErrors[1:]
		return err
	}
	return nil
}

func (rt *identityRecordingRuntime) Output(_ context.Context, args ...string) (string, error) {
	if len(args) >= 4 && args[0] == "image" && args[1] == "inspect" && args[3] == "{{json .Config.User}}" {
		return rt.imageUserOutput, rt.imageUserErr
	}
	return "", fmt.Errorf("unexpected output command: %v", args)
}

func (rt *identityRecordingRuntime) ExecWithInput(_ context.Context, _ string, command string, _ io.Reader) error {
	rt.execCommands = append(rt.execCommands, command)
	return nil
}

func (rt *identityRecordingRuntime) Cmd(ctx context.Context, args ...string) *exec.Cmd {
	rt.commands = append(rt.commands, append([]string(nil), args...))
	rt.commandCtxErrs = append(rt.commandCtxErrs, ctx.Err())
	return exec.CommandContext(ctx, "true")
}

func (rt *identityRecordingRuntime) Name() string { return "docker" }

func TestCaptureTargetContainerUser(t *testing.T) {
	tests := []struct {
		name       string
		inspectOut string
		want       string
	}{
		{name: "default", inspectOut: `""`, want: ""},
		{name: "root", inspectOut: `"root"`, want: "root"},
		{name: "numeric root", inspectOut: `"0"`, want: "0"},
		{name: "named", inspectOut: `"agent"`, want: "agent"},
		{name: "numeric", inspectOut: `"10001"`, want: "10001"},
		{name: "named group", inspectOut: `"agent:workers"`, want: "agent:workers"},
		{name: "numeric group", inspectOut: `"10001:10001"`, want: "10001:10001"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt := &identityRecordingRuntime{imageUserOutput: tt.inspectOut}
			r := &runner{runtime: rt, cfg: config{targetImage: "example/target:latest"}}
			if err := r.captureTargetContainerUser(context.Background()); err != nil {
				t.Fatalf("captureTargetContainerUser() error = %v", err)
			}
			if got := r.targetContainerUser; got != tt.want {
				t.Fatalf("captured user = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCaptureTargetContainerUserRejectsInvalidInspectResults(t *testing.T) {
	tests := []struct {
		name string
		out  string
		err  error
	}{
		{name: "inspect error", err: fmt.Errorf("inspect failed")},
		{name: "empty output"},
		{name: "malformed json", out: `{"`},
		{name: "null", out: `null`},
		{name: "non-string", out: `123`},
		{name: "nul", out: `"agent\u0000root"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt := &identityRecordingRuntime{imageUserOutput: tt.out, imageUserErr: tt.err}
			r := &runner{
				runtime:             rt,
				cfg:                 config{targetImage: "example/target:latest"},
				targetContainerUser: "sentinel",
			}
			if err := r.captureTargetContainerUser(context.Background()); err == nil {
				t.Fatal("captureTargetContainerUser() error = nil, want malformed identity failure")
			}
			if got := r.targetContainerUser; got != "sentinel" {
				t.Fatalf("failed capture changed user to %q", got)
			}
		})
	}
}

func TestValidateContainerUserKeepsOpaqueRuntimeSyntax(t *testing.T) {
	for _, user := range []string{"", " agent", "agent ", "-agent", "agent:", ":staff", "agent:staff:extra", "agent\nroot"} {
		if err := validateContainerUser(user); err != nil {
			t.Fatalf("validateContainerUser(%q) = %v; runtime-owned syntax must remain opaque", user, err)
		}
	}
}

func TestContainerLauncherProvisionRejectsInvalidUserBeforeTargetLaunch(t *testing.T) {
	rt := &identityRecordingRuntime{imageUserOutput: `" agent"`}
	r := &runner{
		runtime: rt,
		cfg: config{
			targetImage: "example/target:latest",
		},
	}

	if _, err := (containerLauncher{r: r}).Provision(context.Background(), "SIGTERM"); err == nil {
		t.Fatal("Provision() error = nil, want invalid target identity failure")
	}
	if len(rt.runs) != 0 || len(rt.commands) != 0 {
		t.Fatalf("invalid identity reached target commands: runs=%v commands=%v", rt.runs, rt.commands)
	}
}

func TestTargetWorkloadExecArgsPreserveIdentity(t *testing.T) {
	tests := []struct {
		name string
		user string
		want string
	}{
		{name: "default", user: "", want: "0"},
		{name: "root", user: "root", want: "root"},
		{name: "numeric root", user: "0", want: "0"},
		{name: "named", user: "agent", want: "agent"},
		{name: "numeric", user: "10001", want: "10001"},
		{name: "numeric group", user: "10001:10001", want: "10001:10001"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &runner{
				cfg:                 config{callerDir: "/workspace", targetContainer: "target"},
				targetContainerUser: tt.user,
			}
			got := r.targetWorkloadExecArgs("-it", "sh", "-lc", "exec id")
			want := []string{"exec", "-it", "--user", tt.want, "-w", "/workspace", "target", "sh", "-lc", "exec id"}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("targetWorkloadExecArgs() = %v, want %v", got, want)
			}
		})
	}
}

func TestTargetWorkloadRootClassification(t *testing.T) {
	tests := []struct {
		user string
		want bool
	}{
		{user: "", want: true},
		{user: "0", want: true},
		{user: "0:0", want: true},
		{user: "root", want: true},
		{user: "root:staff", want: true},
		{user: "agent", want: false},
		{user: "1001:1001", want: false},
	}

	for _, tt := range tests {
		r := &runner{targetContainerUser: tt.user}
		if got := r.targetWorkloadIsRoot(); got != tt.want {
			t.Fatalf("targetWorkloadIsRoot() for %q = %v, want %v", tt.user, got, tt.want)
		}
	}
}

func TestContainerLauncherPromptInstallationRespectsTargetIdentity(t *testing.T) {
	for _, tt := range []struct {
		name      string
		user      string
		wantCalls bool
	}{
		{name: "non-root named user", user: "agent", wantCalls: false},
		{name: "non-root numeric user", user: "1001:1001", wantCalls: false},
		{name: "default root", user: "", wantCalls: true},
		{name: "explicit root", user: "root:root", wantCalls: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rt := &identityRecordingRuntime{}
			r := &runner{
				runtime:             rt,
				cfg:                 config{targetContainer: "target"},
				targetContainerUser: tt.user,
			}
			if err := (containerLauncher{r: r}).InstallPromptAssets(context.Background()); err != nil {
				t.Fatalf("InstallPromptAssets() error = %v", err)
			}
			if got := len(rt.execCommands) > 0; got != tt.wantCalls {
				t.Fatalf("system prompt commands issued = %v, want %v; commands=%v", got, tt.wantCalls, rt.execCommands)
			}
		})
	}
}

func TestInteractivePrecheckFailureRemovesContainers(t *testing.T) {
	rt := &identityRecordingRuntime{}
	r := &runner{
		runtime: rt,
		cfg: config{
			targetContainer: "target",
			leashContainer:  "manager",
		},
	}
	wantErr := errors.New("precheck failed")
	if err := r.finishInteractivePrecheckFailure(context.Background(), wantErr); !errors.Is(err, wantErr) {
		t.Fatalf("finishInteractivePrecheckFailure() error = %v, want %v", err, wantErr)
	}
	want := [][]string{
		{"rm", "-f", "manager"},
		{"rm", "-f", "target"},
	}
	if !reflect.DeepEqual(rt.commands, want) {
		t.Fatalf("cleanup commands = %v, want %v", rt.commands, want)
	}
}

func TestCanceledProbeStillRemovesContainersWithUsableContext(t *testing.T) {
	rt := &identityRecordingRuntime{}
	r := &runner{
		runtime: rt,
		cfg: config{
			targetContainer: "target",
			leashContainer:  "manager",
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := r.finishLifecycle(ctx, 0, context.Canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("finishLifecycle() error = %v, want context.Canceled", err)
	}
	want := [][]string{
		{"rm", "-f", "manager"},
		{"rm", "-f", "target"},
	}
	if !reflect.DeepEqual(rt.commands, want) {
		t.Fatalf("cleanup commands = %v, want %v", rt.commands, want)
	}
	if !reflect.DeepEqual(rt.commandCtxErrs, []error{nil, nil}) {
		t.Fatalf("cleanup context errors = %v, want usable contexts", rt.commandCtxErrs)
	}
}

func TestContainerLauncherWorkloadPathsUseCapturedIdentity(t *testing.T) {
	rt := &identityRecordingRuntime{}
	r := &runner{
		runtime:             rt,
		cfg:                 config{callerDir: "/workspace", targetContainer: "target"},
		targetContainerUser: "agent:workers",
	}
	l := containerLauncher{r: r}

	if shell, err := l.DetectShell(context.Background()); err != nil || shell != "bash" {
		t.Fatalf("DetectShell() = %q, %v; want bash, nil", shell, err)
	}
	wantDetect := []string{"exec", "--env", "BASH_ENV=", "--env", "ENV=", "--user", "agent:workers", "-w", "/workspace", "target", "bash", "--noprofile", "--norc", "-c", "true"}
	if !reflect.DeepEqual(rt.commands[0], wantDetect) {
		t.Fatalf("DetectShell argv = %v, want %v", rt.commands[0], wantDetect)
	}

	_ = l.execCommandWithStdinKind(context.Background(), "bash", "id", false, false)
	wantNonInteractive := []string{"exec", "-i", "--user", "agent:workers", "-w", "/workspace", "target", "bash", "-lc", "exec id"}
	if !reflect.DeepEqual(rt.commands[1], wantNonInteractive) {
		t.Fatalf("non-interactive argv = %v, want %v", rt.commands[1], wantNonInteractive)
	}

	_ = l.ExecCommand(context.Background(), "bash", "id", true)
	wantInteractive := []string{"exec", "-it", "--user", "agent:workers", "-w", "/workspace", "target", "bash", "-lc", "exec id"}
	if !reflect.DeepEqual(rt.commands[2], wantInteractive) {
		t.Fatalf("interactive argv = %v, want %v", rt.commands[2], wantInteractive)
	}

	if err := l.Precheck(context.Background(), "bash", "id"); err != nil {
		t.Fatalf("Precheck() error = %v", err)
	}
	wantPrecheck := []string{"exec", "-it", "--env", "BASH_ENV=", "--env", "ENV=", "--user", "agent:workers", "-w", "/workspace", "target", "bash", "--noprofile", "--norc", "-c", "true"}
	if !reflect.DeepEqual(rt.commands[3], wantPrecheck) {
		t.Fatalf("precheck argv = %v, want %v", rt.commands[3], wantPrecheck)
	}
}

func TestContainerLauncherExecCommandSelectsInputFlag(t *testing.T) {
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devNull.Close()
	if containerStdinIsTerminal(devNull) {
		t.Fatalf("%s is a redirected character device, not a terminal", os.DevNull)
	}

	tests := []struct {
		name            string
		interactive     bool
		stdinIsTerminal bool
		wantFlag        string
	}{
		{name: "terminal non-interactive", stdinIsTerminal: true},
		{name: "pipe non-interactive", wantFlag: "-i"},
		{name: "file non-interactive", wantFlag: "-i"},
		{name: "redirected character device non-interactive", wantFlag: "-i"},
		{name: "terminal interactive", interactive: true, stdinIsTerminal: true, wantFlag: "-it"},
		{name: "non-terminal interactive", interactive: true, wantFlag: "-it"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt := &identityRecordingRuntime{}
			r := &runner{
				runtime:             rt,
				cfg:                 config{callerDir: "/workspace", targetContainer: "target"},
				targetContainerUser: "agent",
			}
			l := containerLauncher{r: r}

			_ = l.execCommandWithStdinKind(context.Background(), "sh", "cat", tt.interactive, tt.stdinIsTerminal)
			want := []string{"exec"}
			if tt.wantFlag != "" {
				want = append(want, tt.wantFlag)
			}
			want = append(want, "--user", "agent", "-w", "/workspace", "target", "sh", "-lc", "exec cat")
			if !reflect.DeepEqual(rt.commands[0], want) {
				t.Fatalf("ExecCommand argv = %v, want %v", rt.commands[0], want)
			}
		})
	}
}

func TestContainerLauncherDetectShellFallbackPreservesIdentity(t *testing.T) {
	rt := &shellProbeRuntime{actions: []shellProbeAction{
		{stderr: "bash unavailable", exitCode: 1},
		{},
	}}
	r := &runner{
		runtime:             rt,
		cfg:                 config{callerDir: "/workspace", targetContainer: "target"},
		targetContainerUser: "10001:10001",
	}

	shell, err := (containerLauncher{r: r}).DetectShell(context.Background())
	if err != nil || shell != "sh" {
		t.Fatalf("DetectShell() = %q, %v; want sh, nil", shell, err)
	}
	want := [][]string{
		{"exec", "--env", "BASH_ENV=", "--env", "ENV=", "--user", "10001:10001", "-w", "/workspace", "target", "bash", "--noprofile", "--norc", "-c", "true"},
		{"exec", "--env", "BASH_ENV=", "--env", "ENV=", "--user", "10001:10001", "-w", "/workspace", "target", "sh", "-c", "true"},
	}
	if !reflect.DeepEqual(rt.commands, want) {
		t.Fatalf("DetectShell fallback argv = %v, want %v", rt.commands, want)
	}
}

type shellProbeAction struct {
	stderr      string
	exitCode    int
	hang        bool
	startedFile string
}

type shellProbeRuntime struct {
	actions  []shellProbeAction
	commands [][]string
}

func (rt *shellProbeRuntime) Run(context.Context, ...string) error { return nil }

func (rt *shellProbeRuntime) Output(context.Context, ...string) (string, error) { return "", nil }

func (rt *shellProbeRuntime) ExecWithInput(context.Context, string, string, io.Reader) error {
	return nil
}

func (rt *shellProbeRuntime) Cmd(ctx context.Context, args ...string) *exec.Cmd {
	rt.commands = append(rt.commands, append([]string(nil), args...))
	var action shellProbeAction
	if len(rt.actions) > 0 {
		action = rt.actions[0]
		rt.actions = rt.actions[1:]
	}
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestContainerShellProbeHelper$", "--")
	cmd.Env = append(os.Environ(),
		"GO_WANT_CONTAINER_SHELL_PROBE_HELPER=1",
		"CONTAINER_SHELL_PROBE_STDERR="+action.stderr,
		"CONTAINER_SHELL_PROBE_EXIT_CODE="+strconv.Itoa(action.exitCode),
		"CONTAINER_SHELL_PROBE_HANG="+strconv.FormatBool(action.hang),
		"CONTAINER_SHELL_PROBE_STARTED_FILE="+action.startedFile,
	)
	return cmd
}

func (rt *shellProbeRuntime) Name() string { return "docker" }

func TestContainerShellProbeHelper(t *testing.T) {
	if os.Getenv("GO_WANT_CONTAINER_SHELL_PROBE_HELPER") != "1" {
		return
	}
	if startedFile := os.Getenv("CONTAINER_SHELL_PROBE_STARTED_FILE"); startedFile != "" {
		if err := os.WriteFile(startedFile, []byte("started"), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(125)
		}
	}
	fmt.Fprint(os.Stderr, os.Getenv("CONTAINER_SHELL_PROBE_STDERR"))
	if os.Getenv("CONTAINER_SHELL_PROBE_HANG") == "true" {
		for {
			time.Sleep(time.Hour)
		}
	}
	exitCode, _ := strconv.Atoi(os.Getenv("CONTAINER_SHELL_PROBE_EXIT_CODE"))
	os.Exit(exitCode)
}

func TestContainerLauncherDetectShellReportsBoundedFailures(t *testing.T) {
	noisy := strings.Repeat("x", shellProbeDiagnosticLimit*2)
	rt := &shellProbeRuntime{actions: []shellProbeAction{
		{stderr: "bash: permission denied\n", exitCode: 126},
		{stderr: noisy, exitCode: 127},
	}}
	r := &runner{runtime: rt, cfg: config{callerDir: "/workspace", targetContainer: "target"}}

	_, err := (containerLauncher{r: r}).DetectShell(context.Background())
	if err == nil {
		t.Fatal("DetectShell() error = nil, want both-candidates failure")
	}
	got := err.Error()
	for _, want := range []string{"bash failed: bash: permission denied", "sh failed:", "[stderr truncated]"} {
		if !strings.Contains(got, want) {
			t.Fatalf("DetectShell() error = %q, want %q", got, want)
		}
	}
	if len(got) > shellProbeDiagnosticLimit+512 {
		t.Fatalf("DetectShell() error length = %d, want bounded diagnostic", len(got))
	}
}

func TestContainerLauncherDetectShellTimeoutIsTerminal(t *testing.T) {
	original := containerShellProbeTimeout
	containerShellProbeTimeout = 50 * time.Millisecond
	t.Cleanup(func() { containerShellProbeTimeout = original })

	rt := &shellProbeRuntime{actions: []shellProbeAction{{hang: true}, {}}}
	r := &runner{runtime: rt, cfg: config{callerDir: "/workspace", targetContainer: "target"}}
	started := time.Now()
	_, err := (containerLauncher{r: r}).DetectShell(context.Background())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("DetectShell() error = %v, want context.DeadlineExceeded", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("DetectShell() took %s; candidate timeout did not bound the probe", elapsed)
	}
	if len(rt.commands) != 1 {
		t.Fatalf("probe commands = %v, want no fallback after timeout", rt.commands)
	}
}

func TestContainerLauncherDetectShellParentCancellationStopsFallback(t *testing.T) {
	original := containerShellProbeTimeout
	containerShellProbeTimeout = 5 * time.Second
	t.Cleanup(func() { containerShellProbeTimeout = original })

	startedFile := filepath.Join(t.TempDir(), "started")
	rt := &shellProbeRuntime{actions: []shellProbeAction{{hang: true, startedFile: startedFile}, {}}}
	r := &runner{runtime: rt, cfg: config{callerDir: "/workspace", targetContainer: "target"}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := (containerLauncher{r: r}).DetectShell(ctx)
		done <- err
	}()

	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(startedFile); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("shell probe helper did not start")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("DetectShell() error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("DetectShell() did not terminate the active probe after cancellation")
	}
	if len(rt.commands) != 1 {
		t.Fatalf("probe commands after cancellation = %v, want no fallback", rt.commands)
	}
}

func TestContainerLauncherPrecheckUsesBoundedNonLoginProbe(t *testing.T) {
	original := containerShellProbeTimeout
	containerShellProbeTimeout = 50 * time.Millisecond
	t.Cleanup(func() { containerShellProbeTimeout = original })

	rt := &shellProbeRuntime{actions: []shellProbeAction{{hang: true}}}
	r := &runner{
		runtime:             rt,
		cfg:                 config{callerDir: "/workspace", targetContainer: "target"},
		targetContainerUser: "agent:workers",
	}
	started := time.Now()
	err := (containerLauncher{r: r}).Precheck(context.Background(), "bash", "ignored workload")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Precheck() error = %v, want context.DeadlineExceeded", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("Precheck() took %s; timeout did not bound the probe", elapsed)
	}
	want := [][]string{{"exec", "-it", "--env", "BASH_ENV=", "--env", "ENV=", "--user", "agent:workers", "-w", "/workspace", "target", "bash", "--noprofile", "--norc", "-c", "true"}}
	if !reflect.DeepEqual(rt.commands, want) {
		t.Fatalf("Precheck argv = %v, want non-login probe %v", rt.commands, want)
	}
}

func TestContainerLauncherPrecheckParentCancellationTerminatesProbe(t *testing.T) {
	original := containerShellProbeTimeout
	containerShellProbeTimeout = 5 * time.Second
	t.Cleanup(func() { containerShellProbeTimeout = original })

	startedFile := filepath.Join(t.TempDir(), "started")
	rt := &shellProbeRuntime{actions: []shellProbeAction{{hang: true, startedFile: startedFile}}}
	r := &runner{runtime: rt, cfg: config{callerDir: "/workspace", targetContainer: "target"}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- (containerLauncher{r: r}).Precheck(ctx, "sh", "ignored workload") }()

	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(startedFile); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("interactive shell probe helper did not start")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Precheck() error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Precheck() did not terminate after parent cancellation")
	}
}

func TestManualAttachCommandQuotesImageUser(t *testing.T) {
	r := &runner{
		runtime:             &identityRecordingRuntime{},
		cfg:                 config{callerDir: "/work tree", targetContainer: "target"},
		targetContainerUser: "agent;touch/tmp/pwn",
	}
	got := r.manualAttachCommand("sh", "printf '%s' ok")
	want := `docker exec -it --user 'agent;touch/tmp/pwn' -w '/work tree' target sh -lc 'exec printf '"'"'%s'"'"' ok'`
	if got != want {
		t.Fatalf("manual attach command = %q, want %q", got, want)
	}
}
