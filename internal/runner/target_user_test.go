package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"reflect"
	"testing"
)

type identityRecordingRuntime struct {
	imageUserOutput string
	imageUserErr    error
	runs            [][]string
	runErrors       []error
	commands        [][]string
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
	wantDetect := []string{"exec", "--user", "agent:workers", "-w", "/workspace", "target", "bash", "-lc", "true"}
	if !reflect.DeepEqual(rt.runs[0], wantDetect) {
		t.Fatalf("DetectShell argv = %v, want %v", rt.runs[0], wantDetect)
	}

	_ = l.execCommandWithStdinKind(context.Background(), "bash", "id", false, false)
	wantNonInteractive := []string{"exec", "-i", "--user", "agent:workers", "-w", "/workspace", "target", "bash", "-lc", "exec id"}
	if !reflect.DeepEqual(rt.commands[0], wantNonInteractive) {
		t.Fatalf("non-interactive argv = %v, want %v", rt.commands[0], wantNonInteractive)
	}

	_ = l.ExecCommand(context.Background(), "bash", "id", true)
	wantInteractive := []string{"exec", "-it", "--user", "agent:workers", "-w", "/workspace", "target", "bash", "-lc", "exec id"}
	if !reflect.DeepEqual(rt.commands[1], wantInteractive) {
		t.Fatalf("interactive argv = %v, want %v", rt.commands[1], wantInteractive)
	}

	if err := l.Precheck(context.Background(), "bash", "id"); err != nil {
		t.Fatalf("Precheck() error = %v", err)
	}
	wantPrecheck := []string{"exec", "-it", "--user", "agent:workers", "-w", "/workspace", "target", "bash", "-lc", "true"}
	if !reflect.DeepEqual(rt.commands[2], wantPrecheck) {
		t.Fatalf("precheck argv = %v, want %v", rt.commands[2], wantPrecheck)
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
	rt := &identityRecordingRuntime{runErrors: []error{fmt.Errorf("bash unavailable"), nil}}
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
		{"exec", "--user", "10001:10001", "-w", "/workspace", "target", "bash", "-lc", "true"},
		{"exec", "--user", "10001:10001", "-w", "/workspace", "target", "sh", "-lc", "true"},
	}
	if !reflect.DeepEqual(rt.runs, want) {
		t.Fatalf("DetectShell fallback argv = %v, want %v", rt.runs, want)
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
