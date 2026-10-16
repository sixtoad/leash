package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"testing"
)

// bootstrapFailureRuntime models a target whose bootstrap entrypoint exits: each
// target state inspect pops the next state, `logs` returns the target's output,
// and launching the sidecar fails the way Docker does once the target is gone.
type bootstrapFailureRuntime struct {
	states    []string // successive "{{.State.Status}} {{.State.ExitCode}}" answers
	logs      string
	runErr    error
	runs      int
	logsCalls int
}

func (rt *bootstrapFailureRuntime) Run(ctx context.Context, args ...string) error {
	_, err := rt.Output(ctx, args...)
	return err
}

func (rt *bootstrapFailureRuntime) Output(_ context.Context, args ...string) (string, error) {
	switch {
	case len(args) == 4 && args[0] == "inspect" && args[2] == "{{.State.Status}} {{.State.ExitCode}}":
		if len(rt.states) == 0 {
			return "", errors.New("no state scripted")
		}
		s := rt.states[0]
		if len(rt.states) > 1 {
			rt.states = rt.states[1:]
		}
		if s == "missing" {
			return "", errors.New("Error: No such object: " + args[3])
		}
		return s + "\n", nil
	case len(args) >= 1 && args[0] == "logs":
		rt.logsCalls++
		return rt.logs, nil
	case len(args) >= 1 && args[0] == "run":
		rt.runs++
		return "", rt.runErr
	}
	return "", fmt.Errorf("unexpected command: %v", args)
}

func (rt *bootstrapFailureRuntime) ExecWithInput(context.Context, string, string, io.Reader) error {
	return nil
}
func (rt *bootstrapFailureRuntime) Cmd(ctx context.Context, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, "true")
}
func (rt *bootstrapFailureRuntime) Name() string { return "docker" }

const failingBootstrapLogs = "starting leash-entry\n" +
	"\x1b[31mOPENAI_API_KEY=sk-live-abcdefghijklmnopqrstuvwxyz0123\x1b[0m\n" +
	"fetching https://bot:hunter2secret@example.com/repo.git\n" +
	"Authorization: Bearer abcdefghijklmnop.qrstuvwxyz\n" +
	"leash-error: update-ca-trust or update-ca-certificates not found\n"

var netnsErr = errors.New("docker: Error response from daemon: cannot join network namespace of a non running container")

func bootstrapFailureRunner(rt Runtime) *runner {
	return &runner{
		runtime: rt,
		cfg: config{
			targetContainer: "target",
			leashContainer:  "target-leash",
			leashImage:      "leash:test",
		},
	}
}

func assertSanitizedTargetDiag(t *testing.T, msg string) {
	t.Helper()
	for _, want := range []string{
		"target container target exited",
		"exit code 1",
		"leash-error: update-ca-trust or update-ca-certificates not found",
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("diagnostic missing %q:\n%s", want, msg)
		}
	}
	for _, secret := range []string{"sk-live-abcdefghijklmnopqrstuvwxyz0123", "hunter2secret", "abcdefghijklmnop.qrstuvwxyz", "\x1b["} {
		if strings.Contains(msg, secret) {
			t.Fatalf("diagnostic leaked %q:\n%s", secret, msg)
		}
	}
}

// The target already exited when enforcement starts: report it, and don't even
// try to launch a sidecar into its dead network namespace (#81).
func TestStartEnforcementSurfacesTargetExitBeforeSidecar(t *testing.T) {
	rt := &bootstrapFailureRuntime{states: []string{"exited 1"}, logs: failingBootstrapLogs, runErr: netnsErr}
	err := containerLauncher{r: bootstrapFailureRunner(rt)}.StartEnforcement(context.Background(), "/sys/fs/cgroup/x")
	var tbe *targetBootstrapError
	if !errors.As(err, &tbe) {
		t.Fatalf("want targetBootstrapError, got %v", err)
	}
	if rt.runs != 0 {
		t.Fatalf("sidecar must not be launched for an exited target (runs=%d)", rt.runs)
	}
	if tbe.exitCode != 1 {
		t.Fatalf("exit code = %d, want 1", tbe.exitCode)
	}
	assertSanitizedTargetDiag(t, err.Error())
	if strings.Contains(err.Error(), "cannot join network namespace") {
		t.Fatalf("no sidecar error expected when the sidecar was never launched: %v", err)
	}
}

// The target dies between the pre-check and the sidecar launch: the netns error
// is demoted to secondary context behind the target's own diagnostic.
func TestStartEnforcementPrefersTargetExitOverNetnsError(t *testing.T) {
	rt := &bootstrapFailureRuntime{states: []string{"running 0", "exited 1"}, logs: failingBootstrapLogs, runErr: netnsErr}
	err := containerLauncher{r: bootstrapFailureRunner(rt)}.StartEnforcement(context.Background(), "/sys/fs/cgroup/x")
	var tbe *targetBootstrapError
	if !errors.As(err, &tbe) {
		t.Fatalf("want targetBootstrapError, got %v", err)
	}
	if rt.runs != 1 {
		t.Fatalf("sidecar launch attempts = %d, want 1", rt.runs)
	}
	msg := err.Error()
	assertSanitizedTargetDiag(t, msg)
	primary := strings.Index(msg, "target container target exited")
	secondary := strings.Index(msg, "cannot join network namespace")
	if primary != 0 || secondary < primary {
		t.Fatalf("target exit must be primary and the netns error secondary:\n%s", msg)
	}
	if !errors.Is(err, netnsErr) {
		t.Fatalf("secondary sidecar error should stay unwrappable: %v", err)
	}
}

// A sidecar failure while the target is still running is not a bootstrap exit:
// the original error is returned unchanged and no logs are pulled.
func TestStartEnforcementKeepsSidecarErrorWhenTargetRunning(t *testing.T) {
	other := errors.New("docker: image not found")
	rt := &bootstrapFailureRuntime{states: []string{"running 0"}, logs: failingBootstrapLogs, runErr: other}
	err := containerLauncher{r: bootstrapFailureRunner(rt)}.StartEnforcement(context.Background(), "/sys/fs/cgroup/x")
	if !errors.Is(err, other) {
		t.Fatalf("want original sidecar error, got %v", err)
	}
	var tbe *targetBootstrapError
	if errors.As(err, &tbe) {
		t.Fatalf("running target must not be reported as a bootstrap exit: %v", err)
	}
	if rt.logsCalls != 0 {
		t.Fatalf("logs fetched for a running target (%d calls)", rt.logsCalls)
	}
}

// A target already removed (e.g. --rm or external cleanup) is still reported as
// the primary failure, without logs.
func TestStartEnforcementTargetMissing(t *testing.T) {
	rt := &bootstrapFailureRuntime{states: []string{"missing"}, runErr: netnsErr}
	err := containerLauncher{r: bootstrapFailureRunner(rt)}.StartEnforcement(context.Background(), "/sys/fs/cgroup/x")
	var tbe *targetBootstrapError
	if !errors.As(err, &tbe) {
		t.Fatalf("want targetBootstrapError, got %v", err)
	}
	if !strings.Contains(err.Error(), "state=missing") || rt.logsCalls != 0 {
		t.Fatalf("unexpected diagnostic (logsCalls=%d): %v", rt.logsCalls, err)
	}
}

// The diagnostic is captured even when the run context is already cancelled
// (teardown in progress), before cleanup removes the container.
func TestTargetBootstrapFailureIgnoresCancellation(t *testing.T) {
	rt := &bootstrapFailureRuntime{states: []string{"exited 2"}, logs: "boom\n"}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	tbe := bootstrapFailureRunner(rt).targetBootstrapFailure(ctx, "during bootstrap", nil)
	if tbe == nil || tbe.exitCode != 2 || tbe.logs != "boom" {
		t.Fatalf("diagnostic = %+v", tbe)
	}
}

func TestSanitizeContainerLogsBounds(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 100; i++ {
		fmt.Fprintf(&b, "line %d\n", i)
	}
	b.WriteString(strings.Repeat("x", 1000) + "\n")
	got := sanitizeContainerLogs(b.String())
	lines := strings.Split(got, "\n")
	if len(lines) > targetLogTailLines {
		t.Fatalf("kept %d lines, want <= %d", len(lines), targetLogTailLines)
	}
	if lines[0] != "line 81" {
		t.Fatalf("should keep the most recent lines, first kept = %q", lines[0])
	}
	if last := lines[len(lines)-1]; len([]rune(last)) > targetLogLineMaxRune+3 {
		t.Fatalf("long line not truncated: %d runes", len([]rune(last)))
	}
	if len(got) > targetLogMaxBytes {
		t.Fatalf("excerpt is %d bytes, want <= %d", len(got), targetLogMaxBytes)
	}
}

func TestRedactCredentials(t *testing.T) {
	cases := map[string]string{
		"GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123":   "ghp_",
		`{"api_key": "plain-secret-value"}`:                 "plain-secret-value",
		"password: hunter2":                                 "hunter2",
		"AWS key AKIAABCDEFGHIJKLMNOP in use":               "AKIAABCDEFGHIJKLMNOP",
		"jwt eyJhbGciOiJI.eyJzdWIiOiIxMjM0.c2lnbmF0dXJlX3g": "eyJhbGciOiJI",
		"-----BEGIN RSA PRIVATE KEY-----":                   "BEGIN RSA",
		"clone https://user:pa55word@git.example/x":         "pa55word",
	}
	for in, leaked := range cases {
		if out := redactCredentials(in); strings.Contains(out, leaked) {
			t.Errorf("redactCredentials(%q) = %q still contains %q", in, out, leaked)
		}
	}
	// Ordinary bootstrap diagnostics pass through untouched.
	plain := "leash-error: update-ca-trust or update-ca-certificates not found"
	if out := redactCredentials(plain); out != plain {
		t.Fatalf("plain diagnostic altered: %q", out)
	}
}
