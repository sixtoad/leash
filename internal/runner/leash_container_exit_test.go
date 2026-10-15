package runner

import (
	"context"
	"io"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// sidecarRuntime is a fake container runtime: inspect returns a fixed state
// per container name and logs returns a fixed log per container name.
type sidecarRuntime struct {
	states map[string]string
	logs   map[string]string
}

func (f sidecarRuntime) Run(ctx context.Context, args ...string) error { return nil }

func (f sidecarRuntime) Output(ctx context.Context, args ...string) (string, error) {
	if len(args) == 0 {
		return "", nil
	}
	name := args[len(args)-1]
	switch args[0] {
	case "inspect":
		return f.states[name], nil
	case "logs":
		return f.logs[name], nil
	}
	return "", nil
}

func (f sidecarRuntime) ExecWithInput(ctx context.Context, container, shellCommand string, input io.Reader) error {
	return nil
}

func (f sidecarRuntime) Cmd(ctx context.Context, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, "true")
}

func (f sidecarRuntime) Name() string { return "docker" }

// A leashd fail-closed refusal in the sidecar must surface immediately with
// the exit code and the FATAL reason — not as the 2-minute readiness timeout —
// and must win over the target container exiting as a consequence.
func TestWaitForEnforcementReadyReportsLeashSidecarExit(t *testing.T) {
	var logs strings.Builder
	for i := 0; i < 100; i++ {
		logs.WriteString("noise line\n")
	}
	logs.WriteString("leash: FATAL: enforcement=proxy-only (layer1=unavailable layer2=active): \"bpf\" is not among the active LSMs (lockdown,apparmor); but fail-closed is in effect\x1b[31m\n")

	r := &runner{runtime: sidecarRuntime{
		states: map[string]string{
			"agent":       "exited 137", // the target dies too
			"agent-leash": "exited 1",
		},
		logs: map[string]string{"agent-leash": logs.String()},
	}}
	r.cfg.shareDir = t.TempDir() // no marker ever appears
	r.cfg.bootstrapTimeout = 2 * time.Minute
	r.cfg.targetContainer = "agent"
	r.cfg.leashContainer = "agent-leash"

	start := time.Now()
	err := r.waitForEnforcementReady(context.Background())
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("waited %s; a stopped sidecar must end the wait immediately", elapsed)
	}
	if err == nil {
		t.Fatal("want an error when the leash sidecar exits before the marker")
	}
	msg := err.Error()
	for _, want := range []string{"leash container stopped", "exit=1", `"bpf" is not among the active LSMs`} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error missing %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "\x1b") {
		t.Fatalf("error must be sanitized of escape sequences:\n%q", msg)
	}
	if n := strings.Count(msg, "noise line"); n > leashContainerLogTailLines {
		t.Fatalf("log tail not bounded: %d noise lines", n)
	}
}

func TestSanitizeLogLine(t *testing.T) {
	got := sanitizeLogLine("a\x1b[1;31mred\x1b[0m\tb\rc\x07")
	if got != "ared\tbc" {
		t.Fatalf("sanitized = %q", got)
	}
}
