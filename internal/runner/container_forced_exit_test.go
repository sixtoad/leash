package runner

import (
	"context"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// runRecorder is a container Runtime that records Run calls.
type runRecorder struct {
	mu   *sync.Mutex
	runs *[]string
}

func (rr runRecorder) Run(ctx context.Context, args ...string) error {
	rr.mu.Lock()
	*rr.runs = append(*rr.runs, strings.Join(args, " "))
	rr.mu.Unlock()
	return nil
}
func (rr runRecorder) Output(ctx context.Context, args ...string) (string, error) { return "", nil }
func (rr runRecorder) ExecWithInput(ctx context.Context, container, shellCommand string, input io.Reader) error {
	return nil
}
func (rr runRecorder) Cmd(ctx context.Context, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, "true")
}
func (rr runRecorder) Name() string { return "docker" }

// Container backend: a forced exit can land after the orderly teardown removed
// the sidecar but not the target, leaving the workload's container running
// unenforced. The forced path removes both and the temp work dir.
func TestContainerForcedExitRemovesContainers(t *testing.T) {
	var mu sync.Mutex
	var runs []string
	r := &runner{runtime: runRecorder{mu: &mu, runs: &runs}, logger: log.New(io.Discard, "", 0)}
	r.cfg.targetContainer, r.cfg.leashContainer = "agent", "agent-leash"
	r.cfg.workDir = filepath.Join(t.TempDir(), "leash.ctr")
	r.cfg.workDirIsTemp = true
	if err := os.MkdirAll(r.cfg.workDir, 0o755); err != nil {
		t.Fatal(err)
	}
	r.forcedExitCleanup()
	mu.Lock()
	defer mu.Unlock()
	if len(runs) != 1 || runs[0] != "rm -f agent agent-leash" {
		t.Fatalf("runs=%v, want rm -f of both containers", runs)
	}
	if _, err := os.Stat(r.cfg.workDir); !os.IsNotExist(err) {
		t.Fatal("temp work dir not removed")
	}
}
