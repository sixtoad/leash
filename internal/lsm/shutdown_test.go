package lsm

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

const shutdownHelperEnv = "LEASH_TEST_LSM_SHUTDOWN_HELPER"

// TestLSMShutdownHelper runs in a re-exec'd process (the shutdown latch is
// process-global and one-way, so it must not fire inside the shared test
// binary). It reproduces the #143 ordering: an attach goroutine is already
// listening when SIGTERM arrives BEFORE LoadAndStart starts waiting. The old
// per-call signal.Notify lost that signal and LoadAndStart blocked forever;
// with the sticky latch LoadAndStart returns, after the attach goroutine (which
// stands in for one closing its BPF links) has returned.
func TestLSMShutdownHelper(t *testing.T) {
	if os.Getenv(shutdownHelperEnv) == "" {
		t.Skip("helper process for TestLoadAndStartObservesEarlySignal")
	}
	InstallShutdownHandler() // leashd Main does this first
	m := NewLSMManager("", nil, false)
	detached := make(chan struct{})
	m.goAttach(func() {
		<-ShutdownRequested()
		time.Sleep(100 * time.Millisecond) // link Close work
		close(detached)
	})
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		os.Exit(4)
	}
	select {
	case <-ShutdownRequested():
	case <-time.After(5 * time.Second):
		os.Exit(5)
	}
	if err := m.LoadAndStart(); err != nil {
		os.Exit(6)
	}
	select {
	case <-detached:
	default:
		os.Exit(7) // LoadAndStart returned before the links were closed
	}
	os.Stdout.WriteString("LSM-SHUTDOWN-OK\n")
	os.Exit(0)
}

func TestLoadAndStartObservesEarlySignal(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLSMShutdownHelper$")
	cmd.Env = append(os.Environ(), shutdownHelperEnv+"=1")
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("LoadAndStart never returned after an early SIGTERM (leashd would keep running):\n%s", out)
	}
	if err != nil || !strings.Contains(string(out), "LSM-SHUTDOWN-OK") {
		t.Fatalf("helper failed: %v\n%s", err, out)
	}
}

// waitDetached is bounded: a wedged attach goroutine cannot hang shutdown.
func TestWaitDetachedIsBounded(t *testing.T) {
	m := NewLSMManager("", nil, false)
	block := make(chan struct{})
	defer close(block)
	m.goAttach(func() { <-block })
	start := time.Now()
	if m.waitDetached(100 * time.Millisecond) {
		t.Fatal("waitDetached reported success with a goroutine still running")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("waitDetached exceeded its bound")
	}
	m2 := NewLSMManager("", nil, false)
	if !m2.waitDetached(time.Second) {
		t.Fatal("waitDetached with no goroutines should succeed immediately")
	}
}
