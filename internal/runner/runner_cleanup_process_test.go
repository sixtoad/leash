package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// This fixture uses a real exec.CommandContext process, so a canceled context
// actually kills a client. It does not model a real container daemon.
func TestContainerCreateProcessHelper(t *testing.T) {
	dir := os.Getenv("LEASH_TEST_CREATE_PROCESS")
	if dir == "" {
		return
	}
	if err := os.WriteFile(filepath.Join(dir, "started"), nil, 0600); err != nil {
		os.Exit(2)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(filepath.Join(dir, "release")); err == nil {
			if err := os.WriteFile(filepath.Join(dir, "settled"), nil, 0600); err != nil {
				os.Exit(3)
			}
			os.Exit(0)
		}
		time.Sleep(time.Millisecond)
	}
	os.Exit(4)
}

type createProcessRuntime struct{ dir string }

func (r createProcessRuntime) Name() string { return "process-fixture" }
func (r createProcessRuntime) Cmd(ctx context.Context, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestContainerCreateProcessHelper$")
	cmd.Env = append(os.Environ(), "LEASH_TEST_CREATE_PROCESS="+r.dir)
	return cmd
}
func (r createProcessRuntime) Run(ctx context.Context, args ...string) error {
	_, err := r.Output(ctx, args...)
	return err
}
func (r createProcessRuntime) Output(ctx context.Context, args ...string) (string, error) {
	if len(args) == 0 {
		return "", errors.New("missing runtime verb")
	}
	switch args[0] {
	case "inspect":
		return "amd64\n", nil
	case "run":
		out, err := r.Cmd(ctx, args...).CombinedOutput()
		return string(out), err
	default:
		return "", fmt.Errorf("unexpected runtime command: %v", args)
	}
}
func (r createProcessRuntime) ExecWithInput(context.Context, string, string, io.Reader) error {
	return errors.New("unexpected exec")
}

func TestTargetCreateProcessSettlesBeforeCancellation(t *testing.T) {
	dir := t.TempDir()
	r := &runner{
		runtime: createProcessRuntime{dir: dir},
		logger:  log.New(io.Discard, "", 0),
		cfg:     config{targetContainer: "target", targetImage: "image", callerDir: dir, shareDir: dir, bootstrapTimeout: 5 * time.Second},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- r.launchTargetContainer(ctx, "SIGTERM") }()
	deadline := time.NewTimer(4 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
waiting:
	for {
		select {
		case err := <-result:
			t.Fatalf("launch exited before client started: %v", err)
		case <-deadline.C:
			t.Fatal("client did not start")
		case <-tick.C:
			if _, err := os.Stat(filepath.Join(dir, "started")); err == nil {
				break waiting
			}
		}
	}
	cancel()
	// Keep the client in flight after cancellation. The old implementation kills
	// it here, before it can acknowledge completed container creation.
	time.Sleep(100 * time.Millisecond)
	if err := os.WriteFile(filepath.Join(dir, "release"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if _, statErr := os.Stat(filepath.Join(dir, "settled")); statErr != nil {
			t.Fatalf("creation client was killed before settling: launch error=%v, marker error=%v", err, statErr)
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("launch error=%v, want cancellation after settlement", err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("launch did not finish within its bound")
	}
}

func TestTerminationSignalProcessHelper(t *testing.T) {
	dir := os.Getenv("LEASH_TEST_SIGNAL_PROCESS")
	if dir == "" {
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), terminationSignals()...)
	defer stop()
	if err := os.WriteFile(filepath.Join(dir, "ready"), nil, 0600); err != nil {
		os.Exit(2)
	}
	<-ctx.Done()
	if err := os.WriteFile(filepath.Join(dir, "canceled"), nil, 0600); err != nil {
		os.Exit(3)
	}
	os.Exit(0)
}

func TestTerminationSignalsCancelProcess(t *testing.T) {
	for _, sig := range []os.Signal{os.Interrupt, syscall.SIGTERM} {
		t.Run(sig.String(), func(t *testing.T) {
			dir := t.TempDir()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestTerminationSignalProcessHelper$")
			cmd.Env = append(os.Environ(), "LEASH_TEST_SIGNAL_PROCESS="+dir)
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			var waitErr error
			go func() { waitErr = cmd.Wait(); close(done) }()
			defer func() { cancel(); <-done }()
			timer := time.NewTicker(time.Millisecond)
			defer timer.Stop()
		ready:
			for {
				select {
				case <-done:
					t.Fatalf("signal receiver exited before readiness: %v", waitErr)
				case <-ctx.Done():
					t.Fatal("signal receiver did not start")
				case <-timer.C:
					if _, err := os.Stat(filepath.Join(dir, "ready")); err == nil {
						break ready
					}
				}
			}
			if err := cmd.Process.Signal(sig); err != nil {
				t.Fatal(err)
			}
			<-done
			if waitErr != nil {
				t.Fatalf("signal %v terminated process instead of canceling context: %v", sig, waitErr)
			}
			if _, err := os.Stat(filepath.Join(dir, "canceled")); err != nil {
				t.Fatalf("signal %v did not trigger cancellation: %v", sig, err)
			}
		})
	}
}
