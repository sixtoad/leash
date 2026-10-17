package runner

import (
	"context"
	"errors"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// writeFakeLeashd writes a stand-in for `leash --daemon --host`: it records its
// PID, forks a long-lived child (standing in for anything leashd spawned) and
// waits. With ignoreTerm it ignores SIGTERM (a wedged shutdown), forcing the
// SIGKILL escalation; otherwise its TERM trap records that it got the graceful
// signal first and exits, like leashd detaching its LSM programs.
func writeFakeLeashd(t *testing.T, dir string, ignoreTerm bool) string {
	t.Helper()
	path := filepath.Join(dir, "fake-leashd.sh")
	trap := "trap ': > \"" + filepath.Join(dir, "got-term") + "\"; exit 0' TERM\n"
	if ignoreTerm {
		trap = "trap '' TERM\n"
	}
	script := "#!/bin/sh\n" + trap +
		"sleep 300 &\n" +
		"echo $! > \"" + filepath.Join(dir, "child.pid") + "\"\n" +
		"echo $$ > \"" + filepath.Join(dir, "leashd.pid") + "\"\n" +
		"while :; do wait; done\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

type spawnedLeashd struct {
	r      *runner
	dir    string
	leashd int
	child  int
}

// spawnFakeLeashd starts a fake leashd through the native launcher's lifetime
// mechanism (startLeashd), wrapped in `sh -c 'exec ...'` like the real
// nsenter/unshare/sh chain, on a runner that selects the native backend.
func spawnFakeLeashd(t *testing.T, ignoreTerm bool) spawnedLeashd {
	t.Helper()
	dir := t.TempDir()
	fake := writeFakeLeashd(t, dir, ignoreTerm)
	r := &runner{
		runtime: nativeRuntime{},
		logger:  log.New(io.Discard, "", 0),
	}
	r.cfg.targetContainer = "leashd-teardown-test"
	cmd := exec.Command("sh", "-c", "exec "+quoteShellArg(fake))
	if err := r.startLeashd(cmd, nil); err != nil {
		t.Fatalf("startLeashd: %v", err)
	}
	s := spawnedLeashd{
		r:      r,
		dir:    dir,
		leashd: readPID(t, filepath.Join(dir, "leashd.pid")),
		child:  readPID(t, filepath.Join(dir, "child.pid")),
	}
	t.Cleanup(func() {
		r.killLeashdNow()
		_ = syscall.Kill(s.child, syscall.SIGKILL)
	})
	if !processAlive(s.leashd) || !processAlive(s.child) {
		t.Fatal("fake leashd should be running after start")
	}
	return s
}

func (s spawnedLeashd) assertGone(t *testing.T) {
	t.Helper()
	assertProcessGone(t, "fake leashd", s.leashd)
	assertProcessGone(t, "fake leashd child", s.child)
	if !s.r.leashd.exited() {
		t.Fatal("fake leashd was not reaped")
	}
}

func (s spawnedLeashd) assertGraceful(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(s.dir, "got-term")); err != nil {
		t.Fatalf("leashd should get SIGTERM (graceful LSM detach) before any SIGKILL: %v", err)
	}
}

// stubHostOutput keeps the native Remove from touching real netns/iptables/
// systemd state.
func stubHostOutput(t *testing.T) {
	t.Helper()
	old := hostOutput
	hostOutput = func(context.Context, string, ...string) (string, error) { return "", nil }
	t.Cleanup(func() { hostOutput = old })
}

func shortLeashdGrace(t *testing.T) {
	t.Helper()
	oldGrace, oldKill := leashdStopGrace, leashdKillWait
	leashdStopGrace, leashdKillWait = 300*time.Millisecond, 2*time.Second
	t.Cleanup(func() { leashdStopGrace, leashdKillWait = oldGrace, oldKill })
}

// Native leashd (and anything it forked) must not survive any teardown path,
// and must get SIGTERM first so it can detach its eBPF LSM programs (#143).
func TestNativeLeashdReapedOnEveryTeardownPath(t *testing.T) {
	shortLeashdGrace(t)
	stubHostOutput(t)

	t.Run("normal exit", func(t *testing.T) {
		s := spawnFakeLeashd(t, false)
		if err := s.r.finishLifecycle(context.Background(), 0, nil); err != nil {
			t.Fatalf("finishLifecycle: %v", err)
		}
		s.assertGone(t)
		s.assertGraceful(t)
	})

	t.Run("workload nonzero exit", func(t *testing.T) {
		s := spawnFakeLeashd(t, false)
		err := s.r.finishLifecycle(context.Background(), 7, nil)
		var exitErr *ExitCodeError
		if !errors.As(err, &exitErr) || exitErr.code != 7 {
			t.Fatalf("want exit code 7, got %v", err)
		}
		s.assertGone(t)
		s.assertGraceful(t)
	})

	t.Run("workload error", func(t *testing.T) {
		s := spawnFakeLeashd(t, false)
		runErr := errors.New("exec failed")
		if err := s.r.finishLifecycle(context.Background(), 0, runErr); !errors.Is(err, runErr) {
			t.Fatalf("want runErr, got %v", err)
		}
		s.assertGone(t)
	})

	t.Run("context cancelled (SIGINT/SIGTERM handler)", func(t *testing.T) {
		// Run's signal handler cancels the run context. leashd is no longer
		// bound to that context (its kill raced os.Exit); teardown must still
		// stop it synchronously.
		s := spawnFakeLeashd(t, false)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_ = s.r.finishLifecycle(ctx, 0, context.Canceled)
		s.assertGone(t)
		s.assertGraceful(t)
	})

	t.Run("readiness failure", func(t *testing.T) {
		s := spawnFakeLeashd(t, false)
		s.r.cfg.shareDir = t.TempDir() // never gets the enforcement-ready marker
		s.r.cfg.bootstrapTimeout = 2 * caCertWaitDelay
		// The fail-closed default: notReady reads cfg.requireLSM (resolved
		// from the flags by enforcement.ResolveRequireLSM), not opts. Setting
		// opts left the verdict on the --allow-proxy-only path, so as root
		// (Layer 2 active) WaitReady degraded and returned nil (#180).
		s.r.cfg.requireLSM = true
		err := (nativeLauncher{r: s.r}).WaitReady(context.Background())
		if err == nil {
			t.Fatal("WaitReady should fail closed when enforcement never confirms")
		}
		// startContainers' handling of a WaitReady error.
		_ = s.r.finishLifecycle(context.Background(), 0, err)
		s.assertGone(t)
	})

	t.Run("keep containers", func(t *testing.T) {
		s := spawnFakeLeashd(t, false)
		s.r.keepContainers = true
		_ = s.r.finishLifecycle(context.Background(), 0, errors.New("interactive exec failed"))
		s.assertGone(t)
	})

	t.Run("early return backstop", func(t *testing.T) {
		// execute defers stopLeashd for paths that return without
		// finishLifecycle.
		s := spawnFakeLeashd(t, false)
		s.r.stopLeashd()
		s.assertGone(t)
		s.assertGraceful(t)
	})

	t.Run("forced exit (second signal)", func(t *testing.T) {
		s := spawnFakeLeashd(t, true)
		s.r.killLeashdNow()
		s.assertGone(t)
	})

	t.Run("SIGTERM ignored escalates to SIGKILL", func(t *testing.T) {
		s := spawnFakeLeashd(t, true)
		start := time.Now()
		s.r.stopLeashd()
		s.assertGone(t)
		if elapsed := time.Since(start); elapsed < leashdStopGrace {
			t.Fatalf("teardown returned in %v, before the SIGTERM grace %v", elapsed, leashdStopGrace)
		}
	})

	t.Run("idempotent", func(t *testing.T) {
		s := spawnFakeLeashd(t, false)
		s.r.stopLeashd()
		s.r.stopLeashd()
		s.r.killLeashdNow()
		_ = (nativeLauncher{r: s.r}).Remove(context.Background())
		s.assertGone(t)
	})
}

// Teardown with no leashd (non-native backend, or a failure before
// StartEnforcement) is a no-op.
func TestStopLeashdWithoutLeashd(t *testing.T) {
	r := &runner{}
	r.stopLeashd()
	r.killLeashdNow()
}

// A leashd that dies on its own is seen by WaitReady's fast path.
func TestNativeLeashdDiedAfterRealExit(t *testing.T) {
	r := &runner{}
	if err := r.startLeashd(exec.Command("sh", "-c", "exit 1"), nil); err != nil {
		t.Fatal(err)
	}
	n := nativeLauncher{r: r}
	deadline := time.Now().Add(5 * time.Second)
	for !n.leashdDied() {
		if time.Now().After(deadline) {
			t.Fatal("leashdDied never reported the exited leashd")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
