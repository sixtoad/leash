package runner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// writeForkingInjectPlugin writes a helper that forks a long-lived child (like a
// real plugin's worker), records its own and the child's PIDs, creates its socket
// path and waits. With ignoreTerm the helper and its child ignore SIGTERM, which
// forces teardown to escalate to SIGKILL.
func writeForkingInjectPlugin(t *testing.T, dir string, ignoreTerm bool) string {
	t.Helper()
	path := filepath.Join(dir, "forking-plugin.sh")
	trap := ""
	if ignoreTerm {
		trap = "trap '' TERM\n"
	}
	script := "#!/bin/sh\n" + trap +
		"sleep 300 &\n" +
		"echo $! > \"" + filepath.Join(dir, "child.pid") + "\"\n" +
		"echo $$ > \"" + filepath.Join(dir, "helper.pid") + "\"\n" +
		": > \"$LEASH_INJECT_SOCKET\"\n" +
		"while :; do wait; done\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func readPID(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		data, err := os.ReadFile(path)
		if err == nil {
			if pid, convErr := strconv.Atoi(strings.TrimSpace(string(data))); convErr == nil && pid > 0 {
				return pid
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("pid file %s never became readable: %v", path, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func processAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

// assertProcessGone waits (bounded) for pid to disappear. The direct helper is
// reaped by the runner; a forked grandchild is reaped by init/launchd, so allow
// a short settle window.
func assertProcessGone(t *testing.T, what string, pid int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for processAlive(pid) {
		if time.Now().After(deadline) {
			t.Fatalf("%s (pid %d) still running after teardown", what, pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

type spawnedHelper struct {
	r        *runner
	helper   int
	child    int
	socket   string
	cancel   context.CancelFunc
	spawnCtx context.Context
}

func spawnTeardownHelper(t *testing.T, ignoreTerm bool) spawnedHelper {
	t.Helper()
	dir := t.TempDir()
	plugin := writeForkingInjectPlugin(t, dir, ignoreTerm)
	sock := filepath.Join(dir, "helper.sock")
	r := &runner{
		cfg: config{logDir: dir},
		opts: options{injectServices: []injectService{
			{plugin: plugin, env: "HELPER_ADDR", socket: sock},
		}},
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := r.spawnInjectServicesContainer(ctx); err != nil {
		cancel()
		t.Fatalf("spawnInjectServicesContainer: %v", err)
	}
	h := spawnedHelper{
		r:        r,
		helper:   readPID(t, filepath.Join(dir, "helper.pid")),
		child:    readPID(t, filepath.Join(dir, "child.pid")),
		socket:   sock,
		cancel:   cancel,
		spawnCtx: ctx,
	}
	t.Cleanup(func() {
		cancel()
		r.killInjectedPluginsNow()
		_ = syscall.Kill(h.child, syscall.SIGKILL)
	})
	if !processAlive(h.helper) || !processAlive(h.child) {
		t.Fatal("helper should be running after spawn")
	}
	return h
}

func (h spawnedHelper) assertGone(t *testing.T) {
	t.Helper()
	assertProcessGone(t, "inject helper", h.helper)
	assertProcessGone(t, "inject helper child", h.child)
	if _, err := os.Stat(h.socket); err != nil && !os.IsNotExist(err) {
		t.Fatalf("stat socket: %v", err)
	}
}

func shortInjectGrace(t *testing.T) {
	t.Helper()
	oldGrace, oldKill := injectStopGrace, injectKillWait
	injectStopGrace, injectKillWait = 300*time.Millisecond, 2*time.Second
	t.Cleanup(func() { injectStopGrace, injectKillWait = oldGrace, oldKill })
}

// No --inject-service helper (nor anything it forked) may survive any teardown
// path (#128).
func TestInjectedHelpersReapedOnEveryTeardownPath(t *testing.T) {
	shortInjectGrace(t)

	t.Run("normal exit", func(t *testing.T) {
		h := spawnTeardownHelper(t, false)
		if err := h.r.finishLifecycle(context.Background(), 0, nil); err != nil {
			t.Fatalf("finishLifecycle: %v", err)
		}
		h.assertGone(t)
	})

	t.Run("workload nonzero exit", func(t *testing.T) {
		h := spawnTeardownHelper(t, false)
		err := h.r.finishLifecycle(context.Background(), 7, nil)
		var exitErr *ExitCodeError
		if !errors.As(err, &exitErr) || exitErr.code != 7 {
			t.Fatalf("want exit code 7, got %v", err)
		}
		h.assertGone(t)
	})

	t.Run("workload error", func(t *testing.T) {
		h := spawnTeardownHelper(t, false)
		runErr := errors.New("exec failed")
		if err := h.r.finishLifecycle(context.Background(), 0, runErr); !errors.Is(err, runErr) {
			t.Fatalf("want runErr, got %v", err)
		}
		h.assertGone(t)
	})

	t.Run("context cancelled (SIGINT/SIGTERM handler)", func(t *testing.T) {
		// Run's signal handler cancels the run context; that path must still
		// tear the helper down rather than SIGKILL only its direct child.
		h := spawnTeardownHelper(t, false)
		h.cancel()
		_ = h.r.finishLifecycle(h.spawnCtx, 0, context.Canceled)
		h.assertGone(t)
	})

	t.Run("keep containers", func(t *testing.T) {
		h := spawnTeardownHelper(t, false)
		h.r.keepContainers = true
		_ = h.r.finishLifecycle(context.Background(), 0, errors.New("interactive exec failed"))
		h.assertGone(t)
	})

	t.Run("forced exit (second signal)", func(t *testing.T) {
		h := spawnTeardownHelper(t, true)
		h.r.killInjectedPluginsNow()
		h.assertGone(t)
	})

	t.Run("SIGTERM ignored escalates to SIGKILL", func(t *testing.T) {
		h := spawnTeardownHelper(t, true)
		start := time.Now()
		h.r.teardownInjectedPlugins()
		h.assertGone(t)
		if elapsed := time.Since(start); elapsed < injectStopGrace {
			t.Fatalf("teardown returned in %v, before the SIGTERM grace %v", elapsed, injectStopGrace)
		}
	})

	t.Run("idempotent", func(t *testing.T) {
		h := spawnTeardownHelper(t, false)
		h.r.teardownInjectedPlugins()
		h.r.teardownInjectedPlugins()
		h.r.killInjectedPluginsNow()
		h.assertGone(t)
	})
}

// A helper that dies before creating its socket fails the readiness wait fast
// (instead of the full 2s poll) and is reaped.
func TestSpawnInjectServiceFailsFastWhenHelperExits(t *testing.T) {
	dir := t.TempDir()
	plugin := filepath.Join(dir, "dies.sh")
	if err := os.WriteFile(plugin, []byte("#!/bin/sh\nexit 3\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	r := &runner{cfg: config{logDir: dir}, opts: options{injectServices: []injectService{
		{plugin: plugin, env: "HELPER_ADDR", socket: filepath.Join(dir, "x.sock")},
	}}}
	err := r.spawnInjectServicesContainer(context.Background())
	if err == nil || !strings.Contains(err.Error(), "exited before creating socket") {
		t.Fatalf("want early-exit error, got %v", err)
	}
	r.teardownInjectedPlugins()
}
