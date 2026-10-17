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
	"sync/atomic"
	"testing"
	"time"
)

// flipRuntime is a fake container runtime whose leash container stops after a
// delay; it records the commands Run receives (the kill of the target).
type flipRuntime struct {
	stopAt time.Time
	logs   string
	mu     sync.Mutex
	runs   []string
}

func (f *flipRuntime) Run(ctx context.Context, args ...string) error {
	f.mu.Lock()
	f.runs = append(f.runs, strings.Join(args, " "))
	f.mu.Unlock()
	return nil
}

func (f *flipRuntime) Output(ctx context.Context, args ...string) (string, error) {
	switch args[0] {
	case "inspect":
		if args[len(args)-1] == "agent-leash" && time.Now().After(f.stopAt) {
			return "exited 1", nil
		}
		return "running 0", nil
	case "logs":
		return f.logs, nil
	}
	return "", nil // "wait" returns at once: the watch falls back to polling
}

func (f *flipRuntime) ExecWithInput(ctx context.Context, container, shellCommand string, input io.Reader) error {
	return nil
}
func (f *flipRuntime) Cmd(ctx context.Context, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, "true")
}
func (f *flipRuntime) Name() string { return "docker" }

func (f *flipRuntime) killed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.runs {
		if r == "kill agent" {
			return true
		}
	}
	return false
}

func fastWatch(t *testing.T) {
	t.Helper()
	orig := enforcementWatchInterval
	enforcementWatchInterval = 20 * time.Millisecond
	t.Cleanup(func() { enforcementWatchInterval = orig })
}

// waitWatchDone joins a watch goroutine, so it never outlives the test (and its
// restores of package-level stubs).
func waitWatchDone(t *testing.T, done <-chan struct{}, d time.Duration) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatal("watch goroutine did not return")
	}
}

func containerWatchRunner(rt *flipRuntime) *runner {
	r := &runner{runtime: rt, logger: log.New(io.Discard, "", 0)}
	r.cfg.targetContainer = "agent"
	r.cfg.leashContainer = "agent-leash"
	return r
}

// Rootful container: the leash sidecar (leashd) dying mid-run kills the
// workload's container and fails the run with leashd's FATAL reason — not only
// in enforcer-daemon runs.
func TestContainerWatchKillsWorkloadWhenLeashdDies(t *testing.T) {
	fastWatch(t)
	rt := &flipRuntime{stopAt: time.Now().Add(100 * time.Millisecond),
		logs: "noise\nleash: FATAL: lsm: ring buffer reader died\n"}
	r := containerWatchRunner(rt)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := r.watchContainerEnforcement(ctx)

	deadline := time.Now().Add(2 * time.Second)
	for !rt.killed() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !rt.killed() {
		t.Fatal("workload container not killed after the leash container stopped")
	}
	for r.enforcementLost.get() == nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	// The watch returns after the kill; join it before the stubs are restored.
	waitWatchDone(t, done, 2*time.Second)
	err := r.finishLifecycle(ctx, 137, nil)
	if err == nil || !strings.Contains(err.Error(), "ring buffer reader died") || !strings.Contains(err.Error(), "fail-closed") {
		t.Fatalf("run must fail with leashd's reason, got %v", err)
	}
}

// A normal end of the workload is not reported as an enforcement loss.
func TestContainerWatchIgnoresNormalTeardown(t *testing.T) {
	fastWatch(t)
	rt := &flipRuntime{stopAt: time.Now().Add(100 * time.Millisecond)}
	r := containerWatchRunner(rt)
	r.workloadFinished.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := r.watchContainerEnforcement(ctx)
	// Past the leash container's stop: a watch that still ran would see it.
	time.Sleep(300 * time.Millisecond)
	// The watch must have ended on its own (workload finished), without the
	// context being canceled.
	waitWatchDone(t, done, 2*time.Second)
	if rt.killed() || r.enforcementLost.get() != nil {
		t.Fatal("teardown after the workload finished was treated as enforcement loss")
	}
}

func startFakeNativeLeashd(t *testing.T, r *runner, script string) {
	t.Helper()
	n := nativeLauncher{r: r}
	logf, err := os.Create(n.leashdLogPath())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(n.leashdLogPath()) })
	cmd := exec.Command("sh", "-c", script)
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := r.startLeashd(cmd, logf); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.killLeashdNow)
}

// Native: leashd crashing mid-run kills the box's cgroup within ~1s and fails
// the run with leashd's FATAL line.
func TestNativeWatchKillsWorkloadWhenLeashdDies(t *testing.T) {
	var killedAt atomic.Int64
	var killedPath atomic.Value
	var reasonBeforeKill atomic.Bool
	r := &runner{runtime: nativeRuntime{}, logger: log.New(io.Discard, "", 0)}
	orig := killCgroup
	killCgroup = func(p string) bool {
		// The workload's exit races the watch: the reason must already be
		// recorded when the kill happens, or the run could end without it.
		reasonBeforeKill.Store(r.enforcementLost.get() != nil)
		killedPath.Store(p)
		killedAt.Store(time.Now().UnixNano())
		return true
	}
	t.Cleanup(func() { killCgroup = orig })

	r.cfg.targetContainer = "watch-" + filepath.Base(t.TempDir())
	r.cgroupPath = "/sys/fs/cgroup/system.slice/fake.service"
	startFakeNativeLeashd(t, r, `echo "leash: FATAL: proxy: listener closed"; sleep 0.2; exit 1`)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := nativeLauncher{r: r}.watchNativeEnforcement(ctx)

	r.waitLeashdExitForTest(t, 2*time.Second)
	exited := time.Now()
	deadline := exited.Add(time.Second)
	for r.enforcementLost.get() == nil && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	waitWatchDone(t, done, 2*time.Second)
	if killedAt.Load() == 0 {
		t.Fatal("box cgroup not killed after leashd exited")
	}
	if !reasonBeforeKill.Load() {
		t.Fatal("the reason must be recorded before the workload is killed")
	}
	if got := killedPath.Load(); got != r.cgroupPath {
		t.Fatalf("killed %v, want %s", got, r.cgroupPath)
	}
	if d := time.Unix(0, killedAt.Load()).Sub(exited); d > time.Second {
		t.Fatalf("workload killed %s after leashd exit; want within ~1s", d)
	}
	err := r.finishLifecycle(ctx, 137, nil)
	if err == nil || !strings.Contains(err.Error(), "proxy: listener closed") {
		t.Fatalf("run must fail with leashd's reason, got %v", err)
	}
}

// Native: leashd stopping during normal teardown (workload finished) is not a loss.
func TestNativeWatchIgnoresNormalTeardown(t *testing.T) {
	var killed atomic.Bool
	orig := killCgroup
	killCgroup = func(string) bool { killed.Store(true); return true }
	t.Cleanup(func() { killCgroup = orig })

	r := &runner{runtime: nativeRuntime{}, logger: log.New(io.Discard, "", 0)}
	r.cfg.targetContainer = "watch2-" + filepath.Base(t.TempDir())
	startFakeNativeLeashd(t, r, `sleep 0.2; exit 0`)
	r.workloadFinished.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := nativeLauncher{r: r}.watchNativeEnforcement(ctx)
	r.waitLeashdExitForTest(t, 2*time.Second)
	waitWatchDone(t, done, 2*time.Second)
	if killed.Load() || r.enforcementLost.get() != nil {
		t.Fatal("normal teardown treated as enforcement loss")
	}
}

func (r *runner) waitLeashdExitForTest(t *testing.T, d time.Duration) {
	t.Helper()
	r.leashdMu.Lock()
	p := r.leashd
	r.leashdMu.Unlock()
	select {
	case <-p.done:
	case <-time.After(d):
		t.Fatal("fake leashd did not exit")
	}
}
