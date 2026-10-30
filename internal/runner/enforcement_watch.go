package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Fail closed when enforcement dies mid-run: once the workload has been
// released, leashd (native) or the leash sidecar running it (container) is the
// only thing enforcing — the eBPF LSM links close with leashd's FDs and the
// proxy is gone with it. If it exits while the workload still runs, the
// workload is killed at once and the run fails with leashd's reason, instead of
// the workload carrying on unenforced.

// enforcementLost records why the workload was killed, for finishLifecycle.
type enforcementLost struct {
	mu  sync.Mutex
	err error
}

func (l *enforcementLost) set(err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err == nil {
		l.err = err
	}
}

func (l *enforcementLost) get() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.err
}

// enforcementWatchInterval is the container watch's fallback polling interval
// (it normally blocks in `<runtime> wait`). Variable for tests.
var enforcementWatchInterval = 500 * time.Millisecond

// watchContainerEnforcement stops the workload if the leash container exits
// while it runs. In a daemon-enforced (rootless) run leashd exits when
// the daemon reports the session lost; in a rootful run leashd itself attached
// the LSM, so its exit leaves the workload unenforced either way. The returned
// channel is closed once the watch goroutine has returned.
func (r *runner) watchContainerEnforcement(ctx context.Context) <-chan struct{} {
	// Read the interval before starting the goroutine, so the watch does not
	// touch package state after its caller has moved on.
	interval := enforcementWatchInterval
	done := make(chan struct{})
	go func() {
		defer close(done)
		// Block until the sidecar stops (prompt); fall back to polling if the
		// runtime's `wait` is unavailable or returns early.
		_, _ = r.rt().Output(ctx, "wait", r.cfg.leashContainer)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			if ctx.Err() != nil || r.workloadFinished.Load() {
				return
			}
			state := r.containerSummary(ctx, r.cfg.leashContainer)
			if isTerminalStatus(state) && !r.workloadFinished.Load() && ctx.Err() == nil {
				r.containerEnforcementLost(ctx, state)
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
	return done
}

func (r *runner) containerEnforcementLost(ctx context.Context, state string) {
	killCtx, cancel := context.WithTimeout(cleanupContext(ctx), 10*time.Second)
	defer cancel()

	what := "kernel enforcement is no longer guaranteed"
	if r.enforcerSocket != "" {
		what = "kernel enforcement through the enforcer daemon is no longer guaranteed"
	}
	msg := fmt.Sprintf("the leash container stopped (%s) while the workload was running; %s, so the workload was stopped (fail-closed)", state, what)
	// Collect the sidecar's logs before the kill: once the workload exits the
	// runner tears the containers down, logs included. The reason is recorded
	// before the kill too, so the run's result can never miss it.
	diagCtx, diagCancel := context.WithTimeout(killCtx, 2*time.Second)
	msg += r.leashContainerDiagnostics(diagCtx, state)
	diagCancel()
	r.enforcementLost.set(errors.New(msg))
	fmt.Fprintf(os.Stderr, "leash: FATAL: %s\n", firstLine(msg))
	_ = r.rt().Run(killCtx, "kill", r.cfg.targetContainer)
}

// leashContainerDiagnostics is leashd's FATAL reason and a bounded,
// credential-redacted log tail from the sidecar (the #136/#137 helpers).
func (r *runner) leashContainerDiagnostics(ctx context.Context, state string) string {
	if statusCategory(state) == "missing" {
		return "; the leash container was removed, so no logs are available"
	}
	raw, err := r.rt().Output(ctx, "logs", "--tail", "200", r.cfg.leashContainer)
	if err != nil {
		return ""
	}
	var b strings.Builder
	if fatal := lastFatalLine(raw); fatal != "" {
		b.WriteString(": leashd: " + fatal)
	}
	if tail := sanitizeContainerLogs(raw); tail != "" {
		fmt.Fprintf(&b, "\nRecent logs (%s):\n%s", r.cfg.leashContainer, indentLines(tail, "  "))
	}
	return b.String()
}

// watchNativeEnforcement kills the box if native leashd exits while the
// workload runs. The returned channel is closed once the watch has returned
// (at once when there is no leashd to watch).
func (n nativeLauncher) watchNativeEnforcement(ctx context.Context) <-chan struct{} {
	done := make(chan struct{})
	n.r.leashdMu.Lock()
	p := n.r.leashd
	n.r.leashdMu.Unlock()
	if p == nil {
		close(done)
		return done
	}
	cgroupPath := n.r.cgroupPath
	go func() {
		defer close(done)
		select {
		case <-ctx.Done():
			return
		case <-p.done:
		}
		if n.r.workloadFinished.Load() || ctx.Err() != nil {
			return
		}
		msg := "native leashd exited while the workload was running; neither the eBPF LSM nor the L7 proxy enforces any more, so the workload was killed (fail-closed)"
		logPath := n.leashdLogPath()
		if detail := leashdFailureReason(logPath); detail != "" {
			msg += ": leashd: " + detail
		} else if code := p.exitDescription(); code != "" {
			msg += " (leashd " + code + ")"
		}
		if tail := leashdLogTail(logPath); tail != "" {
			msg += ".\nRecent leashd log:\n" + indentLines(tail, "  ")
		}
		msg += "\nSee " + logPath
		// Record the reason before the kill so the run's result can never
		// miss it (the workload's exit races this goroutine otherwise).
		n.r.enforcementLost.set(errors.New(msg))
		if !killCgroup(cgroupPath) {
			killCtx, cancel := context.WithTimeout(cleanupContext(ctx), 5*time.Second)
			_, _ = hostOutput(killCtx, "systemctl", append(n.userFlag(), "kill", "--signal=SIGKILL", n.unitName())...)
			cancel()
		}
		fmt.Fprintf(os.Stderr, "leash: FATAL: %s\n", firstLine(msg))
	}()
	return done
}

// killCgroup SIGKILLs every process in a cgroup-v2 cgroup: cgroup.kill (5.14+)
// in one atomic step, else each PID in cgroup.procs. Variable for tests.
var killCgroup = func(cgroupPath string) bool {
	if strings.TrimSpace(cgroupPath) == "" {
		return false
	}
	if err := os.WriteFile(filepath.Join(cgroupPath, "cgroup.kill"), []byte("1"), 0); err == nil {
		return true
	}
	data, err := os.ReadFile(filepath.Join(cgroupPath, "cgroup.procs"))
	if err != nil {
		return false
	}
	any := false
	for _, f := range strings.Fields(string(data)) {
		if pid, err := strconv.Atoi(f); err == nil && pid > 0 {
			if syscall.Kill(pid, syscall.SIGKILL) == nil {
				any = true
			}
		}
	}
	return any
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
