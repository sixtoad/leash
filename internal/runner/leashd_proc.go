package runner

import (
	"os"
	"os/exec"
	"syscall"
	"time"
)

// leashdStopGrace bounds how long teardown waits for native leashd to exit after
// SIGTERM before escalating to SIGKILL. It exceeds leashd's own bounded wait for
// its LSM programs to detach (lsm.lsmDetachWait) so a graceful shutdown is not
// cut short. leashdKillWait bounds the wait after SIGKILL so a wedged leashd can
// never hang teardown. Variables so tests can shorten them.
var (
	leashdStopGrace = 5 * time.Second
	leashdKillWait  = 2 * time.Second
)

// startLeashd starts the native leashd host-mode process with the same lifetime
// mechanism as the --inject-service helpers (#128): its own process group (so
// teardown signals the nsenter/unshare/sh wrapper chain and leashd together),
// a parent-death signal on Linux (so a SIGKILLed or crashed leash still takes
// leashd and its eBPF LSM down), and a reaper goroutine that Waits on it and
// closes logf. The process is recorded on the runner for stopLeashd.
func (r *runner) startLeashd(cmd *exec.Cmd, logf *os.File) error {
	proc, err := startInjectedProc("leashd", cmd, logf)
	if err != nil {
		return err
	}
	r.leashdMu.Lock()
	r.leashd = proc
	r.leashdMu.Unlock()
	return nil
}

// stopLeashd terminates native leashd: SIGTERM to its process group (leashd
// detaches its LSM programs and exits), SIGKILL after leashdStopGrace, and a
// bounded wait for the reaper. Called from the native Remove, the keepContainers
// branch of finishLifecycle, and as a deferred backstop when the run returns, so
// it is idempotent and a no-op when leashd never started (#143).
func (r *runner) stopLeashd() {
	r.leashdMu.Lock()
	p := r.leashd
	r.leashdMu.Unlock()
	if p == nil {
		return
	}
	if !p.stop(leashdStopGrace, leashdKillWait) {
		r.debugf("native leashd (pid %d) did not exit after SIGKILL", p.cmd.Process.Pid)
	}
}

// killLeashdNow SIGKILLs leashd's process group without waiting. Used on the
// forced-exit path (a second interrupt calls os.Exit, skipping the orderly
// teardown). The kernel detaches leashd's eBPF links when its FDs close.
func (r *runner) killLeashdNow() {
	r.leashdMu.Lock()
	p := r.leashd
	r.leashdMu.Unlock()
	if p != nil && !p.exited() {
		p.signalGroup(syscall.SIGKILL)
	}
}
