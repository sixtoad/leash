package runner

import (
	"os"
	"os/exec"
	"syscall"
	"time"
)

// injectStopGrace bounds how long teardown waits for an --inject-service helper
// to exit after SIGTERM before escalating to SIGKILL. injectKillWait bounds the
// wait after SIGKILL so a wedged (e.g. D-state) helper can never hang teardown.
// Variables so tests can shorten them.
var (
	injectStopGrace = 5 * time.Second
	injectKillWait  = 2 * time.Second
)

// injectedProc is one running --inject-service helper. Its lifetime is owned by
// the runner, not by any context: the helper is started with exec.Command (not
// CommandContext) because a context-driven SIGKILL of the direct child (often
// `runuser`) would orphan the real plugin underneath it. Instead every teardown
// path goes through stop(), which signals the helper's whole process group.
type injectedProc struct {
	name string
	cmd  *exec.Cmd
	// done is closed once the reaper goroutine's cmd.Wait returns (the direct
	// child is reaped and its log file closed).
	done chan struct{}
}

// startInjectedProc starts cmd in its own process group (plus, on Linux, with a
// parent-death signal) and starts a reaper that Waits on it and closes logf.
func startInjectedProc(name string, cmd *exec.Cmd, logf *os.File) (*injectedProc, error) {
	cmd.SysProcAttr = injectSysProcAttr()
	if err := cmd.Start(); err != nil {
		if logf != nil {
			_ = logf.Close()
		}
		return nil, err
	}
	p := &injectedProc{name: name, cmd: cmd, done: make(chan struct{})}
	go func() {
		_ = cmd.Wait()
		if logf != nil {
			_ = logf.Close()
		}
		close(p.done)
	}()
	return p, nil
}

func (p *injectedProc) exited() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

// signalGroup delivers sig to the helper's process group (so a `runuser` wrapper
// and the plugin it spawned, plus any children the plugin forked, all receive it).
func (p *injectedProc) signalGroup(sig syscall.Signal) {
	if p == nil || p.cmd == nil || p.cmd.Process == nil {
		return
	}
	signalInjectGroup(p.cmd.Process, sig)
}

// stop terminates the helper: SIGTERM to the group, wait up to grace for the
// direct child to be reaped, then SIGKILL the group (also sweeping any group
// member that ignored SIGTERM) and wait a further bounded interval. It returns
// whether the direct child was reaped. Safe to call more than once.
func (p *injectedProc) stop(grace, killWait time.Duration) bool {
	if p == nil || p.cmd == nil || p.cmd.Process == nil {
		return true
	}
	if !p.exited() {
		p.signalGroup(syscall.SIGTERM)
		select {
		case <-p.done:
		case <-time.After(grace):
		}
	}
	// Sweep stragglers in the group (a plugin child that ignored SIGTERM, or the
	// leader itself if it outlived the grace). ESRCH once the group is empty is
	// ignored by signalInjectGroup.
	p.signalGroup(syscall.SIGKILL)
	select {
	case <-p.done:
		return true
	case <-time.After(killWait):
		return false
	}
}
