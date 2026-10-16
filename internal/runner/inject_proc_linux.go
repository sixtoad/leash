//go:build linux

package runner

import (
	"os"
	"syscall"
)

// injectSysProcAttr puts the helper in its own process group (so teardown can
// signal the wrapper and the plugin together) and sets Pdeathsig so a crashed or
// SIGKILLed leash still takes the helper down. Pdeathsig fires when the OS
// thread that forked the child exits; the Go runtime does not retire ordinary
// threads, so in practice it tracks the leash process. When the helper is
// spawned via `runuser`, the parent-death SIGTERM lands on runuser, which
// forwards it to the plugin.
func injectSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGTERM}
}

func signalInjectGroup(proc *os.Process, sig syscall.Signal) {
	if err := syscall.Kill(-proc.Pid, sig); err != nil {
		_ = proc.Signal(sig)
	}
}
