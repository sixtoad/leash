//go:build !linux

package runner

import (
	"os"
	"syscall"
)

// injectSysProcAttr puts the helper in its own process group so teardown can
// signal it together with anything it spawned. There is no Pdeathsig equivalent
// on darwin: if leash itself is SIGKILLed (or crashes) the helper is not
// notified, so it must detect parent death itself. Every orderly teardown path,
// including a second interrupt, still stops it explicitly.
func injectSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}

func signalInjectGroup(proc *os.Process, sig syscall.Signal) {
	if err := syscall.Kill(-proc.Pid, sig); err != nil {
		_ = proc.Signal(sig)
	}
}
