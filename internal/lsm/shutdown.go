package lsm

import (
	"os"
	"os/signal"
	"sync"
	"syscall"
)

// Process-wide shutdown latch. leashd used to register SIGINT/SIGTERM
// separately in several places (LoadAndStart, each LoadAndAttachBPF event loop,
// leashd's waitForShutdown). Registering any one of them disables Go's default
// "terminate on SIGTERM" for the whole process, so a signal that arrived while
// only some of them were listening (e.g. after the attach goroutines registered
// but before LoadAndStart did, or during the bootstrap wait) was consumed by
// the early listeners and the rest blocked forever: leashd kept running after
// the launcher asked it to stop (#143). A single sticky latch fixes that: once
// any SIGINT/SIGTERM is seen, ShutdownRequested stays closed for every current
// and future waiter.
var (
	shutdownInstallOnce sync.Once
	shutdownCloseOnce   sync.Once
	shutdownCh          = make(chan struct{})
)

// InstallShutdownHandler starts listening for SIGINT/SIGTERM (idempotent). The
// first signal closes ShutdownRequested; a second one exits the process
// immediately, so a wedged graceful shutdown can always be forced.
func InstallShutdownHandler() {
	shutdownInstallOnce.Do(func() {
		sigCh := make(chan os.Signal, 2)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-sigCh
			RequestShutdown()
			<-sigCh
			os.Exit(1)
		}()
	})
}

// RequestShutdown closes ShutdownRequested (idempotent).
func RequestShutdown() {
	shutdownCloseOnce.Do(func() { close(shutdownCh) })
}

// ShutdownRequested is closed once shutdown has been requested. Call
// InstallShutdownHandler before waiting on it so signals are observed.
func ShutdownRequested() <-chan struct{} {
	return shutdownCh
}
