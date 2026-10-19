//go:build !linux

package hardening

import "fmt"

// Apply is a no-op stub on non-Linux platforms; the native seccomp hardening is
// Linux-only (the --harden-exec path is never taken elsewhere).
func Apply(*Identity) error {
	return fmt.Errorf("process hardening is only supported on Linux")
}

// Run is never reached off Linux: Apply fails first.
func Run(argv, env []string) (int, error) {
	return 0, fmt.Errorf("process hardening is only supported on Linux")
}
