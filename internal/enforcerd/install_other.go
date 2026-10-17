//go:build !linux

package enforcerd

import (
	"errors"
	"io"
)

var errLinuxOnly = errors.New("the leash enforcer daemon is Linux-only (it loads eBPF LSM programs)")

func runDaemon(string, string) error { return errLinuxOnly }
func runWorkerMain() error           { return errLinuxOnly }

// Install is Linux-only.
func Install(string, io.Writer) error { return errLinuxOnly }

// Uninstall is Linux-only.
func Uninstall(bool, io.Writer) error { return errLinuxOnly }
