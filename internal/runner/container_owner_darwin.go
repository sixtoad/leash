//go:build darwin

package runner

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// ownerProcStart is a process's start time in microseconds since the epoch.
func ownerProcStart(pid int) (uint64, error) {
	if pid <= 0 {
		return 0, errors.New("invalid pid")
	}
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return 0, err
	}
	if int(kp.Proc.P_pid) != pid {
		return 0, errors.New("no such process")
	}
	tv := kp.Proc.P_starttime
	return uint64(tv.Sec)*1_000_000 + uint64(tv.Usec), nil
}

func ownerBootID() string {
	id, err := unix.Sysctl("kern.bootsessionuuid")
	if err != nil {
		return ""
	}
	return id
}

func ownerMachineID() string {
	if h, err := os.Hostname(); err == nil {
		return "host:" + h
	}
	return ""
}

// ownerPidNamespace: macOS has no PID namespaces.
func ownerPidNamespace() string { return "-" }
