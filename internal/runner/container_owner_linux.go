//go:build linux

package runner

import (
	"os"
	"strings"
)

// ownerProcStart is a process's start time in clock ticks since boot.
func ownerProcStart(pid int) (uint64, error) { return procStartTime(pid) }

func ownerBootID() string { return currentBootID() }

// ownerMachineID distinguishes this machine from others sharing an engine.
func ownerMachineID() string {
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if data, err := os.ReadFile(p); err == nil {
			if id := strings.TrimSpace(string(data)); id != "" {
				return id
			}
		}
	}
	if h, err := os.Hostname(); err == nil {
		return "host:" + h
	}
	return ""
}

// ownerPidNamespace identifies the PID namespace the owner PID lives in.
func ownerPidNamespace() string {
	ns, err := os.Readlink("/proc/self/ns/pid")
	if err != nil {
		return ""
	}
	return ns
}
