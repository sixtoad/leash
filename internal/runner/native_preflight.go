package runner

import (
	"fmt"
	"os"
	"os/exec"
)

// When --runtime native is selected (the default on Linux), enforcement runs
// leashd as a host process against a systemd-scope cgroup + a named network
// namespace. That requires Linux, systemd, and root — root creates the netns and
// attaches the eBPF LSM. This preflight is the runtime-selection analog of the
// eBPF-LSM preflight (lsm_preflight.go) and the macOS ES/NE preflight: detect the
// prerequisite and surface it with advice.
//
// Spirit: leash fails fatally only when NO enforcement boundary can survive.
// Every non-viable native state here is a no-boundary case — without root there
// is neither an LSM (Layer 1) nor a netns for the proxy (Layer 2) — so they are
// fatal with actionable guidance. Native never silently falls back to docker;
// docker/podman are opt-in via --runtime.

type nativeViability int

const (
	nativeViable    nativeViability = iota // Linux + systemd + root — native can enforce
	nativeNotLinux                         // the container-free Linux backend does not apply
	nativeNoSystemd                        // systemd-run/systemctl unavailable
	nativeNeedsRoot                        // no root: can't create the netns or attach the LSM
)

// classifyNativeRuntime is pure so the viability policy is unit-testable without
// a real host.
func classifyNativeRuntime(goosName string, hasSystemd bool, euid int) nativeViability {
	if goosName != "linux" {
		return nativeNotLinux
	}
	if !hasSystemd {
		return nativeNoSystemd
	}
	if euid != 0 {
		return nativeNeedsRoot
	}
	return nativeViable
}

func nativeRuntimeAdvice(v nativeViability) string {
	switch v {
	case nativeNotLinux:
		return `the native (container-free) runtime requires Linux.
Use --runtime docker (or --runtime podman); on macOS, native enforcement is the separate --darwin mode.`
	case nativeNoSystemd:
		return `the native runtime requires systemd (systemd-run/systemctl) to build the cgroup box.
Use --runtime docker (or --runtime podman).`
	case nativeNeedsRoot:
		return `native enforcement requires root: it creates the workload's network namespace and attaches the eBPF LSM.
Re-run with sudo, or use --runtime docker (or --runtime podman) for a rootless container-based run.`
	default:
		return ""
	}
}

// decideNativeRuntime returns nil when native can enforce, else a fatal error
// (no boundary survives). Pure, mirroring decideBPFLSM.
func decideNativeRuntime(v nativeViability) error {
	if v == nativeViable {
		return nil
	}
	return fmt.Errorf("native runtime is unavailable, so leash will not start (native never falls back to docker — pass --runtime docker to opt in).\n%s", nativeRuntimeAdvice(v))
}

func (r *runner) preflightNativeRuntime() error {
	if !r.usingNativeRuntime() {
		return nil
	}
	hasSystemd := hostHasSystemd()
	return decideNativeRuntime(classifyNativeRuntime(goos(), hasSystemd, os.Geteuid()))
}

func hostHasSystemd() bool {
	if _, err := exec.LookPath("systemd-run"); err != nil {
		return false
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false
	}
	return true
}
