package doctor

import (
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/strongdm/leash/internal/runner"
)

// This file is the only part of the package that touches the machine. Keeping
// the probes thin and separate is what lets doctor.go stay pure: every check
// here is a lookup with no policy in it, and every decision lives there.

const procSelfStatus = "/proc/self/status"

// Capability bit positions from <linux/capability.h>. Hardcoded rather than
// pulled from a cgo header so the probe cross-compiles and unit-tests anywhere.
const (
	capNetAdminBit = 12 // CAP_NET_ADMIN
	capBPFBit      = 39 // CAP_BPF (Linux >= 5.8)
)

// Probe reads the live machine into a Host. It never fails: an unreadable
// source becomes the cautious answer (not ready) with advice, because doctor's
// job is to report a verdict, not to error out on a missing /proc.
func Probe() Host {
	lsmActive, lsmAdvice := runner.ProbeBPFLSM()
	capBPF, capNetAdmin := probeCaps(os.Geteuid())
	return Host{
		GOOS:            runtime.GOOS,
		HasSystemd:      runner.HostHasSystemd(),
		EUID:            os.Geteuid(),
		CapBPF:          capBPF,
		CapNetAdmin:     capNetAdmin,
		BPFLSMActive:    lsmActive,
		BPFLSMAdvice:    lsmAdvice,
		ContainerEngine: runner.DetectContainerEngine(),
	}
}

// probeCaps reports the effective capabilities leash cares about. When
// /proc/self/status is unavailable (non-Linux, or a locked-down /proc) it falls
// back to euid: uid 0 without a capability bounding restriction has them all,
// and a non-root process that we cannot inspect must not be assumed privileged.
func probeCaps(euid int) (capBPF, capNetAdmin bool) {
	data, err := os.ReadFile(procSelfStatus)
	if err == nil {
		if bpf, netAdmin, ok := capsFromStatus(string(data)); ok {
			return bpf, netAdmin
		}
	}
	return euid == 0, euid == 0
}

// capsFromStatus extracts the effective-capability bitmask from a
// /proc/<pid>/status dump ("CapEff:\t000001ffffffffff"). Pure, so the bit math
// is testable without /proc. ok is false when the field is absent or malformed.
func capsFromStatus(status string) (capBPF, capNetAdmin, ok bool) {
	for _, line := range strings.Split(status, "\n") {
		rest, found := strings.CutPrefix(line, "CapEff:")
		if !found {
			continue
		}
		mask, err := strconv.ParseUint(strings.TrimSpace(rest), 16, 64)
		if err != nil {
			return false, false, false
		}
		return mask&(1<<capBPFBit) != 0, mask&(1<<capNetAdminBit) != 0, true
	}
	return false, false, false
}
