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

// procSelfStatus is a var, not a const, so the unreadable-source path (CAP-3's
// "never fabricate capabilities") can be exercised without root or a container.
var procSelfStatus = "/proc/self/status"

// Capability bit positions from <linux/capability.h>. Hardcoded rather than
// pulled from a cgo header so the probe cross-compiles and unit-tests anywhere.
const (
	capNetAdminBit = 12 // CAP_NET_ADMIN
	capBPFBit      = 39 // CAP_BPF (Linux >= 5.8)
)

// Probe reads the live machine into a Host. It never fails: an unreadable
// source becomes the cautious answer (unknown, and therefore not ready) with
// advice, because doctor's job is to report a verdict, not to error out on a
// missing /proc.
func Probe() Host {
	lsm, lsmAdvice := runner.ProbeBPFLSM()
	capBPF, capNetAdmin, capsKnown := probeCaps()
	engine, engineErr := runner.DetectContainerEngine()

	h := Host{
		GOOS:            runtime.GOOS,
		HasSystemd:      runner.HostHasSystemd(),
		EUID:            os.Geteuid(),
		CapBPF:          capBPF,
		CapNetAdmin:     capNetAdmin,
		CapsKnown:       capsKnown,
		BPFLSM:          lsm,
		BPFLSMAdvice:    lsmAdvice,
		ContainerEngine: engine,
	}
	if engineErr != nil {
		h.ContainerEngineError = engineErr.Error()
	}
	return h
}

// probeCaps reports the effective capabilities leash cares about, and whether
// they could be observed at all.
//
// It never falls back to euid. "Root, so it must hold CAP_BPF" is a guess, and
// it is wrong in exactly the environments where it would be consulted: on
// darwin there is no such capability, and in a container with a masked or
// dropped-capability /proc a root process can be missing both. Inventing
// capabilities is how a report claims Layer 1 that the kernel will refuse to
// attach, so an unreadable source is reported as unknown-and-not-ready.
func probeCaps() (capBPF, capNetAdmin, known bool) {
	data, err := os.ReadFile(procSelfStatus)
	if err != nil {
		return false, false, false
	}
	return capsFromStatus(string(data))
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
