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

// procSelfUIDMap is a var for the same reason as procSelfStatus: the
// user-namespace path has to be testable without actually being in one.
var procSelfUIDMap = "/proc/self/uid_map"

// initialUIDMap is what /proc/self/uid_map contains in the initial user
// namespace: the whole uid range mapped identically. Any other content means
// the process is in a mapped (non-initial) namespace.
const initialUIDMapFullRange = 4294967295

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
		CapsNamespaced:  inUserNamespace(),
		BPFLSM:          lsm,
		BPFLSMAdvice:    lsmAdvice,
		ContainerEngine: engine,
		// Read here, decided in doctor.go. The engine client resolves its
		// daemon from this the same way `leash run` does, so a set DOCKER_HOST
		// means the kernel just probed is not the one the workload will get.
		DockerHost:     strings.TrimSpace(os.Getenv("DOCKER_HOST")),
		DefaultRuntime: runner.DefaultRuntimeName(),
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
	// A capability set read inside a user namespace describes what this process
	// holds *against that namespace*, not against the host. CAP_BPF held in a
	// user namespace does not permit loading a BPF_PROG_TYPE_LSM program, which
	// is exactly what Layer 1 needs — so reporting those bits as held would
	// claim more capability than leash can deliver. Treat them as unknown.
	if inUserNamespace() {
		return false, false, false
	}
	data, err := os.ReadFile(procSelfStatus)
	if err != nil {
		return false, false, false
	}
	return capsFromStatus(string(data))
}

// inUserNamespace reports whether this process is in a non-initial user
// namespace. The initial namespace maps the entire uid range identically
// ("0 0 4294967295"); anything else is a mapped namespace. An unreadable or
// unparseable map is treated as namespaced — the cautious direction, since the
// only cost is reporting capabilities as unknown rather than claiming them.
func inUserNamespace() bool {
	data, err := os.ReadFile(procSelfUIDMap)
	if err != nil {
		return true
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 1 {
		return true // more than one range is only possible in a mapped namespace
	}
	f := strings.Fields(lines[0])
	if len(f) != 3 {
		return true
	}
	inside, outside, count := f[0], f[1], f[2]
	return !(inside == "0" && outside == "0" && count == strconv.Itoa(initialUIDMapFullRange))
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
