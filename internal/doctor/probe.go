package doctor

import (
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/strongdm/leash/internal/lsm"
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

// ProbeOptions tunes what Probe touches. The zero value is the default probe,
// which is the honest one: everything doctor can observe, it observes.
type ProbeOptions struct {
	// Quick skips the checks that cost more than a file read — today, the
	// BPF-LSM attachability probe, which loads and attaches a real program.
	// Opting *out* is the flag, deliberately: an opt-in would leave the guess
	// as the default answer, which is the gap issue #52 exists to close.
	Quick bool

	// LeashCLIPath overrides where the macOS probe looks for the companion
	// leashcli binary, mirroring `leash --darwin exec --leash-cli-path`: a
	// locally built leashcli is the normal case during development, and doctor
	// reporting the app-bundle path as missing would be true but useless.
	LeashCLIPath string

	// DarwinDaemonAddr overrides where the macOS probe looks for the running
	// `leash --darwin` daemon. Empty means LEASH_LISTEN, then the default.
	DarwinDaemonAddr string
}

// Probe reads the live machine into a Host, running every check doctor has.
// It never fails: an unreadable source becomes the cautious answer (unknown,
// and therefore not ready) with advice, because doctor's job is to report a
// verdict, not to error out on a missing /proc.
func Probe() Host { return ProbeWithOptions(ProbeOptions{}) }

// ProbeWithOptions is Probe with the expensive checks made optional.
func ProbeWithOptions(opts ProbeOptions) Host {
	lsmState, lsmAdvice := runner.ProbeBPFLSM()
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
		BPFLSM:          lsmState,
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
	h.BPFLSMAttach = probeAttachable(opts, capBPF, capsKnown)
	h.Darwin = probeDarwin(opts)
	return h
}

// probeAttachable decides whether to ask the kernel, and asks it. The two
// reasons not to are the two the report has to be able to name: the caller
// passed --quick, or this process could not have loaded a BPF program in the
// first place.
//
// The privilege gate is not an optimisation. Without it every unprivileged run
// would pay for a load that can only end in EPERM, and the reason reaching the
// report would be the kernel's "operation not permitted" rather than the plain
// fact that doctor is not running as root.
func probeAttachable(opts ProbeOptions, capBPF, capsKnown bool) lsm.AttachProbe {
	if opts.Quick {
		return lsm.SkippedAttachProbe("--quick was passed, so doctor did not load and attach a probe program")
	}
	if !privilegedEnoughToProbe(capBPF, capsKnown) {
		return lsm.SkippedAttachProbe("this process is not privileged enough to load a BPF LSM program (needs root, or CAP_BPF), so doctor did not attempt the attach")
	}
	return lsm.ProbeAttachable()
}

// privilegedEnoughToProbe reports whether loading a BPF_PROG_TYPE_LSM program
// could possibly succeed. Capabilities are preferred over euid and euid is only
// the fallback for a process whose capability set could not be read at all —
// mirroring probeCaps, which refuses to infer capabilities from being root.
func privilegedEnoughToProbe(capBPF, capsKnown bool) bool {
	if capsKnown {
		return capBPF
	}
	return os.Geteuid() == 0
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
