// Package enforcement holds leash's fail-closed posture and describes the
// effective enforcement level. It has no dependencies so both the client
// (runner) and leashd share one decision.
//
// Fail-closed is the only posture: leash never runs a workload with only the
// L7 proxy (Layer 2) enforcing. When the eBPF LSM (Layer 1) is unavailable
// the run is refused.
package enforcement

import (
	"fmt"
	"strings"
)

// EnvRequireLSM is accepted for compatibility (Walk and older provisioners
// set it, and the client injects it into the leash container so an older
// leashd image stays fail-closed). Fail-closed is the only posture, so it is a
// no-op for this build.
const EnvRequireLSM = "LEASH_REQUIRE_LSM"

// FailClosedRemedy is the remediation appended to every fail-closed refusal.
const FailClosedRemedy = "leash never runs a workload with only the L7 proxy enforcing; enable the bpf LSM and give the workload a scopable cgroup (run `leash doctor` to see what this host is missing)"

// Enforcement levels reported in the enforcement-ready marker and logs. The
// vocabulary matches the `enforcement` field of Walk's machine-mode start
// record, so orchestrators can compare the two directly. Whether the L7 proxy
// is also active is reported separately in Layer2. A workload is released
// only at "lsm".
const (
	// LevelLSM: Layer 1 (eBPF LSM) attached.
	LevelLSM = "lsm"
	// LevelNone: Layer 1 is not active (the reason says why), or enforcement
	// was explicitly skipped. No workload is released at this level except
	// on the skip-enforcement path.
	LevelNone = "none"
)

// Layer states reported alongside the level.
const (
	LayerActive      = "active"
	LayerUnavailable = "unavailable"
	LayerDisabled    = "disabled"
)

// Status is the machine-readable statement of the effective
// enforcement level, written as JSON into the enforcement-ready marker.
type Status struct {
	Enforcement string `json:"enforcement"`
	Layer1      string `json:"layer1"`
	Layer2      string `json:"layer2"`
	// RequireLSM is always true: fail-closed is the only posture.
	RequireLSM bool `json:"requireLSM"`
	// Reason says why Layer 1 is not active (empty when it is).
	Reason string `json:"reason,omitempty"`
	// Layer1Via names who holds the eBPF LSM programs when it is not leashd
	// itself: "enforcer-daemon" for a rootless run whose programs the
	// leash enforcer daemon attached (docs/ROOTLESS.md). Empty otherwise.
	// The level is "lsm" either way: the same programs, compiled from the
	// same policy.
	Layer1Via string `json:"layer1Via,omitempty"`
	// Audit is the eBPF audit pipeline's posture and losses (issue #241).
	// leashd rewrites the marker when Dropped changes, so a reader sees
	// whether the audit trail of the run is complete.
	Audit *AuditStatus `json:"audit,omitempty"`
}

// AuditStatus describes the kernel audit pipeline of a run.
type AuditStatus struct {
	// RingBufferBytes is the size of each eBPF object's event ring buffer.
	RingBufferBytes uint32 `json:"ringBufferBytes"`
	// Lossless is the opt-in posture that denies an operation whose audit
	// record cannot be written instead of deciding it without a record.
	Lossless bool `json:"lossless"`
	// Dropped counts audit records the kernel could not write because the
	// ring buffer was full. Nonzero means the event log is incomplete (the
	// operations were still decided by policy, or denied under Lossless).
	Dropped uint64 `json:"dropped"`
}

// Layer1ViaEnforcerDaemon is Status.Layer1Via for a rootless run enforced by
// the leash enforcer daemon.
const Layer1ViaEnforcerDaemon = "enforcer-daemon"

// LSMListState is what the kernel's active-LSM list says about "bpf". Attach
// success alone proves nothing: with CONFIG_BPF_LSM=y but bpf absent from the
// active list (Ubuntu 24.04's default), BPF LSM programs attach and are never
// invoked, so Layer 1 is only active when the list confirms it.
type LSMListState int

const (
	// LSMListUnknown: the list could not be read (securityfs not mounted or
	// unreadable). Treated as not active: fail closed.
	LSMListUnknown LSMListState = iota
	// LSMListInactive: the list was read and "bpf" is not in it.
	LSMListInactive
	// LSMListActive: "bpf" is an active LSM.
	LSMListActive
)

// ActiveLSMPath is the kernel's active-LSM list.
const ActiveLSMPath = "/sys/kernel/security/lsm"

// ClassifyLSMList interprets the contents of ActiveLSMPath (or the error
// reading it) and returns a human-readable reason when bpf is not active.
func ClassifyLSMList(data []byte, readErr error) (LSMListState, string) {
	if readErr != nil {
		return LSMListUnknown, fmt.Sprintf("cannot read the active LSM list %s (%v), so the bpf LSM cannot be confirmed active", ActiveLSMPath, readErr)
	}
	list := strings.TrimSpace(string(data))
	if list == "" {
		return LSMListUnknown, fmt.Sprintf("the active LSM list %s is empty, so the bpf LSM cannot be confirmed active", ActiveLSMPath)
	}
	for _, name := range strings.Split(list, ",") {
		if strings.TrimSpace(name) == "bpf" {
			return LSMListActive, ""
		}
	}
	return LSMListInactive, fmt.Sprintf(`"bpf" is not among the active LSMs (%s): eBPF LSM programs can attach but are never invoked; add bpf to the lsm= boot parameter`, list)
}

// Describe derives the effective enforcement level. layer1Available
// is false when the eBPF LSM could not attach (or had no scopable cgroup);
// layer2Active is false in --lsm-only mode.
func Describe(layer1Available, layer2Active bool) Status {
	st := Status{
		Enforcement: LevelNone,
		Layer1:      LayerUnavailable,
		Layer2:      LayerActive,
		RequireLSM:  true,
	}
	if layer1Available {
		st.Enforcement = LevelLSM
		st.Layer1 = LayerActive
	}
	if !layer2Active {
		st.Layer2 = LayerDisabled
	}
	return st
}

// Check reports whether a workload may be released at this level. Only "lsm"
// is acceptable: with Layer 1 unavailable the run is refused even when the L7
// proxy is up, because leash never runs a workload proxy-only.
func (s Status) Check() error {
	if s.Enforcement == LevelLSM {
		return nil
	}
	return fmt.Errorf("%s; fail-closed, refusing to run the workload (%s)", s.describe(), FailClosedRemedy)
}

// describe renders "enforcement=… (layer1=… layer2=…)[: reason]" with the
// reason's own trailing punctuation trimmed so callers can join cleanly.
func (s Status) describe() string {
	out := fmt.Sprintf("enforcement=%s (layer1=%s layer2=%s)", s.Enforcement, s.Layer1, s.Layer2)
	if r := strings.TrimRight(strings.TrimSpace(s.Reason), ".;:, "); r != "" {
		out += ": " + r
	}
	return out
}

// Narrow lowers Layer 1 to unavailable (with reason) if it was reported
// active. It never raises a level, so combining independent observations
// (leashd's and the client's) can only make the result more conservative.
func (s Status) Narrow(reason string) Status {
	if s.Layer1 != LayerActive {
		return s
	}
	n := Describe(false, s.Layer2 == LayerActive)
	n.Reason = reason
	return n
}
