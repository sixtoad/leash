// Package enforcement resolves leash's fail-closed vs proxy-only posture and
// describes the effective enforcement level. It has no dependencies so both
// the client (runner) and leashd share one decision.
package enforcement

import (
	"errors"
	"fmt"
	"strings"
)

// Environment variables selecting what happens when the eBPF LSM (Layer 1)
// cannot attach. Fail-closed is the default (issue #117); proxy-only is an
// explicit opt-out.
const (
	// EnvRequireLSM is accepted for compatibility. Fail-closed is now the
	// default, so setting it is redundant.
	EnvRequireLSM = "LEASH_REQUIRE_LSM"
	// EnvAllowProxyOnly opts out of fail-closed: when the eBPF LSM cannot
	// attach, leash warns and continues with only the L7 proxy (Layer 2).
	EnvAllowProxyOnly = "LEASH_ALLOW_PROXY_ONLY"
)

// ErrConflictingLSMMode is returned when fail-closed and proxy-only are both
// requested at the same precedence level.
var ErrConflictingLSMMode = errors.New("--require-lsm and --allow-proxy-only are mutually exclusive")

// EnvTruthy reports whether an environment value is one of the accepted
// truthy spellings (1, true, yes, on; case-insensitive).
func EnvTruthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// ResolveRequireLSM decides whether an eBPF LSM attach failure is fatal.
//
// Precedence: explicit flags beat environment variables. At each level,
// requesting both fail-closed and proxy-only is an error. With nothing set the
// answer is true (fail closed). LEASH_REQUIRE_LSM / --require-lsm are accepted
// for compatibility and are redundant with the default; a falsy
// LEASH_REQUIRE_LSM does NOT opt out — only --allow-proxy-only /
// LEASH_ALLOW_PROXY_ONLY does.
//
// requireFlag and allowProxyOnlyFlag mean "the flag was passed on the command
// line". getenv may be nil (treated as an empty environment).
func ResolveRequireLSM(requireFlag, allowProxyOnlyFlag bool, getenv func(string) string) (bool, error) {
	if requireFlag && allowProxyOnlyFlag {
		return true, ErrConflictingLSMMode
	}
	if allowProxyOnlyFlag {
		return false, nil
	}
	if requireFlag {
		return true, nil
	}
	if getenv == nil {
		return true, nil
	}
	envRequire := EnvTruthy(getenv(EnvRequireLSM))
	envAllow := EnvTruthy(getenv(EnvAllowProxyOnly))
	if envRequire && envAllow {
		return true, errors.New(EnvRequireLSM + " and " + EnvAllowProxyOnly + " are mutually exclusive")
	}
	return !envAllow, nil
}

// Enforcement levels reported in the enforcement-ready marker and logs. The
// vocabulary ("lsm" | "proxy-only") matches the `enforcement` field of Walk's
// machine-mode start record, so orchestrators can compare the two directly.
// Whether the L7 proxy is also active is reported separately in Layer2.
const (
	// LevelLSM: Layer 1 (eBPF LSM) attached.
	LevelLSM = "lsm"
	// LevelProxyOnly: Layer 1 is unavailable; only the L7 proxy enforces.
	// Reachable only with --allow-proxy-only / LEASH_ALLOW_PROXY_ONLY.
	LevelProxyOnly = "proxy-only"
	// LevelNone: no layer enforces (enforcement explicitly skipped, or
	// Layer 1 unavailable in --lsm-only mode).
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
	Enforcement    string `json:"enforcement"`
	Layer1         string `json:"layer1"`
	Layer2         string `json:"layer2"`
	RequireLSM     bool   `json:"requireLSM"`
	AllowProxyOnly bool   `json:"allowProxyOnly"`
	// Reason says why Layer 1 is not active (empty when it is).
	Reason string `json:"reason,omitempty"`
	// Layer1Via names who holds the eBPF LSM programs when it is not leashd
	// itself: "enforcer-daemon" for a rootless run whose programs the
	// leash enforcer daemon attached (docs/ROOTLESS.md). Empty otherwise.
	// The level is "lsm" either way: the same programs, compiled from the
	// same policy.
	Layer1Via string `json:"layer1Via,omitempty"`
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
	// unreadable). Treated as not active: fail closed under the default.
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
func Describe(layer1Available, layer2Active, requireLSM bool) Status {
	st := Status{
		Layer1:         LayerActive,
		Layer2:         LayerActive,
		RequireLSM:     requireLSM,
		AllowProxyOnly: !requireLSM,
	}
	if !layer1Available {
		st.Layer1 = LayerUnavailable
	}
	if !layer2Active {
		st.Layer2 = LayerDisabled
	}
	switch {
	case layer1Available:
		st.Enforcement = LevelLSM
	case layer2Active:
		st.Enforcement = LevelProxyOnly
	default:
		st.Enforcement = LevelNone
	}
	return st
}

// Check reports whether a workload may be released at this level under the
// given posture. "none" is never acceptable — no layer enforces policy, and
// --allow-proxy-only only permits degrading to the proxy, not past it. With
// fail-closed in effect, anything other than "lsm" is refused.
func (s Status) Check(requireLSM bool) error {
	remedy := FailClosedRemedy(s.Layer2 == LayerActive)
	switch {
	case s.Enforcement == LevelNone:
		return fmt.Errorf("%s; no layer enforces policy, refusing to run the workload (%s)", s.describe(), remedy)
	case requireLSM && s.Enforcement != LevelLSM:
		return fmt.Errorf("%s; fail-closed is in effect, refusing to run the workload unenforced (%s)", s.describe(), remedy)
	}
	return nil
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

// FailClosedRemedy is the remediation for a fail-closed refusal. It depends
// on whether the L7 proxy (Layer 2) is running: with the proxy off (native
// --lsm-only — unprivileged, or the egress setup failed) --allow-proxy-only
// cannot help, so suggesting it would mislead.
func FailClosedRemedy(layer2Active bool) string {
	if !layer2Active {
		return "enable the bpf LSM; the L7 proxy is not available in this session (--lsm-only: unprivileged or the native egress setup failed), so proxy-only is not possible even with --allow-proxy-only — fix the egress setup or run as root to make it an option"
	}
	return "enable the bpf LSM, or pass --allow-proxy-only to continue with only the L7 proxy"
}

// Narrow lowers Layer 1 to unavailable (with reason) if it was reported
// active. It never raises a level, so combining independent observations
// (leashd's and the client's) can only make the result more conservative.
func (s Status) Narrow(reason string) Status {
	if s.Layer1 != LayerActive {
		return s
	}
	n := Describe(false, s.Layer2 == LayerActive, s.RequireLSM)
	n.AllowProxyOnly = s.AllowProxyOnly
	n.Reason = reason
	return n
}
