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
	switch {
	case s.Enforcement == LevelNone:
		return fmt.Errorf("enforcement=%s (layer1=%s layer2=%s): no layer enforces policy; refusing to run the workload", s.Enforcement, s.Layer1, s.Layer2)
	case requireLSM && s.Enforcement != LevelLSM:
		return fmt.Errorf("enforcement=%s (layer1=%s layer2=%s) but fail-closed is in effect; refusing to run the workload unenforced (pass --allow-proxy-only to accept proxy-only)", s.Enforcement, s.Layer1, s.Layer2)
	}
	return nil
}
