// Package macext answers "is this leash system extension actually activated?"
// from the only source macOS exposes without private API: the text
// `systemextensionsctl list` prints.
//
// It lives outside internal/darwind because two callers now need the same
// answer and must not drift: the `--darwin` runtime's own preflight (warn or
// refuse to start unenforced) and `leash doctor` (report the same fact as a
// machine-readable verdict). A doctor that parsed the table its own way would
// eventually disagree with the runtime about whether the machine enforces,
// which is exactly the false assurance doctor exists to prevent.
//
// Everything here is pure text and environment: it compiles and unit-tests on
// any OS. Running systemextensionsctl is the caller's job.
package macext

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// State describes a system extension's activation, as reported by
// `systemextensionsctl list`.
//
// The zero value is StateUnknown, not StateMissing: "we could not ask" and "it
// is not installed" have different remedies, and collapsing them would let an
// unreadable systemextensionsctl (it exits EX_NOPERM without admin rights)
// masquerade as a definite negative. Callers that only care whether enforcement
// is live can compare against StateActive, which is false for both.
type State int

const (
	StateUnknown  State = iota // systemextensionsctl could not be consulted
	StateMissing               // no row for this identifier: not installed, or never approved
	StateDisabled              // installed, but not enabled+active (e.g. waiting for user approval)
	StateActive                // enabled and active: the extension is running
)

// String is the wire form used in leash doctor's JSON and in operator advice.
func (s State) String() string {
	switch s {
	case StateActive:
		return "active"
	case StateDisabled:
		return "disabled"
	case StateMissing:
		return "missing"
	default:
		return "unknown"
	}
}

// Describe is the sentence a human needs, where String is the word a machine
// parses. The two are kept apart because doctor's JSON must stay a stable
// vocabulary while the human text is free to explain itself.
func (s State) Describe() string {
	switch s {
	case StateActive:
		return "active"
	case StateDisabled:
		return "installed but not enabled/active (approval pending?)"
	case StateMissing:
		return "not installed / not approved"
	default:
		return "unknown (systemextensionsctl could not be consulted)"
	}
}

// Extension identifiers mirror mac-leash/Shared/LeashIdentifiers.swift. The base
// bundle id can be overridden for non-default builds via LEASH_BUNDLE_IDENTIFIER
// (the Swift app honors the same env var).
func BundleID() string {
	if v := strings.TrimSpace(os.Getenv("LEASH_BUNDLE_IDENTIFIER")); v != "" {
		return v
	}
	return "com.strongdm.leash"
}

// EndpointSecurityExtensionID is the ES extension: leash's file and exec
// enforcement. Without it nothing on macOS enforces those at all.
func EndpointSecurityExtensionID() string { return BundleID() + ".LeashES" }

// NetworkFilterExtensionID is the NE content filter: the socket-level gate.
func NetworkFilterExtensionID() string { return BundleID() + ".LeashNetworkFilter" }

// TransparentProxyExtensionID is the NETransparentProxyProvider that feeds
// flows to leash's MITM proxy. Without it there is no HTTPS inspection.
func TransparentProxyExtensionID() string { return BundleID() + ".LeashProxy" }

// InterpretEntry mirrors interpretExtensionEntry in
// mac-leash/Leash/SystemExtensionController+Internals.swift (the source of
// truth). `systemextensionsctl list` rows are tab-separated:
//
//	enabled  active  teamID  bundleID (version)  name  [state]
//	  *        *     W5H…    com.strongdm.leash.LeashES (1/1)  LeashES  [activated enabled]
//
// column 0 carries a "*" when enabled, column 1 when active, and the last column
// is a bracketed [state]. ok is false only for an empty line.
func InterpretEntry(line string) (isActive, isInstalledButDisabled bool, state string, ok bool) {
	cols := strings.Split(line, "\t")
	if len(cols) == 0 {
		return false, false, "", false
	}
	star := func(i int) bool { return i < len(cols) && strings.Contains(cols[i], "*") }
	enabled := star(0)
	active := star(1)

	state = strings.Trim(strings.TrimSpace(cols[len(cols)-1]), "[]")
	norm := strings.ToLower(state)

	isActive = (enabled && active) || strings.Contains(norm, "activated enabled")
	switch {
	case enabled && !active:
		isInstalledButDisabled = true
	case strings.Contains(norm, "disabled"), strings.Contains(norm, "inactive"), strings.Contains(norm, "paused"):
		isInstalledButDisabled = true
	}
	return isActive, isInstalledButDisabled, state, true
}

// Parse scans `systemextensionsctl list` output for the row(s) matching id
// (case-insensitive) and returns the best state found.
//
// A missing row is StateMissing, never StateUnknown: the command answered, and
// what it said was "there is no such extension". StateUnknown is reserved for
// callers that could not run the command at all.
func Parse(output, id string) State {
	idLower := strings.ToLower(strings.TrimSpace(id))
	disabled := false
	for _, raw := range strings.Split(output, "\n") {
		if !strings.Contains(strings.ToLower(raw), idLower) {
			continue
		}
		active, isDisabled, _, ok := InterpretEntry(raw)
		if !ok {
			continue
		}
		if active {
			return StateActive
		}
		if isDisabled {
			disabled = true
		}
	}
	if disabled {
		return StateDisabled
	}
	return StateMissing
}

// MarshalJSON emits the string form. Integers would make the payload's meaning
// depend on a constant table the consumer does not have.
func (s State) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

// UnmarshalJSON is the exact inverse, and it rejects rather than defaults: a
// state this build does not recognise is not one it may quietly read as
// "active". Callers that want lenience should not be decoding a verdict.
func (s *State) UnmarshalJSON(data []byte) error {
	var word string
	if err := json.Unmarshal(data, &word); err != nil {
		return fmt.Errorf("system extension state must be a JSON string: %w", err)
	}
	switch word {
	case "active":
		*s = StateActive
	case "disabled":
		*s = StateDisabled
	case "missing":
		*s = StateMissing
	case "unknown":
		*s = StateUnknown
	default:
		return fmt.Errorf("unknown system extension state %q (want active, disabled, missing or unknown)", word)
	}
	return nil
}
