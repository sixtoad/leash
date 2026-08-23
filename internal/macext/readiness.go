package macext

import (
	"encoding/json"
	"fmt"
)

// The vocabulary in this file is shared by the daemon that observes these facts
// (internal/macsync, internal/darwind) and the command that grades them
// (internal/doctor). It lives here so the two cannot drift: a doctor that spelt
// the component names or the FDA states its own way would eventually disagree
// with the daemon about whether the machine enforces.

// Component names reported in the extensions' client.hello, mirroring
// LeashIdentifiers.Component in mac-leash/Shared/LeashIdentifiers.swift.
//
// Connection is a stronger readiness signal than activation: an extension that
// is activated but absent from the daemon's client registry receives no PID or
// rule broadcasts, so it enforces nothing (leash #62). Activation says the code
// is allowed to run; presence here says it is running AND wired to policy.
const (
	ComponentEndpointSecurity = "leash.es"
	ComponentNetworkFilter    = "leash.netfilter"
	ComponentTransparentProxy = "leash.proxy"
	ComponentApp              = "leash.app"
	ComponentCLI              = "leash.cli"
	// ComponentProbe is the daemon's own websocket health probe: it connects,
	// says hello and disconnects, so it shows up as register/unregister churn.
	ComponentProbe   = "leash.probe"
	ComponentUnknown = "unknown"
)

// CapabilityFullDiskAccess is the tag LeashES puts in its client.hello once
// es_new_client has succeeded, mirroring LeashIdentifiers.Capability in
// mac-leash/Shared/LeashIdentifiers.swift.
//
// It is in the hello rather than in an event because the hello is re-sent on
// every reconnect, and the event is not. LeashES emits es.full_disk_access.ready
// once per process launch, so a daemon started after the extension — which is
// the normal case, macOS launches extensions at boot — never saw it and could
// never confirm the grant. An extension too old to advertise this leaves the
// state unknown, which is the honest answer for it.
const CapabilityFullDiskAccess = "full-disk-access"

// FDA is what is known about LeashES's Full Disk Access grant.
//
// macOS exposes no public API for "does that other process hold FDA", and every
// obvious substitute answers a different question: probing a TCC-gated path
// tells you about the process doing the probing, not about LeashES, and TCC.db
// is neither readable nor documented. The honest signal is the one LeashES
// already produces — es_new_client returns ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED
// without FDA, and LeashES reports that to the daemon before exiting.
//
// The zero value is FDAUnknown, so a daemon that has heard nothing never
// implies a grant it has no evidence for.
type FDA int

const (
	FDAUnknown FDA = iota // LeashES has not reported either way
	FDADenied             // LeashES reported es.full_disk_access.missing
	FDAGranted            // LeashES reported es.full_disk_access.ready
)

// String is the wire form carried in JSON.
func (f FDA) String() string {
	switch f {
	case FDAGranted:
		return "granted"
	case FDADenied:
		return "denied"
	default:
		return "unknown"
	}
}

// DaemonHealth is the body of the daemon's /health/darwin endpoint: everything
// about macOS enforcement that only the running daemon can see.
//
// It is deliberately observation-only — no verdicts. The daemon reports what it
// has been told; internal/doctor decides what that means. Keeping the policy on
// one side means a daemon and a doctor from different builds still agree on the
// facts even if they disagree about the grading.
type DaemonHealth struct {
	// Components are the sorted, de-duplicated component names of the clients
	// currently connected over the websocket.
	Components []string `json:"components"`

	// FullDiskAccess is the last grant LeashES reported, as a wire word
	// ("granted", "denied", "unknown").
	FullDiskAccess string `json:"full_disk_access"`

	// FullDiskAccessAt is when that report arrived (RFC3339), or "" when
	// nothing has been reported.
	FullDiskAccessAt string `json:"full_disk_access_at,omitempty"`
}

// ParseFDA is the inverse of FDA.String. An unrecognised word is FDAUnknown
// rather than an error: a newer daemon reporting a state this build has never
// heard of must degrade to "we do not know", never to a grant.
func ParseFDA(word string) FDA {
	switch word {
	case "granted":
		return FDAGranted
	case "denied":
		return FDADenied
	default:
		return FDAUnknown
	}
}

// MarshalJSON emits the string form, for the same reason State does: the
// document has to be readable without a constant table.
func (f FDA) MarshalJSON() ([]byte, error) { return json.Marshal(f.String()) }

// UnmarshalJSON is the strict inverse. It is deliberately stricter than
// ParseFDA: ParseFDA reads a field inside a document that may come from a
// newer daemon, where degrading to "unknown" is correct, whereas decoding a
// doctor report is decoding a verdict, and a word this build does not know is
// an error rather than a silent state change.
func (f *FDA) UnmarshalJSON(data []byte) error {
	var word string
	if err := json.Unmarshal(data, &word); err != nil {
		return fmt.Errorf("full disk access state must be a JSON string: %w", err)
	}
	switch word {
	case "granted":
		*f = FDAGranted
	case "denied":
		*f = FDADenied
	case "unknown":
		*f = FDAUnknown
	default:
		return fmt.Errorf("unknown full disk access state %q (want granted, denied or unknown)", word)
	}
	return nil
}
