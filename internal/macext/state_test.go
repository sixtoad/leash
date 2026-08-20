package macext

import (
	"encoding/json"
	"testing"
)

// Sample `systemextensionsctl list` output (header + a few rows), modeled on the
// real format. Replace/extend with captured output from a real Mac when verifying.
const sampleSystemExtensionsList = `3 extension(s)
--- com.apple.system_extension.endpoint_security
enabled	active	teamID	bundleID (version)	name	[state]
*	*	W5HSYBBJGA	com.strongdm.leash.LeashES (1.0/1)	LeashES	[activated enabled]
--- com.apple.system_extension.network_extension
enabled	active	teamID	bundleID (version)	name	[state]
*		W5HSYBBJGA	com.strongdm.leash.LeashNetworkFilter (1.0/1)	LeashNetworkFilter	[activated waiting for user]
*		W5HSYBBJGA	com.strongdm.leash.LeashProxy (1.0/1)	LeashProxy	[activated waiting for user]
`

func TestParseExtensionStateActive(t *testing.T) {
	t.Parallel()
	if got := Parse(sampleSystemExtensionsList, "com.strongdm.leash.LeashES"); got != StateActive {
		t.Fatalf("ES state = %v, want active", got)
	}
}

func TestParseExtensionStateDisabled(t *testing.T) {
	t.Parallel()
	// NE row has the active column unset and a non-"activated enabled" state.
	if got := Parse(sampleSystemExtensionsList, "com.strongdm.leash.LeashNetworkFilter"); got != StateDisabled {
		t.Fatalf("NE state = %v, want disabled", got)
	}
}

func TestParseExtensionStateNotInstalled(t *testing.T) {
	t.Parallel()
	if got := Parse(sampleSystemExtensionsList, "com.strongdm.leash.DoesNotExist"); got != StateMissing {
		t.Fatalf("missing extension state = %v, want missing", got)
	}
}

func TestInterpretExtensionEntry(t *testing.T) {
	t.Parallel()

	active, disabled, _, ok := InterpretEntry("*\t*\tTEAM\tcom.x.y (1/1)\ty\t[activated enabled]")
	if !ok || !active || disabled {
		t.Fatalf("both-stars row: active=%v disabled=%v ok=%v, want active", active, disabled, ok)
	}

	// state text alone (no active star) still counts as active.
	active, _, _, _ = InterpretEntry("\t\tTEAM\tcom.x.y (1/1)\ty\t[activated enabled]")
	if !active {
		t.Fatal(`"activated enabled" state should be treated as active`)
	}

	// enabled but not active => installed-but-disabled.
	active, disabled, _, _ = InterpretEntry("*\t\tTEAM\tcom.x.y (1/1)\ty\t[activated waiting for user]")
	if active || !disabled {
		t.Fatalf("enabled-not-active row: active=%v disabled=%v, want disabled", active, disabled)
	}
}

func TestExtensionIdentifiers(t *testing.T) {
	t.Setenv("LEASH_BUNDLE_IDENTIFIER", "")
	// All three ids are asserted: leash doctor grades the transparent proxy
	// too, and an id that does not match the Swift side reads as "extension not
	// installed" on a Mac where it is running perfectly.
	for _, c := range []struct {
		got, want string
	}{
		{EndpointSecurityExtensionID(), "com.strongdm.leash.LeashES"},
		{NetworkFilterExtensionID(), "com.strongdm.leash.LeashNetworkFilter"},
		{TransparentProxyExtensionID(), "com.strongdm.leash.LeashProxy"},
	} {
		if c.got != c.want {
			t.Errorf("id = %q, want %q", c.got, c.want)
		}
	}
	t.Setenv("LEASH_BUNDLE_IDENTIFIER", "com.example.leash")
	if got := EndpointSecurityExtensionID(); got != "com.example.leash.LeashES" {
		t.Fatalf("override ES id = %q", got)
	}
	if got := TransparentProxyExtensionID(); got != "com.example.leash.LeashProxy" {
		t.Fatalf("override proxy id = %q", got)
	}
}

// The proxy row in the fixture is enabled but not active — approval pending —
// which is the state that must not read as "active".
func TestParseExtensionStateProxyPendingApproval(t *testing.T) {
	t.Parallel()
	if got := Parse(sampleSystemExtensionsList, "com.strongdm.leash.LeashProxy"); got != StateDisabled {
		t.Fatalf("proxy state = %v, want disabled", got)
	}
}

// The three states a caller may branch on must never collapse into each other,
// and the round trip has to be exact: an unknown that decodes as active is a
// fabricated verdict.
func TestStateJSONRoundTrip(t *testing.T) {
	t.Parallel()
	for _, want := range []State{StateUnknown, StateMissing, StateDisabled, StateActive} {
		encoded, err := json.Marshal(want)
		if err != nil {
			t.Fatalf("marshal %v: %v", want, err)
		}
		var got State
		if err := json.Unmarshal(encoded, &got); err != nil {
			t.Fatalf("unmarshal %s: %v", encoded, err)
		}
		if got != want {
			t.Errorf("round trip %s: got %v want %v", encoded, got, want)
		}
	}
	var s State
	if err := json.Unmarshal([]byte(`"activated"`), &s); err == nil {
		t.Errorf("an unrecognised state must not decode to %v", s)
	}
}

func TestFDAJSONRoundTrip(t *testing.T) {
	t.Parallel()
	for _, want := range []FDA{FDAUnknown, FDADenied, FDAGranted} {
		encoded, err := json.Marshal(want)
		if err != nil {
			t.Fatalf("marshal %v: %v", want, err)
		}
		var got FDA
		if err := json.Unmarshal(encoded, &got); err != nil {
			t.Fatalf("unmarshal %s: %v", encoded, err)
		}
		if got != want {
			t.Errorf("round trip %s: got %v want %v", encoded, got, want)
		}
	}
	// ParseFDA is the lenient half of the pair, and it degrades to unknown on
	// purpose: it reads a field from a daemon that may be newer than this
	// build, where anything unrecognised must not become a grant.
	if got := ParseFDA("granted-ish"); got != FDAUnknown {
		t.Errorf("ParseFDA of an unknown word = %v, want unknown", got)
	}
	var f FDA
	if err := json.Unmarshal([]byte(`"granted-ish"`), &f); err == nil {
		t.Errorf("decoding a verdict must be strict, got %v", f)
	}
}
