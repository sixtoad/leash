package darwind

import "testing"

// Sample `systemextensionsctl list` output (header + a few rows), modeled on the
// real format. Replace/extend with captured output from a real Mac when verifying.
const sampleSystemExtensionsList = `2 extension(s)
--- com.apple.system_extension.endpoint_security
enabled	active	teamID	bundleID (version)	name	[state]
*	*	W5HSYBBJGA	com.strongdm.leash.LeashES (1.0/1)	LeashES	[activated enabled]
--- com.apple.system_extension.network_extension
enabled	active	teamID	bundleID (version)	name	[state]
*		W5HSYBBJGA	com.strongdm.leash.LeashNetworkFilter (1.0/1)	LeashNetworkFilter	[activated waiting for user]
`

func TestParseExtensionStateActive(t *testing.T) {
	t.Parallel()
	if got := parseExtensionState(sampleSystemExtensionsList, "com.strongdm.leash.LeashES"); got != extActive {
		t.Fatalf("ES state = %v, want active", got)
	}
}

func TestParseExtensionStateDisabled(t *testing.T) {
	t.Parallel()
	// NE row has the active column unset and a non-"activated enabled" state.
	if got := parseExtensionState(sampleSystemExtensionsList, "com.strongdm.leash.LeashNetworkFilter"); got != extInstalledButDisabled {
		t.Fatalf("NE state = %v, want installed-but-disabled", got)
	}
}

func TestParseExtensionStateNotInstalled(t *testing.T) {
	t.Parallel()
	if got := parseExtensionState(sampleSystemExtensionsList, "com.strongdm.leash.DoesNotExist"); got != extNotInstalled {
		t.Fatalf("missing extension state = %v, want not-installed", got)
	}
}

func TestInterpretExtensionEntry(t *testing.T) {
	t.Parallel()

	active, disabled, _, ok := interpretExtensionEntry("*\t*\tTEAM\tcom.x.y (1/1)\ty\t[activated enabled]")
	if !ok || !active || disabled {
		t.Fatalf("both-stars row: active=%v disabled=%v ok=%v, want active", active, disabled, ok)
	}

	// state text alone (no active star) still counts as active.
	active, _, _, _ = interpretExtensionEntry("\t\tTEAM\tcom.x.y (1/1)\ty\t[activated enabled]")
	if !active {
		t.Fatal(`"activated enabled" state should be treated as active`)
	}

	// enabled but not active => installed-but-disabled.
	active, disabled, _, _ = interpretExtensionEntry("*\t\tTEAM\tcom.x.y (1/1)\ty\t[activated waiting for user]")
	if active || !disabled {
		t.Fatalf("enabled-not-active row: active=%v disabled=%v, want disabled", active, disabled)
	}
}

func TestExtensionIdentifiers(t *testing.T) {
	t.Setenv("LEASH_BUNDLE_IDENTIFIER", "")
	if got := endpointSecurityExtensionID(); got != "com.strongdm.leash.LeashES" {
		t.Fatalf("ES id = %q", got)
	}
	if got := networkFilterExtensionID(); got != "com.strongdm.leash.LeashNetworkFilter" {
		t.Fatalf("NE id = %q", got)
	}
	t.Setenv("LEASH_BUNDLE_IDENTIFIER", "com.example.leash")
	if got := endpointSecurityExtensionID(); got != "com.example.leash.LeashES" {
		t.Fatalf("override ES id = %q", got)
	}
}
