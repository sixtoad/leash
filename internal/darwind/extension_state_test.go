package darwind

import (
	"strings"
	"testing"
)

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

func TestParseExtensionStateDetail(t *testing.T) {
	t.Parallel()

	state, detail := parseExtensionStateDetail(sampleSystemExtensionsList, "com.strongdm.leash.LeashNetworkFilter")
	if state != extInstalledButDisabled {
		t.Fatalf("NE state = %v, want installed-but-disabled", state)
	}
	if detail != "activated waiting for user" {
		t.Fatalf("NE detail = %q, want %q", detail, "activated waiting for user")
	}

	state, detail = parseExtensionStateDetail(sampleSystemExtensionsList, "com.strongdm.leash.LeashES")
	if state != extActive || detail != "activated enabled" {
		t.Fatalf("ES detail = (%v, %q), want (active, %q)", state, detail, "activated enabled")
	}

	// No matching row: not installed, empty detail.
	if state, detail = parseExtensionStateDetail(sampleSystemExtensionsList, "com.strongdm.leash.Missing"); state != extNotInstalled || detail != "" {
		t.Fatalf("missing = (%v, %q), want (not-installed, \"\")", state, detail)
	}
}

func TestParseExtensionStateNoSiblingPrefixMatch(t *testing.T) {
	t.Parallel()
	// Only a sibling extension whose id has the queried id as a prefix is active.
	// Matching the whole line as a substring would wrongly report the queried id
	// as active and let the enforcement gate pass — i.e. run UNENFORCED.
	out := "1 extension(s)\n" +
		"enabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n" +
		"*\t*\tTEAM\tcom.strongdm.leash.LeashESHelper (1/1)\tLeashESHelper\t[activated enabled]\n"
	if got := parseExtensionState(out, "com.strongdm.leash.LeashES"); got != extNotInstalled {
		t.Fatalf("sibling-prefix row matched as %v, want not-installed (must match bundle id exactly)", got)
	}
}

// realSystemExtensionsList is verbatim `systemextensionsctl list` output captured
// on macOS 26.3 with the official (StrongDM-signed) Leash.app extensions active.
// It locks the parser to the real row format: versioned bundle ids like
// "(1.1.0/20251027.1)", display names with spaces ("Leash Network Filter"), and
// "--- ... (Go to ...)" / "enabled active ..." header lines that must NOT match.
const realSystemExtensionsList = "2 extension(s)\n" +
	"--- com.apple.system_extension.network_extension (Go to 'System Settings > General > Login Items & Extensions > Network Extensions' to modify these system extension(s))\n" +
	"enabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n" +
	"*\t*\tW5HSYBBJGA\tcom.strongdm.leash.LeashNetworkFilter (1.1.0/20251027.1)\tLeash Network Filter\t[activated enabled]\n" +
	"--- com.apple.system_extension.endpoint_security (Go to 'System Settings > General > Login Items & Extensions > Endpoint Security Extensions' to modify these system extension(s))\n" +
	"enabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n" +
	"*\t*\tW5HSYBBJGA\tcom.strongdm.leash.LeashES (1.1.0/20251027.1)\tLeashES\t[activated enabled]\n"

func TestParseRealSystemExtensionsList(t *testing.T) {
	t.Parallel()
	es, esDet := parseExtensionStateDetail(realSystemExtensionsList, "com.strongdm.leash.LeashES")
	ne, neDet := parseExtensionStateDetail(realSystemExtensionsList, "com.strongdm.leash.LeashNetworkFilter")
	if es != extActive || ne != extActive {
		t.Fatalf("real listing: es=%v ne=%v, want both active", es, ne)
	}
	if esDet != "activated enabled" || neDet != "activated enabled" {
		t.Fatalf("real listing detail: es=%q ne=%q, want \"activated enabled\"", esDet, neDet)
	}
	if err := decideDarwinEnforcement(
		"com.strongdm.leash.LeashES", "com.strongdm.leash.LeashNetworkFilter",
		es, ne, esDet, neDet,
	); err != nil {
		t.Fatalf("real active listing should pass the gate, got: %v", err)
	}
}

func TestExtensionStateString(t *testing.T) {
	t.Parallel()
	cases := map[extensionState]string{
		extActive:               "active",
		extInstalledButDisabled: "installed but disabled",
		extNotInstalled:         "not installed / not approved",
		extUnknown:              "unknown (could not query systemextensionsctl)",
	}
	for state, want := range cases {
		if got := state.String(); got != want {
			t.Errorf("state %d String() = %q, want %q", state, got, want)
		}
	}
}

func TestDecideDarwinEnforcement(t *testing.T) {
	t.Parallel()
	const esID, neID = "com.strongdm.leash.LeashES", "com.strongdm.leash.LeashNetworkFilter"

	// Both active: the only non-error path.
	if err := decideDarwinEnforcement(esID, neID, extActive, extActive, "activated enabled", "activated enabled"); err != nil {
		t.Fatalf("both active: unexpected error: %v", err)
	}

	// Every non-(active,active) combination is a hard stop — there is no opt-out.
	hardStops := []struct {
		name           string
		es, ne         extensionState
		esDet, neDet   string
		wantInErrParts []string
	}{
		{"NE waiting-for-user", extActive, extInstalledButDisabled, "activated enabled", "activated waiting for user",
			[]string{neID, "activated waiting for user", "will not start"}},
		{"ES not installed", extNotInstalled, extActive, "", "activated enabled",
			[]string{esID, "not installed", "will not start"}},
		{"both unknown (exit 69)", extUnknown, extUnknown, "", "",
			[]string{"unknown", "will not start"}},
	}
	for _, tc := range hardStops {
		err := decideDarwinEnforcement(esID, neID, tc.es, tc.ne, tc.esDet, tc.neDet)
		if err == nil {
			t.Fatalf("%s: expected hard-stop error, got nil", tc.name)
		}
		for _, part := range tc.wantInErrParts {
			if !strings.Contains(err.Error(), part) {
				t.Errorf("%s: error %q missing %q", tc.name, err.Error(), part)
			}
		}
	}
}
