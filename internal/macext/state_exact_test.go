package macext

import "testing"

// A sibling bundle id that merely starts with the wanted id must not satisfy
// the check: the runtime refuses to start unenforced on this answer.
func TestParseMatchesBundleIDColumnExactly(t *testing.T) {
	t.Parallel()
	const listing = "enabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n" +
		"*\t*\t-\tcom.sixtoad.leash.LeashESHelper (1/1)\tHelper\t[activated enabled]\n" +
		"*\t\t-\tcom.sixtoad.leash.LeashES (1/1)\tLeashES\t[activated waiting for user]\n"
	if got := Parse(listing, "com.sixtoad.leash.LeashES"); got != StateDisabled {
		t.Fatalf("LeashES = %v, want disabled (the active row is a different extension)", got)
	}
	if got := Parse("note: com.sixtoad.leash.LeashES [activated enabled]\n", "com.sixtoad.leash.LeashES"); got != StateMissing {
		t.Fatalf("a non-row line mentioning the id = %v, want missing", got)
	}
	// The format an ad-hoc build prints on the validation VM ("-" team).
	const vm = "*\t*\t-\tcom.sixtoad.leash.LeashES (1.1.0/20260820.2)\tLeashES\t[activated enabled]\n"
	if got := Parse(vm, "COM.sixtoad.leash.LeashES"); got != StateActive {
		t.Fatalf("ad-hoc row = %v, want active", got)
	}
}

func TestRowBundleID(t *testing.T) {
	t.Parallel()
	for line, want := range map[string]string{
		"*\t*\t-\tcom.x.y (1/1)\ty\t[activated enabled]": "com.x.y",
		"*\t*\t-\tcom.x.y\ty\t[activated enabled]":       "com.x.y",
		"enabled\tactive": "",
		"--- com.apple.system_extension.endpoint_security": "",
	} {
		if got := RowBundleID(line); got != want {
			t.Fatalf("RowBundleID(%q) = %q, want %q", line, got, want)
		}
	}
}
