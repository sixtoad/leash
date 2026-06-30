//go:build darwin

package darwind

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// These tests drive the real exec→CombinedOutput→parse→decide pipeline against a
// fake `systemextensionsctl` so the positive ("both active → start") path is
// exercised end-to-end on a machine without the extensions installed. The row
// format mirrors the Swift source of truth (tab-separated columns).

// Both extensions active and enabled.
const fakeListBothActive = "2 extension(s)\n" +
	"--- com.apple.system_extension.endpoint_security\n" +
	"enabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n" +
	"*\t*\tW5HSYBBJGA\tcom.strongdm.leash.LeashES (1.0/1)\tLeashES\t[activated enabled]\n" +
	"--- com.apple.system_extension.network_extension\n" +
	"enabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n" +
	"*\t*\tW5HSYBBJGA\tcom.strongdm.leash.LeashNetworkFilter (1.0/1)\tLeashNetworkFilter\t[activated enabled]\n"

// ES active, NE installed but not yet approved by the user.
const fakeListNEWaiting = "2 extension(s)\n" +
	"enabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n" +
	"*\t*\tW5HSYBBJGA\tcom.strongdm.leash.LeashES (1.0/1)\tLeashES\t[activated enabled]\n" +
	"*\t\tW5HSYBBJGA\tcom.strongdm.leash.LeashNetworkFilter (1.0/1)\tLeashNetworkFilter\t[activated waiting for user]\n"

// fakeSystemextensionsctl points systemextensionsctlPath at a temp script that
// prints output and exits with code. Restored via t.Cleanup. Not parallel-safe
// (mutates the package var).
func fakeSystemextensionsctl(t *testing.T, output string, code int) {
	t.Helper()
	script := filepath.Join(t.TempDir(), "systemextensionsctl")
	body := "#!/bin/sh\ncat <<'LEASH_EOF'\n" + output + "LEASH_EOF\nexit " + strconv.Itoa(code) + "\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatalf("write fake systemextensionsctl: %v", err)
	}
	orig := systemextensionsctlPath
	systemextensionsctlPath = script
	t.Cleanup(func() { systemextensionsctlPath = orig })
}

// TestLiveSystemExtensions runs the REAL systemextensionsctl against the actually
// installed extensions. Skipped unless LEASH_TEST_LIVE_EXTENSIONS is set, since it
// requires both Leash extensions to be activated on the host.
func TestLiveSystemExtensions(t *testing.T) {
	if os.Getenv("LEASH_TEST_LIVE_EXTENSIONS") == "" {
		t.Skip("set LEASH_TEST_LIVE_EXTENSIONS=1 with the Leash extensions installed+active to run")
	}
	t.Setenv("LEASH_BUNDLE_IDENTIFIER", "")
	es, ne, esDet, neDet := querySystemExtensions(endpointSecurityExtensionID(), networkFilterExtensionID())
	t.Logf("live: ES=%v %q  NE=%v %q", es, esDet, ne, neDet)
	if es != extActive || ne != extActive {
		t.Fatalf("live extensions not both active: es=%v ne=%v", es, ne)
	}
	if err := preflightDarwinEnforcement(); err != nil {
		t.Fatalf("live preflight should pass with both active, got: %v", err)
	}
}

func TestPreflightDarwinEnforcementActive(t *testing.T) {
	t.Setenv("LEASH_BUNDLE_IDENTIFIER", "") // pin to the default ids
	fakeSystemextensionsctl(t, fakeListBothActive, 0)

	es, ne, _, _ := querySystemExtensions(endpointSecurityExtensionID(), networkFilterExtensionID())
	if es != extActive || ne != extActive {
		t.Fatalf("querySystemExtensions = (%v, %v), want (active, active)", es, ne)
	}
	if err := preflightDarwinEnforcement(); err != nil {
		t.Fatalf("both active should pass preflight, got: %v", err)
	}
}

func TestPreflightDarwinEnforcementNEWaiting(t *testing.T) {
	t.Setenv("LEASH_BUNDLE_IDENTIFIER", "")
	fakeSystemextensionsctl(t, fakeListNEWaiting, 0)

	err := preflightDarwinEnforcement()
	if err == nil {
		t.Fatal("ES active but NE waiting-for-user should hard-stop")
	}
	for _, want := range []string{networkFilterExtensionID(), "activated waiting for user", "will not start"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err.Error(), want)
		}
	}
}

func TestPreflightDarwinEnforcementExit69(t *testing.T) {
	t.Setenv("LEASH_BUNDLE_IDENTIFIER", "")
	fakeSystemextensionsctl(t, "Operation not permitted\n", 69)

	err := preflightDarwinEnforcement()
	if err == nil {
		t.Fatal("exit 69 (EX_NOPERM) should hard-stop")
	}
	// State is unknown and the underlying reason is surfaced for diagnosis.
	for _, want := range []string{"unknown (could not query systemextensionsctl)", "Operation not permitted", "will not start"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err.Error(), want)
		}
	}
}
