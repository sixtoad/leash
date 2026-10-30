//go:build darwin

package darwind

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// These tests drive the real exec -> parse -> decide pipeline against a fake
// systemextensionsctl, so the "both active, start" path runs end to end on a
// machine without the extensions installed.

const fakeListBothActive = "2 extension(s)\n" +
	"--- com.apple.system_extension.endpoint_security\n" +
	"enabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n" +
	"*\t*\t-\tcom.sixtoad.leash.LeashES (1.1.0/20260820.2)\tLeashES\t[activated enabled]\n" +
	"--- com.apple.system_extension.network_extension\n" +
	"enabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n" +
	"*\t*\t-\tcom.sixtoad.leash.LeashNetworkFilter (1.1.0/20260820.2)\tLeash Network Filter\t[activated enabled]\n"

const fakeListNEWaiting = "2 extension(s)\n" +
	"enabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n" +
	"*\t*\t-\tcom.sixtoad.leash.LeashES (1.0/1)\tLeashES\t[activated enabled]\n" +
	"*\t\t-\tcom.sixtoad.leash.LeashNetworkFilter (1.0/1)\tLeash Network Filter\t[activated waiting for user]\n"

// fakeSystemextensionsctl points systemextensionsctlPath at a script that
// prints output and exits with code. Not parallel-safe.
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

// stubEnforcementOK lets tests of unrelated preFlight behaviour run on a
// machine without the extensions.
func stubEnforcementOK(t *testing.T) {
	t.Helper()
	orig := preflightDarwinEnforcement
	preflightDarwinEnforcement = func() error { return nil }
	t.Cleanup(func() { preflightDarwinEnforcement = orig })
}

func TestPreflightDarwinEnforcementActive(t *testing.T) {
	t.Setenv("LEASH_BUNDLE_IDENTIFIER", "")
	fakeSystemextensionsctl(t, fakeListBothActive, 0)
	if err := preflightDarwinEnforcement(); err != nil {
		t.Fatalf("both active should pass, got: %v", err)
	}
}

func TestPreflightDarwinEnforcementNEWaiting(t *testing.T) {
	t.Setenv("LEASH_BUNDLE_IDENTIFIER", "")
	fakeSystemextensionsctl(t, fakeListNEWaiting, 0)
	err := preflightDarwinEnforcement()
	if err == nil {
		t.Fatal("ES active but NE waiting for user must not start")
	}
	for _, want := range []string{"com.sixtoad.leash.LeashNetworkFilter", "installed but not enabled", "will not start"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err.Error(), want)
		}
	}
}

func TestPreflightDarwinEnforcementQueryFailure(t *testing.T) {
	t.Setenv("LEASH_BUNDLE_IDENTIFIER", "")
	fakeSystemextensionsctl(t, "Operation not permitted\n", 69)
	err := preflightDarwinEnforcement()
	if err == nil {
		t.Fatal("exit 69 (EX_NOPERM) must not start")
	}
	for _, want := range []string{"unknown", "Operation not permitted", "will not start"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err.Error(), want)
		}
	}
}

func TestPreFlightStopsBeforeTouchingStateWithoutEnforcement(t *testing.T) {
	orig := preflightDarwinEnforcement
	preflightDarwinEnforcement = func() error { return fmt.Errorf("ES/NE not active") }
	t.Cleanup(func() { preflightDarwinEnforcement = orig })

	dir := t.TempDir()
	cfg := &runtimeConfig{
		PolicyPath: filepath.Join(dir, "policy.cedar"),
		SkipCgroup: true,
		ProxyPort:  "18000",
	}
	if err := preFlight(cfg); err == nil || !strings.Contains(err.Error(), "ES/NE not active") {
		t.Fatalf("preFlight must propagate the refusal, got: %v", err)
	}
	if _, err := os.Stat(cfg.PolicyPath); !os.IsNotExist(err) {
		t.Fatalf("preFlight wrote the default policy before refusing (stat err=%v)", err)
	}
}

// TestLiveSystemExtensions runs the real systemextensionsctl. Opt in with
// LEASH_TEST_LIVE_EXTENSIONS=1 on a Mac with both extensions activated.
func TestLiveSystemExtensions(t *testing.T) {
	if os.Getenv("LEASH_TEST_LIVE_EXTENSIONS") == "" {
		t.Skip("set LEASH_TEST_LIVE_EXTENSIONS=1 with the Leash extensions activated to run")
	}
	if err := preflightDarwinEnforcement(); err != nil {
		t.Fatalf("live preflight: %v", err)
	}
}
