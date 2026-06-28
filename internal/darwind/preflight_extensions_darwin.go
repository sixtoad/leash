//go:build darwin

package darwind

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

// Native macOS (`--darwin`) enforcement uses the Endpoint Security (ES) and
// Network Extension (NE) system extensions. Unlike Linux, there is NO Layer-2
// MITM proxy fallback (see docs/MACOS.md): if the extensions are not activated,
// NOTHING enforces and today leash runs silently unprotected. This preflight is
// the macOS analog of the Linux eBPF-LSM preflight (internal/runner/
// lsm_preflight.go): detect the prerequisite, and surface it instead of failing
// silent.
//
// TODO(macOS agent): this is a scaffold to finish and verify on a real Mac.
//   1. Verify systemextensionsctl parsing against captured `systemextensionsctl
//      list` output (the parser in extension_state.go is ported from the Swift
//      interpretExtensionEntry — confirm it matches; extend the test fixture).
//   2. Add Full Disk Access detection for the ES extension. There is no public
//      API; options: attempt an ES client connection and catch the permission
//      error, or probe a TCC-gated path. Today FDA is NOT checked.
//   3. NE "enabled" is more than extension activation — the content filter must
//      also be turned on (NEFilterManager.isEnabled). Decide whether to check it
//      here (likely needs cgo/Swift helper) or rely on the extension state.
//   4. DECIDE THE DEFAULT: this scaffold WARNS and continues by default (mirrors
//      Linux --require-lsm). But native macOS has no proxy fallback, so "continue
//      unenforced" is more dangerous than on Linux — consider making the hard
//      stop the default here, with an explicit opt-out to run unenforced. This is
//      the same warn-vs-require call we made for Linux; pick per product intent.
//   5. systemextensionsctl exits 69 (EX_NOPERM) without admin; the Swift app
//      treats that as "assume inactive". systemExtensionState currently treats a
//      non-zero exit as not-installed — confirm that's the behavior you want.

// requireEnforcement reports whether a missing native enforcement layer should
// be fatal (LEASH_REQUIRE_ENFORCEMENT), the macOS analog of --require-lsm.
func requireEnforcement() bool {
	v := strings.TrimSpace(os.Getenv("LEASH_REQUIRE_ENFORCEMENT"))
	return v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
}

// systemExtensionState queries `systemextensionsctl list` (the same tool the
// Leash.app GUI uses) and returns the activation state of id.
func systemExtensionState(id string) extensionState {
	out, err := exec.Command("/usr/bin/systemextensionsctl", "list").CombinedOutput()
	if err != nil {
		// Includes EX_NOPERM (69) when run without admin rights. Treat as
		// not-installed/unknown rather than guessing it's active.
		return extNotInstalled
	}
	return parseExtensionState(string(out), id)
}

// preflightDarwinEnforcement verifies the native macOS enforcement layer is
// actually active before leash relies on it. By default it warns and continues
// (the agent runs UNENFORCED); LEASH_REQUIRE_ENFORCEMENT makes it a hard stop.
func preflightDarwinEnforcement() error {
	esID := endpointSecurityExtensionID()
	neID := networkFilterExtensionID()
	es := systemExtensionState(esID)
	ne := systemExtensionState(neID)
	if es == extActive && ne == extActive {
		return nil
	}

	advice := darwinEnforcementAdvice(esID, neID, es, ne)
	if requireEnforcement() {
		return fmt.Errorf("native macOS enforcement is unavailable and LEASH_REQUIRE_ENFORCEMENT is set, so leash will not start.\n%s", advice)
	}
	log.Printf("WARNING: native macOS enforcement is unavailable — the agent will run UNENFORCED (native --darwin mode has no proxy fallback). Set LEASH_REQUIRE_ENFORCEMENT=1 to make this fatal.\n%s", advice)
	return nil
}

func darwinEnforcementAdvice(esID, neID string, es, ne extensionState) string {
	return fmt.Sprintf(`  Endpoint Security extension (%s): %s
  Network Filter extension   (%s): %s
Activate them:
  1. open Leash.app and click Activate for both extensions
  2. approve in System Settings ▸ General ▸ Login Items & Extensions
  3. grant the Endpoint Security extension Full Disk Access
     (System Settings ▸ Privacy & Security ▸ Full Disk Access)
See docs/MACOS.md.`, esID, es, neID, ne)
}
