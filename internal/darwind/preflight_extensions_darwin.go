//go:build darwin

package darwind

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/strongdm/leash/internal/macext"
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
//      list` output (the parser in internal/macext is ported from the Swift
//      interpretExtensionEntry — confirm it matches; extend the test fixture).
//   2. DECIDE THE DEFAULT: this scaffold WARNS and continues by default (mirrors
//      Linux --require-lsm). But native macOS has no proxy fallback, so "continue
//      unenforced" is more dangerous than on Linux — consider making the hard
//      stop the default here, with an explicit opt-out to run unenforced. This is
//      the same warn-vs-require call we made for Linux; pick per product intent.
//   3. systemextensionsctl exits 69 (EX_NOPERM) without admin; the Swift app
//      treats that as "assume inactive". systemExtensionState reports it as
//      macext.StateUnknown — confirm that's the behavior you want.
//
// Full Disk Access and the "is the filter actually switched on" question are
// answered by `leash doctor` (internal/doctor), which reads them from the
// running daemon rather than guessing: LeashES exits before it ever connects
// when FDA is denied, and a component missing from the daemon's client registry
// is not receiving rules. See internal/doctor/darwin.go.

// requireEnforcement reports whether a missing native enforcement layer should
// be fatal (LEASH_REQUIRE_ENFORCEMENT), the macOS analog of --require-lsm.
func requireEnforcement() bool {
	v := strings.TrimSpace(os.Getenv("LEASH_REQUIRE_ENFORCEMENT"))
	return v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
}

// systemExtensionState queries `systemextensionsctl list` (the same tool the
// Leash.app GUI uses) and returns the activation state of id.
func systemExtensionState(id string) macext.State {
	out, err := exec.Command("/usr/bin/systemextensionsctl", "list").CombinedOutput()
	if err != nil {
		// Includes EX_NOPERM (69) when run without admin rights. Unknown, not
		// missing: the command never answered, so the only thing established is
		// that we could not ask. Either way it is not StateActive, so the
		// preflight below still refuses to assume enforcement.
		return macext.StateUnknown
	}
	return macext.Parse(string(out), id)
}

// preflightDarwinEnforcement verifies the native macOS enforcement layer is
// actually active before leash relies on it. By default it warns and continues
// (the agent runs UNENFORCED); LEASH_REQUIRE_ENFORCEMENT makes it a hard stop.
func preflightDarwinEnforcement() error {
	esID := macext.EndpointSecurityExtensionID()
	neID := macext.NetworkFilterExtensionID()
	es := systemExtensionState(esID)
	ne := systemExtensionState(neID)
	if es == macext.StateActive && ne == macext.StateActive {
		return nil
	}

	advice := darwinEnforcementAdvice(esID, neID, es, ne)
	if requireEnforcement() {
		return fmt.Errorf("native macOS enforcement is unavailable and LEASH_REQUIRE_ENFORCEMENT is set, so leash will not start.\n%s", advice)
	}
	log.Printf("WARNING: native macOS enforcement is unavailable — the agent will run UNENFORCED (native --darwin mode has no proxy fallback). Set LEASH_REQUIRE_ENFORCEMENT=1 to make this fatal.\n%s", advice)
	return nil
}

func darwinEnforcementAdvice(esID, neID string, es, ne macext.State) string {
	return fmt.Sprintf(`  Endpoint Security extension (%s): %s
  Network Filter extension   (%s): %s
Activate them:
  1. open Leash.app and click Activate for both extensions
  2. approve in System Settings ▸ General ▸ Login Items & Extensions
  3. grant the Endpoint Security extension Full Disk Access
     (System Settings ▸ Privacy & Security ▸ Full Disk Access)
See docs/MACOS.md, or run 'leash doctor' for the full macOS readiness report.`, esID, es.Describe(), neID, ne.Describe())
}
