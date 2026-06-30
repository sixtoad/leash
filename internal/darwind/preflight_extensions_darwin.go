//go:build darwin

package darwind

import (
	"os/exec"
	"strings"
)

// Native macOS (`--darwin`) enforcement uses the Endpoint Security (ES) and
// Network Extension (NE) system extensions. Unlike Linux, there is NO Layer-2
// MITM proxy fallback (see docs/MACOS.md): if the extensions are not activated,
// NOTHING enforces. This preflight is the macOS analog of the Linux eBPF-LSM
// preflight (internal/runner/lsm_preflight.go) — but because there is no
// fallback layer, the policy is a HARD STOP (decideDarwinEnforcement) rather
// than the warn-and-degrade used on Linux.
//
// The check is cgo-free on purpose: the daemon is built CGO_ENABLED=0 and is not
// an entitled process, so the authoritative entitled-only signals — Full Disk
// Access for the ES extension and the NE content-filter `isEnabled` toggle — are
// out of its reach by design. Those are enforced and surfaced by the entitled
// extensions at runtime. `systemextensionsctl` is the OS's own source of truth
// for activation and needs no entitlement.

// querySystemExtensions runs `systemextensionsctl list` once and returns the ES
// and NE activation states plus their raw [state] detail. On any query failure —
// including EX_NOPERM (exit 69) when run without admin rights — both states are
// reported as extUnknown rather than guessed as active, so the hard stop fails
// safe.
// systemextensionsctlPath is the tool the daemon shells out to. It is a var so
// tests can point it at a fake that emits a realistic listing, exercising the
// full exec→parse→decide pipeline without installed extensions.
var systemextensionsctlPath = "/usr/bin/systemextensionsctl"

func querySystemExtensions(esID, neID string) (es, ne extensionState, esDetail, neDetail string) {
	out, err := exec.Command(systemextensionsctlPath, "list").CombinedOutput()
	if err != nil {
		// Surface why the probe failed (exec error + first line of any output,
		// e.g. EX_NOPERM) so a hard stop on a genuinely-configured machine is
		// diagnosable rather than an opaque "unknown".
		reason := strings.TrimSpace(err.Error())
		if first := strings.TrimSpace(string(out)); first != "" {
			reason += ": " + strings.SplitN(first, "\n", 2)[0]
		}
		return extUnknown, extUnknown, reason, reason
	}
	es, esDetail = parseExtensionStateDetail(string(out), esID)
	ne, neDetail = parseExtensionStateDetail(string(out), neID)
	return es, ne, esDetail, neDetail
}

// preflightDarwinEnforcement verifies the native macOS enforcement layer is
// active before leash relies on it, and hard-stops daemon startup (returns an
// error) otherwise. See decideDarwinEnforcement for the policy. It is a var so
// tests of unrelated preFlight behavior can stub out the systemextensionsctl
// probe (which would otherwise hard-stop on any machine lacking the extensions).
var preflightDarwinEnforcement = func() error {
	esID := endpointSecurityExtensionID()
	neID := networkFilterExtensionID()
	es, ne, esDetail, neDetail := querySystemExtensions(esID, neID)
	return decideDarwinEnforcement(esID, neID, es, ne, esDetail, neDetail)
}
