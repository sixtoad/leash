//go:build darwin

package darwind

import (
	"os/exec"
	"strings"

	"github.com/strongdm/leash/internal/macext"
)

// Native macOS (`--darwin`) enforcement is the Endpoint Security (ES) and
// Network Extension (NE) system extensions. There is no second layer behind
// them (see docs/MACOS.md): if either is not activated, that half of the policy
// is simply not enforced. So, unlike the Linux eBPF-LSM preflight, there is no
// degraded mode and no opt-out: leash refuses to start (decideDarwinEnforcement).
//
// The check is cgo-free on purpose: the daemon is built CGO_ENABLED=0 and is
// not an entitled process, so the entitled-only facts (Full Disk Access for ES,
// the NE content filter's isEnabled) are out of its reach. Those are covered at
// workload launch instead, by the readiness the running extensions report to
// the daemon, and by `leash doctor` (internal/doctor/darwin.go).

// systemextensionsctlPath is the tool the preflight shells out to. It is a var
// so tests can point it at a fake that prints a realistic listing.
var systemextensionsctlPath = "/usr/bin/systemextensionsctl"

// querySystemExtensions runs `systemextensionsctl list` once and returns the ES
// and NE activation states. A query failure (including EX_NOPERM, exit 69,
// without admin rights) is StateUnknown for both, with the reason, so the hard
// stop fails safe and is diagnosable.
func querySystemExtensions(esID, neID string) (es, ne macext.State, reason string) {
	out, err := exec.Command(systemextensionsctlPath, "list").CombinedOutput()
	if err != nil {
		reason = strings.TrimSpace(err.Error())
		if first := strings.TrimSpace(string(out)); first != "" {
			reason += ": " + strings.SplitN(first, "\n", 2)[0]
		}
		return macext.StateUnknown, macext.StateUnknown, reason
	}
	return macext.Parse(string(out), esID), macext.Parse(string(out), neID), ""
}

// preflightDarwinEnforcement verifies the native macOS enforcement layer is
// activated before leash relies on it, and returns an error (leash does not
// start) otherwise. It is a var so tests of unrelated preFlight behaviour can
// stub out the systemextensionsctl probe.
var preflightDarwinEnforcement = func() error {
	esID := macext.EndpointSecurityExtensionID()
	neID := macext.NetworkFilterExtensionID()
	es, ne, reason := querySystemExtensions(esID, neID)
	return decideDarwinEnforcement(esID, neID, es, ne, reason)
}
