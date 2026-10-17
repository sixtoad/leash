package darwind

import (
	"fmt"
	"sort"
	"strings"

	"github.com/strongdm/leash/internal/macext"
)

// The launch gate: `leash --darwin exec` starts the workload only when the
// running daemon reports that the macOS enforcement layer is actually in
// place for it. Activation (the preflight) only says the extensions may run;
// this says they are running, connected to this daemon, and enforcing its
// current policy.
//
//   - leash.es and leash.netfilter must be connected and must have applied
//     exactly the daemon's current policy tables: they enforce files, execs
//     and connections.
//   - leash.proxy must be connected: the transparent proxy is what enforces
//     host names, MCP and header rewrites; without it a TCP flow is decided
//     by address only, and a forbid on a name (or on an MCP tool) would not
//     apply.
//
// Before the workload itself runs, the gate also waits for the Endpoint
// Security extension to report leashcli's own PID as tracked (gateTracked):
// a command it never started tracking would run with no enforcement at all.

var (
	gateConnected = []string{macext.ComponentEndpointSecurity, macext.ComponentNetworkFilter, macext.ComponentTransparentProxy}
	gateApplied   = []string{macext.ComponentEndpointSecurity, macext.ComponentNetworkFilter}
)

// enforcementGaps lists what keeps the daemon's enforcement from being in
// place, as human-readable reasons; empty means the workload may start.
func enforcementGaps(h macext.DaemonHealth) []string {
	has := func(list []string, want string) bool {
		for _, c := range list {
			if c == want {
				return true
			}
		}
		return false
	}
	var gaps []string
	if strings.TrimSpace(h.PolicyVersion) == "" {
		gaps = append(gaps, "the daemon has no compiled policy")
	}
	for _, c := range gateConnected {
		if !has(h.Components, c) {
			gaps = append(gaps, fmt.Sprintf("%s is not connected to the daemon", c))
		}
	}
	for _, c := range gateApplied {
		if has(h.Components, c) && h.PolicyVersion != "" && !has(h.PolicyApplied, c) {
			gaps = append(gaps, fmt.Sprintf("%s has not applied policy %s", c, h.PolicyVersion))
		}
	}
	sort.Strings(gaps)
	return gaps
}

// gateTracked reports whether pid is in the daemon's tracked set.
func gateTracked(h macext.DaemonHealth, pid int) bool {
	for _, p := range h.TrackedPIDs {
		if p == pid {
			return true
		}
	}
	return false
}

func enforcementGateError(gaps []string, waited string) error {
	return fmt.Errorf("native macOS enforcement is not in place, so leash will not run the command (waited %s):\n  - %s\nCheck Leash.app (all three extensions active and connected) and run 'leash doctor'.",
		waited, strings.Join(gaps, "\n  - "))
}
