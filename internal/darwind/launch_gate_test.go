package darwind

import (
	"strings"
	"testing"

	"github.com/strongdm/leash/internal/macext"
)

func TestEnforcementGaps(t *testing.T) {
	ready := macext.DaemonHealth{
		Components:    []string{"leash.app", "leash.es", "leash.netfilter", "leash.proxy"},
		PolicyVersion: "abc",
		PolicyApplied: []string{"leash.es", "leash.netfilter"},
	}
	if gaps := enforcementGaps(ready); len(gaps) != 0 {
		t.Fatalf("ready daemon has gaps: %v", gaps)
	}
	for _, tc := range []struct {
		name string
		edit func(*macext.DaemonHealth)
		want string
	}{
		{"no policy", func(h *macext.DaemonHealth) { h.PolicyVersion = ""; h.PolicyApplied = nil }, "no compiled policy"},
		{"no ES", func(h *macext.DaemonHealth) { h.Components = []string{"leash.netfilter", "leash.proxy"} }, "leash.es is not connected"},
		{"no filter", func(h *macext.DaemonHealth) { h.Components = []string{"leash.es", "leash.proxy"} }, "leash.netfilter is not connected"},
		{"no proxy", func(h *macext.DaemonHealth) { h.Components = []string{"leash.es", "leash.netfilter"} }, "leash.proxy is not connected"},
		{"stale ES", func(h *macext.DaemonHealth) { h.PolicyApplied = []string{"leash.netfilter"} }, "leash.es has not applied policy abc"},
		{"stale filter", func(h *macext.DaemonHealth) { h.PolicyApplied = []string{"leash.es"} }, "leash.netfilter has not applied policy abc"},
	} {
		h := ready
		h.Components = append([]string(nil), ready.Components...)
		h.PolicyApplied = append([]string(nil), ready.PolicyApplied...)
		tc.edit(&h)
		gaps := enforcementGaps(h)
		if !strings.Contains(strings.Join(gaps, "|"), tc.want) {
			t.Fatalf("%s: gaps %v, want one containing %q", tc.name, gaps, tc.want)
		}
	}
	if err := enforcementGateError([]string{"leash.es is not connected to the daemon"}, "60s"); err == nil || !strings.Contains(err.Error(), "will not run the command") {
		t.Fatalf("gate error: %v", err)
	}
}

func TestGateTracked(t *testing.T) {
	h := macext.DaemonHealth{TrackedPIDs: []int{10, 42}}
	if !gateTracked(h, 42) || gateTracked(h, 7) {
		t.Fatal("gateTracked")
	}
}
