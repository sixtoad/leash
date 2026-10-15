package macsync

import (
	"math/rand"
	"testing"

	"github.com/strongdm/leash/internal/lsm"
)

// Issue #135: the macOS network filter returns the first matching rule, so a
// forbid must reach it ahead of every permit, whatever the input order.
func TestConvertPolicyToMacRules_NetworkDeniesFirstInAnyOrder(t *testing.T) {
	host := func(action int32, name string) lsm.PolicyRule {
		r := lsm.PolicyRule{Action: action, Operation: lsm.OpConnect, HostnameLen: int32(len(name))}
		copy(r.Hostname[:], name)
		return r
	}
	base := []lsm.PolicyRule{
		host(lsm.PolicyAllow, "api.example.com"),
		host(lsm.PolicyDeny, "example.com"),
		host(lsm.PolicyAllow, "ok.test"),
		host(lsm.PolicyDeny, "bad.test"),
	}
	rng := rand.New(rand.NewSource(135))
	for i := 0; i < 200; i++ {
		in := append([]lsm.PolicyRule(nil), base...)
		rng.Shuffle(len(in), func(a, b int) { in[a], in[b] = in[b], in[a] })
		_, network := ConvertPolicyToMacRules(&lsm.PolicySet{Connect: in})
		if len(network) != len(base) {
			t.Fatalf("got %d network rules, want %d", len(network), len(base))
		}
		seenAllow := false
		for _, r := range network {
			if r.Action == "allow" {
				seenAllow = true
			} else if seenAllow {
				t.Fatalf("shuffle %d: deny %q after an allow: %+v", i, r.TargetValue, network)
			}
		}
	}
}
