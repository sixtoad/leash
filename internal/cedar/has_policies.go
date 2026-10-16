package cedar

import (
	cedarlib "github.com/cedar-policy/cedar-go"

	"github.com/strongdm/leash/internal/lsm"
)

// HasPolicies reports whether a compiled PolicySet's Cedar source holds at
// least one policy (a strict policy can be meaningful without producing a
// kernel rule: plugin and MCP policies, or forbids under the default deny).
func HasPolicies(ps *lsm.PolicySet) bool {
	if ps == nil || ps.Source == nil {
		return false
	}
	set, err := cedarlib.NewPolicySetFromBytes(ps.Source.Name, []byte(ps.Source.Text))
	if err != nil {
		return false
	}
	for range set.All() {
		return true
	}
	return false
}
