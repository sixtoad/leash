package transpiler_test

import (
	"bytes"
	"testing"

	"github.com/strongdm/leash/internal/lsm"
	"github.com/strongdm/leash/internal/policy"
	"github.com/strongdm/leash/internal/transpiler"
)

// The file-open and exec LSMs are always attached and default to deny unless a
// rule permits the root path "/". The built-in bootstrap policy (used when no
// policy file is configured) must therefore keep transpiling to an allow rule
// on "/" for both categories, or a policy-less run could not start a workload.
func TestDefaultBootstrapPolicyPermitsRootForOpenAndExec(t *testing.T) {
	ps, _, err := transpiler.NewCedarToLeashTranspiler().TranspileFromString(policy.DefaultCedar())
	if err != nil {
		t.Fatalf("transpile default policy: %v", err)
	}
	allowsRoot := func(rules []lsm.PolicyRule) bool {
		for _, r := range rules {
			if r.Action == lsm.PolicyAllow && string(bytes.TrimRight(r.Path[:r.PathLen], "\x00")) == "/" {
				return true
			}
		}
		return false
	}
	if !allowsRoot(ps.Open) {
		t.Errorf("default policy has no file-open allow on \"/\": %v", ps.Open)
	}
	if !allowsRoot(ps.Exec) {
		t.Errorf("default policy has no exec allow on \"/\": %v", ps.Exec)
	}
}
