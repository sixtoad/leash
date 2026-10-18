package transpiler_test

import (
	"bytes"
	"testing"

	"github.com/strongdm/leash/internal/cedar"
	"github.com/strongdm/leash/internal/lsm"
	"github.com/strongdm/leash/internal/policy"
)

// The file-open and exec LSMs are always attached and default to deny unless a
// rule permits the root path "/". The built-in bootstrap policy (used when no
// policy file is configured) must therefore keep compiling to an allow rule
// on "/" for both categories, or a policy-less run could not start a workload.
func TestDefaultBootstrapPolicyPermitsRootForOpenAndExec(t *testing.T) {
	// Compiled the way a load compiles it (strict Cedar, the default
	// dialect, to kernel tables).
	comp, err := cedar.CompileString("default.cedar", policy.DefaultCedar())
	if err != nil {
		t.Fatalf("compile default policy: %v", err)
	}
	ps := comp.Policies
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
