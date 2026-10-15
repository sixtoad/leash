package lsm

import (
	"runtime"
	"testing"
)

func mustConnectRule(t *testing.T, line string) PolicyRule {
	t.Helper()
	r, err := parsePolicyLine(line, 1)
	if err != nil {
		t.Fatalf("parse %q: %v", line, err)
	}
	return r
}

// effectiveConnectDefault runs the manager's decision through LoadPolicies
// (no BPF collection loaded) and returns the kernel default verdict that
// would be written to connect_default_policy.
func effectiveConnectDefault(t *testing.T, ps *PolicySet) bool {
	t.Helper()
	l, err := NewConnectLsm("/sys/fs/cgroup/leash-test", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.LoadPolicies(ConvertToConnectRules(ps.Connect), connectDefaultOverride(ps)); err != nil {
		t.Fatal(err)
	}
	return l.defaultPolicyResult
}

// Issue #118: a policy that never mentions the network must default to deny
// in the kernel, matching the proxy (which also defaults to deny).
func TestConnectDefaultDecision(t *testing.T) {
	cases := []struct {
		name      string
		ps        *PolicySet
		wantAllow bool
	}{
		{
			name:      "no connect rules, no explicit default -> deny",
			ps:        &PolicySet{Open: []PolicyRule{mustConnectRule(t, "allow file.open /tmp/")}},
			wantAllow: false,
		},
		{
			name:      "empty policy set -> deny",
			ps:        &PolicySet{},
			wantAllow: false,
		},
		{
			name:      "explicit deny default, no rules -> deny",
			ps:        &PolicySet{ConnectDefaultExplicit: true, ConnectDefaultAllow: false},
			wantAllow: false,
		},
		{
			name:      "explicit allow default, no rules -> allow",
			ps:        &PolicySet{ConnectDefaultExplicit: true, ConnectDefaultAllow: true},
			wantAllow: true,
		},
		{
			name:      "implicit allow (merged permit *), no rules -> allow",
			ps:        &PolicySet{ConnectDefaultAllow: true},
			wantAllow: true,
		},
		{
			name:      "permit Host * rule -> allow",
			ps:        &PolicySet{Connect: []PolicyRule{mustConnectRule(t, "allow net.send *")}, ConnectDefaultAllow: true},
			wantAllow: true,
		},
		{
			name:      "specific IP allow only -> deny default",
			ps:        &PolicySet{Connect: []PolicyRule{mustConnectRule(t, "allow net.send 1.1.1.1")}},
			wantAllow: false,
		},
		{
			name: "explicit deny wins over permit *",
			ps: &PolicySet{
				Connect:                []PolicyRule{mustConnectRule(t, "allow net.send *")},
				ConnectDefaultExplicit: true,
				ConnectDefaultAllow:    false,
			},
			wantAllow: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := effectiveConnectDefault(t, tc.ps); got != tc.wantAllow {
				t.Fatalf("effective default allow = %v, want %v", got, tc.wantAllow)
			}
		})
	}
}

func TestConnectDefaultOverride(t *testing.T) {
	if got := connectDefaultOverride(nil); got != nil {
		t.Fatalf("nil policy: got %v, want nil", *got)
	}
	if got := connectDefaultOverride(&PolicySet{}); got != nil {
		t.Fatalf("empty policy: got %v, want nil (LoadPolicies falls back to deny)", *got)
	}
	got := connectDefaultOverride(&PolicySet{ConnectDefaultExplicit: true})
	if got == nil || *got {
		t.Fatalf("explicit deny: got %v, want &false", got)
	}
	got = connectDefaultOverride(&PolicySet{ConnectDefaultAllow: true})
	if got == nil || !*got {
		t.Fatalf("implicit allow with no rules: got %v, want &true", got)
	}
	r := mustConnectRule(t, "allow net.send 1.1.1.1")
	if got := connectDefaultOverride(&PolicySet{Connect: []PolicyRule{r}}); got != nil {
		t.Fatalf("rules present, implicit: got %v, want nil (derive from rules)", *got)
	}
}

// The connect LSM must be created even when the policy has no connect rules.
// Skipped on Linux, where the background attach could touch a real kernel; on
// other platforms the attach fails immediately (stub loader) and is ignored.
func TestUpdateConnectLSMCreatesWithoutConnectRules(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("avoids a real BPF attach attempt; covered by the pure decision tests")
	}
	m := NewLSMManager("/sys/fs/cgroup/leash-test", nil, false)
	if err := m.updateConnectLSM(&PolicySet{Open: []PolicyRule{mustConnectRule(t, "allow file.open /tmp/")}}); err != nil {
		t.Fatalf("updateConnectLSM: %v", err)
	}
	if m.connectLsm == nil {
		t.Fatal("connect LSM was not created for a policy without connect rules (issue #118)")
	}
	if m.connectLsm.defaultPolicyResult {
		t.Fatal("connect LSM default must be deny when the policy has no connect rules")
	}
	m.attachWG.Wait()
}
