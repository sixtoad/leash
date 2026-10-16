package lsm

import (
	"runtime"
	"testing"
)

func mustRules(t *testing.T, lines ...string) []PolicyRule {
	t.Helper()
	out := make([]PolicyRule, 0, len(lines))
	for _, line := range lines {
		out = append(out, mustConnectRule(t, line))
	}
	return out
}

// effectiveOpenDefault runs the policy set through OpenLsm.LoadPolicies (no BPF
// collection loaded) exactly as updateOpenLSM does and returns the default
// verdict that would be written to open_default_policy.
func effectiveOpenDefault(t *testing.T, ps *PolicySet) bool {
	t.Helper()
	l, err := NewOpenLsm("/sys/fs/cgroup/leash-test", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.LoadPolicies(ConvertToFileOpenRules(ps.Open)); err != nil {
		t.Fatal(err)
	}
	if got := rootPathPolicy(l.policyRules); got != l.defaultPolicyResult {
		t.Fatalf("rootPathPolicy=%v disagrees with loaded default %v", got, l.defaultPolicyResult)
	}
	return l.defaultPolicyResult
}

func effectiveExecDefault(t *testing.T, ps *PolicySet) bool {
	t.Helper()
	l, err := NewExecLsm("/sys/fs/cgroup/leash-test", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.LoadPolicies(ConvertToExecRules(ps.Exec)); err != nil {
		t.Fatal(err)
	}
	if got := execDefaultAllow(l.policyRules); got != l.defaultPolicyResult {
		t.Fatalf("execDefaultAllow=%v disagrees with loaded default %v", got, l.defaultPolicyResult)
	}
	return l.defaultPolicyResult
}

// A policy that never mentions files or exec must default to deny in the
// kernel (Cedar's default), not leave the category unenforced. Each category
// is decided only from its own rules.
func TestOpenExecDefaultDecision(t *testing.T) {
	cases := []struct {
		name          string
		ps            *PolicySet
		wantOpenAllow bool
		wantExecAllow bool
	}{
		{
			name: "empty policy set -> deny both",
			ps:   &PolicySet{},
		},
		{
			name: "network-only policy -> deny both",
			ps:   &PolicySet{Connect: mustRules(t, "allow net.send *"), ConnectDefaultAllow: true},
		},
		{
			name:          "exec permits / but no file rules -> exec allow, open deny",
			ps:            &PolicySet{Exec: mustRules(t, "allow proc.exec /")},
			wantExecAllow: true,
		},
		{
			name:          "file permits / but no exec rules -> open allow, exec deny",
			ps:            &PolicySet{Open: mustRules(t, "allow file.open /")},
			wantOpenAllow: true,
		},
		{
			name: "specific exec allow only, no file rules -> deny both defaults",
			ps:   &PolicySet{Exec: mustRules(t, "allow proc.exec /usr/bin/")},
		},
		{
			name: "specific file allows only -> deny default",
			ps:   &PolicySet{Open: mustRules(t, "allow file.open /usr/", "allow file.open /tmp/")},
		},
		{
			name: "deny-only rules -> deny default",
			ps:   &PolicySet{Open: mustRules(t, "deny file.open /etc/shadow"), Exec: mustRules(t, "deny proc.exec /usr/bin/curl")},
		},
		{
			name: "bootstrap-style permissive policy -> allow both",
			ps: &PolicySet{
				Open:                mustRules(t, "allow file.open /"),
				Exec:                mustRules(t, "allow proc.exec /"),
				Connect:             mustRules(t, "allow net.send *"),
				ConnectDefaultAllow: true,
			},
			wantOpenAllow: true,
			wantExecAllow: true,
		},
		{
			name:          "permit / with narrower forbids -> allow default",
			ps:            &PolicySet{Open: mustRules(t, "allow file.open /", "deny file.open /etc/shadow"), Exec: mustRules(t, "allow proc.exec /", "deny proc.exec /usr/bin/curl")},
			wantOpenAllow: true,
			wantExecAllow: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := effectiveOpenDefault(t, tc.ps); got != tc.wantOpenAllow {
				t.Errorf("open default allow = %v, want %v", got, tc.wantOpenAllow)
			}
			if got := effectiveExecDefault(t, tc.ps); got != tc.wantExecAllow {
				t.Errorf("exec default allow = %v, want %v", got, tc.wantExecAllow)
			}
		})
	}
}

// The open and exec LSMs must be created even when the policy has no rules in
// their category. Skipped on Linux, where the background attach could touch a
// real kernel; elsewhere the attach fails immediately (stub loader) and is
// ignored (requireLSM=false).
func TestUpdateOpenExecLSMCreatesWithoutRules(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("avoids a real BPF attach attempt; covered by the pure decision tests")
	}
	cases := []struct {
		name string
		ps   *PolicySet
	}{
		{name: "network only", ps: &PolicySet{Connect: mustRules(t, "allow net.send 1.1.1.1")}},
		{name: "empty", ps: &PolicySet{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := NewLSMManager("/sys/fs/cgroup/leash-test", nil, false)
			if err := m.updateOpenLSM(tc.ps); err != nil {
				t.Fatalf("updateOpenLSM: %v", err)
			}
			if err := m.updateExecLSM(tc.ps); err != nil {
				t.Fatalf("updateExecLSM: %v", err)
			}
			m.attachWG.Wait()
			if m.openLsm == nil {
				t.Fatal("file open LSM was not created for a policy without file rules")
			}
			if m.execLsm == nil {
				t.Fatal("exec LSM was not created for a policy without exec rules")
			}
			if m.openLsm.defaultPolicyResult || m.execLsm.defaultPolicyResult {
				t.Fatalf("defaults must be deny without rules: open=%v exec=%v",
					m.openLsm.defaultPolicyResult, m.execLsm.defaultPolicyResult)
			}
		})
	}
}

// A policy with exec rules but no file rules attaches both programs and keeps
// each category's own decision: the exec rules still drive the exec default.
func TestUpdateExecRulesWithoutFileRules(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("avoids a real BPF attach attempt; covered by the pure decision tests")
	}
	m := NewLSMManager("/sys/fs/cgroup/leash-test", nil, false)
	ps := &PolicySet{Exec: mustRules(t, "allow proc.exec /")}
	if err := m.updateOpenLSM(ps); err != nil {
		t.Fatalf("updateOpenLSM: %v", err)
	}
	if err := m.updateExecLSM(ps); err != nil {
		t.Fatalf("updateExecLSM: %v", err)
	}
	m.attachWG.Wait()
	if m.openLsm == nil || m.execLsm == nil {
		t.Fatalf("both LSMs must be created: open=%v exec=%v", m.openLsm != nil, m.execLsm != nil)
	}
	if m.openLsm.defaultPolicyResult {
		t.Fatal("open default must be deny with no file rules")
	}
	if !m.execLsm.defaultPolicyResult || m.execLsm.numPolicyRules != 1 {
		t.Fatalf("exec rules must still apply: default=%v rules=%d", m.execLsm.defaultPolicyResult, m.execLsm.numPolicyRules)
	}
}
