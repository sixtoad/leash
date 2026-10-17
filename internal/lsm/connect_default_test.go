package lsm

import (
	"math/rand"
	"runtime"
	"testing"
)

// Host::"*" is the connect default, not a rule: a default-deny plus an
// allowlist must still permit the listed destinations (#135).
func TestConnectDefaultRuleIsNotAMatchingRule(t *testing.T) {
	rng := rand.New(rand.NewSource(1354))
	const ip = uint32(10<<24 | 1)
	denyAll := connectRuleForTest(PolicyDeny, 0, 0, "*")
	allowAll := connectRuleForTest(PolicyAllow, 0, 0, "*")
	if !IsConnectDefaultRule(PolicyRule{Action: PolicyDeny, Operation: OpConnect, Hostname: denyAll.Hostname, HostnameLen: 1}) {
		t.Fatal(`bare Host::"*" not recognised as the default rule`)
	}
	if IsConnectDefaultRule(PolicyRule{Action: PolicyDeny, Operation: OpConnect, Hostname: denyAll.Hostname, HostnameLen: 1, DestPort: 443}) {
		t.Fatal(`port-scoped Host::"*:443" treated as the default`)
	}

	allowlist := []ConnectPolicyRule{denyAll, connectRuleForTest(PolicyAllow, 0, 0, "api.openai.com"), connectRuleForTest(PolicyAllow, ip, 443, "")}
	denylist := []ConnectPolicyRule{allowAll, connectRuleForTest(PolicyDeny, 0, 0, "evil.test"), connectRuleForTest(PolicyDeny, ip, 22, "")}
	for i := 0; i < precedenceShuffles; i++ {
		// Proxy checker; the runtime passes PolicySet.ConnectDefaultAllow.
		pc := newLegacyChecker(shuffled(rng, allowlist), false, nil)
		if !pc.CheckConnect("api.openai.com", "", 443) || !pc.CheckConnect("", "10.0.0.1", 443) {
			t.Fatalf("shuffle %d: default-deny shadowed an allowlisted destination", i)
		}
		if pc.CheckConnect("example.com", "", 443) || pc.CheckConnect("", "10.0.0.1", 80) {
			t.Fatalf("shuffle %d: unlisted destination allowed under default deny", i)
		}
		pc = newLegacyChecker(shuffled(rng, denylist), true, nil)
		if pc.CheckConnect("evil.test", "", 443) || pc.CheckConnect("", "10.0.0.1", 22) {
			t.Fatalf("shuffle %d: forbid lost under default allow", i)
		}
		if !pc.CheckConnect("example.com", "", 443) {
			t.Fatalf("shuffle %d: default allow not applied", i)
		}

		// Kernel: the "*" rule never becomes a BPF rule; the default (the
		// explicit override the manager passes) does the work.
		deny := false
		l := &ConnectLsm{}
		if err := l.LoadPolicies(shuffled(rng, []ConnectPolicyRule{denyAll, connectRuleForTest(PolicyAllow, ip, 443, "")}), &deny); err != nil {
			t.Fatal(err)
		}
		if len(l.policyRules) != 1 || l.defaultPolicyResult {
			t.Fatalf("shuffle %d: kernel rules %+v default %v", i, l.policyRules, l.defaultPolicyResult)
		}
		if connectBPFDecision(l.policyRules, l.defaultPolicyResult, ip, 443) != PolicyAllow ||
			connectBPFDecision(l.policyRules, l.defaultPolicyResult, ip, 80) != PolicyDeny ||
			connectBPFDecision(l.policyRules, l.defaultPolicyResult, ip+1, 443) != PolicyDeny {
			t.Fatalf("shuffle %d: kernel default-deny allowlist decisions wrong", i)
		}
	}
}

// --- issue #118: connect LSM always attached, default-deny without rules ---

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

// fakeConnectMaps models the three connect policy maps and the kernel's
// check_connect_policy lookup (lsm_connect.bpf.c) over them.
type fakeConnectMaps struct {
	defaultPolicy uint32
	unaddressed   uint32
	numRules      int32
	numSet        bool
	rules         map[uint32]ConnectPolicyRuleBPF
}

type fakeMap struct {
	put func(key, value interface{}) error
}

func (f fakeMap) Put(key, value interface{}) error { return f.put(key, value) }

func (f *fakeConnectMaps) lookup(name string) connectMapPutter {
	switch name {
	case "connect_default_policy":
		return fakeMap{func(_, v interface{}) error { f.defaultPolicy = *v.(*uint32); return nil }}
	case "connect_unaddressed_policy":
		return fakeMap{func(_, v interface{}) error { f.unaddressed = *v.(*uint32); return nil }}
	case "connect_num_rules":
		return fakeMap{func(_, v interface{}) error { f.numRules = *v.(*int32); f.numSet = true; return nil }}
	case "connect_policy_rules":
		return fakeMap{func(k, v interface{}) error { f.rules[k.(uint32)] = *v.(*ConnectPolicyRuleBPF); return nil }}
	}
	return nil
}

// allows mirrors check_connect_policy: no count entry => deny; count <= 0 =>
// default; first matching rule wins; else default.
func (f *fakeConnectMaps) allows(ip uint32, port uint16) bool {
	if !f.numSet {
		return false
	}
	if f.numRules <= 0 {
		return f.defaultPolicy == 1
	}
	for i := uint32(0); i < uint32(f.numRules); i++ {
		r, ok := f.rules[i]
		if !ok {
			continue
		}
		if r.DestIP != 0 && r.DestIP != ip {
			continue
		}
		if r.DestPort != 0 && r.DestPort != port {
			continue
		}
		return r.Action == PolicyAllow
	}
	return f.defaultPolicy == 1
}

// Review finding on #118: a reload that drops to zero connect rules must
// retire the previously loaded kernel rules; before the fix num_rules was
// never rewritten and 1.1.1.1 stayed allowed in the kernel.
func TestConnectReloadToZeroRulesRetiresKernelRules(t *testing.T) {
	l, err := NewConnectLsm("/sys/fs/cgroup/leash-test", nil)
	if err != nil {
		t.Fatal(err)
	}
	maps := &fakeConnectMaps{rules: map[uint32]ConnectPolicyRuleBPF{}}
	oneOneOneOne := uint32(1<<24 | 1<<16 | 1<<8 | 1)

	withRule := &PolicySet{Connect: []PolicyRule{mustConnectRule(t, "allow net.send 1.1.1.1")}}
	if err := l.LoadPolicies(ConvertToConnectRules(withRule.Connect), connectDefaultOverride(withRule)); err != nil {
		t.Fatal(err)
	}
	if err := l.writePolicyMaps(maps.lookup); err != nil {
		t.Fatal(err)
	}
	if !maps.allows(oneOneOneOne, 53) {
		t.Fatal("setup: 1.1.1.1 should be allowed while the rule is loaded")
	}

	empty := &PolicySet{}
	if err := l.LoadPolicies(ConvertToConnectRules(empty.Connect), connectDefaultOverride(empty)); err != nil {
		t.Fatal(err)
	}
	if err := l.writePolicyMaps(maps.lookup); err != nil {
		t.Fatal(err)
	}
	if maps.numRules != 0 {
		t.Fatalf("connect_num_rules = %d after reload to zero rules, want 0", maps.numRules)
	}
	if maps.allows(oneOneOneOne, 53) {
		t.Fatal("1.1.1.1 still allowed by the kernel after the rule was removed")
	}
}

func TestConnectWritePolicyMapsMissingMap(t *testing.T) {
	l, err := NewConnectLsm("/sys/fs/cgroup/leash-test", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.writePolicyMaps(func(string) connectMapPutter { return nil }); err == nil {
		t.Fatal("missing maps must be an error, not a silent no-op")
	}
}
