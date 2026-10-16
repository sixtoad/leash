package lsm

import (
	"math/rand"
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
