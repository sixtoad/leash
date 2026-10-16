package lsm

import "testing"

func exactRule(action uint32, op uint32, path string) OpenPolicyRule {
	r := OpenPolicyRule{Action: action, Operation: op, PathLen: uint32(len(path)), IsDirectory: ExactPath}
	copy(r.Path[:], path)
	return r
}

// An exact-path open rule (#142) compiles to an exact-map entry only, above
// every prefix of its path; a generic exact deny also blocks mutations of
// that path, and nothing below it.
func TestExactPathOpenRule(t *testing.T) {
	rules := []OpenPolicyRule{
		openDirectoryRuleForPath(PolicyAllow, OpOpen, "/etc/"),
		exactRule(PolicyDeny, OpOpen, "/etc/shadow"),
	}
	if err := validateOpenPolicyRules(rules); err != nil {
		t.Fatal(err)
	}
	sortOpenRulesByPrecedence(rules)
	index := compileOpenIndex(rules)
	for path, want := range map[string]uint32{
		"/etc/shadow":   PolicyDeny,
		"/etc/shadow2":  PolicyAllow,
		"/etc/shadow/x": PolicyAllow,
		"/etc/passwd":   PolicyAllow,
	} {
		if got := indexedOpenDecision(index, rootPathPolicy(rules), path, OpOpenRW); got != want {
			t.Errorf("%s: %d, want %d", path, got, want)
		}
	}
	mut := compileMutationIndex(rules)
	if len(mut.denies) != 0 || len(mut.selfDenies) != 1 {
		t.Fatalf("mutation index: denies %v self %v", mut.denies, mut.selfDenies)
	}
	if rootPathPolicy([]OpenPolicyRule{exactRule(PolicyAllow, OpOpen, "/")}) {
		t.Fatal("an exact allow on / covers only the root directory, not the default")
	}
}

// An exact exec rule is its path plus a terminating NUL: the matcher
// compares it against the NUL-terminated resolved path.
func TestExactPathExecRule(t *testing.T) {
	exact := execRuleForTest(PolicyDeny, "/usr/bin/nmap\x00")
	l := &ExecLsm{}
	if err := l.LoadPolicies([]ExecPolicyRule{execRuleForTest(PolicyAllow, "/usr/bin/"), exact}); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]int32{"/usr/bin/nmap": PolicyDeny, "/usr/bin/nmap2": PolicyAllow, "/usr/bin/ls": PolicyAllow} {
		if got := execDecision(l.policyRules, l.defaultPolicyResult, path, nil); got != want {
			t.Errorf("%s: %d, want %d", path, got, want)
		}
	}
	if err := validateExecPolicyRules([]ExecPolicyRule{execRuleForTest(PolicyDeny, "/a\x00b")}); err == nil {
		t.Fatal("a NUL may only end an exec rule path")
	}
}
