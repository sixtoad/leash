package lsm

import "testing"

// mutationDecision models check_mutation_policy over a compiled mutation
// index: each trie yields its longest matching prefix, whose value is its
// specificity; an exact deny denies; otherwise the allow wins only when it is
// strictly more specific than the deny (none counts as 0).
func mutationDecision(idx compiledMutationIndex, path string) bool {
	longest := func(keys map[mutationPrefixRuleKey]uint8) (uint8, bool) {
		bestLen, val, found := -1, uint8(0), false
		for key, v := range keys {
			n := int(key.PrefixLen-mutationIndexDomainBits) / 8
			if n <= len(path) && path[:n] == string(key.Path[:n]) && n > bestLen {
				bestLen, val, found = n, v, true
			}
		}
		return val, found
	}
	self := mutationExactRuleKey{PathLen: uint32(len(path))}
	copy(self.Path[:], path)
	if idx.selfDenies[self] != 0 {
		return false
	}
	deny, _ := longest(idx.denies)
	allow, ok := longest(idx.allows)
	return ok && allow > deny
}

// The mutation table compiled from Cedar is longest-prefix: a permit nested
// in a forbid nested in a permit allows mutations; a table derived from open
// rules (specificity 1 everywhere) keeps any deny above any allow.
func TestMutationTableIsLongestPrefix(t *testing.T) {
	mut := func(action uint32, path string) OpenPolicyRule {
		r := OpenPolicyRule{Action: action, Operation: OpMutation, PathLen: uint32(len(path))}
		copy(r.Path[:], path)
		return r
	}
	idx := compileMutationIndex([]OpenPolicyRule{mut(PolicyAllow, "/"), mut(PolicyDeny, "/srv/"), mut(PolicyAllow, "/srv/ok/")})
	for path, want := range map[string]bool{"/x": true, "/srv/x": false, "/srv/ok/x": true, "/srv/okx": false} {
		if got := mutationDecision(idx, path); got != want {
			t.Errorf("compiled %s: %v, want %v", path, got, want)
		}
	}
	legacy := compileMutationIndex([]OpenPolicyRule{
		openDirectoryRuleForPath(PolicyAllow, OpOpenRW, "/"),
		openDirectoryRuleForPath(PolicyDeny, OpOpen, "/srv/"),
		openDirectoryRuleForPath(PolicyAllow, OpOpenRW, "/srv/ok/"),
	})
	if mutationDecision(legacy, "/srv/ok/x") || !mutationDecision(legacy, "/x") {
		t.Error("a derived table keeps deny-first")
	}
}

// Compiled mutation rules are the whole mutation table: the open rules are
// not consulted when one is present (#142).
func TestCompiledMutationRulesAreTheWholeTable(t *testing.T) {
	mut := func(action uint32, kind uint32, path string) OpenPolicyRule {
		r := OpenPolicyRule{Action: action, Operation: OpMutation, PathLen: uint32(len(path)), IsDirectory: kind}
		copy(r.Path[:], path)
		return r
	}
	rules := []OpenPolicyRule{
		openDirectoryRuleForPath(PolicyAllow, OpOpenRW, "/ignored/"),
		mut(PolicyAllow, 0, "/"),
		mut(PolicyDeny, 0, "/etc/"),
		mut(PolicyDeny, ExactPath, "/etc"),
	}
	if err := validateOpenPolicyRules(rules); err != nil {
		t.Fatal(err)
	}
	idx := compileMutationIndex(rules)
	if len(idx.allows) != 1 || len(idx.denies) != 1 || len(idx.selfDenies) != 1 {
		t.Fatalf("mutation index: %+v", idx)
	}
	if rootPathPolicy(rules[1:]) {
		t.Fatal("a mutation allow on / must not set the open default")
	}
	if err := validateOpenPolicyRules([]OpenPolicyRule{mut(PolicyAllow, ExactPath, "/x")}); err == nil {
		t.Fatal("the mutation table has no exact allow")
	}
}

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
