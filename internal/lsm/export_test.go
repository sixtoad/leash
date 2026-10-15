package lsm

import "reflect"

// OpenDecisionForTest runs rules through the same pipeline LoadPolicies uses
// (conversion, precedence sort, root default, full-byte index
// compilation) and evaluates path/operation with the userspace model of
// check_open_indexed_policy. It lets external tests (package lsm_test) check
// front-end output (Cedar, line format) against enforcement semantics without
// a kernel.
func OpenDecisionForTest(rules []PolicyRule, path string, operation uint32) uint32 {
	converted := ConvertToFileOpenRules(rules)
	sortOpenRulesByPrecedence(converted)
	return indexedOpenDecision(compileOpenIndex(converted), rootPathPolicy(converted), path, operation)
}

// SameKernelIndexesForTest reports whether two rule sets compile to identical
// file-open and directory-mutation kernel indexes (including directory-self
// entries and mutation grants), i.e. whether they enforce identically.
func SameKernelIndexesForTest(a, b []PolicyRule) bool {
	compile := func(rules []PolicyRule) (compiledOpenIndex, compiledMutationIndex, bool) {
		converted := ConvertToFileOpenRules(rules)
		sortOpenRulesByPrecedence(converted)
		return compileOpenIndex(converted), compileMutationIndex(converted), rootPathPolicy(converted)
	}
	openA, mutA, rootA := compile(a)
	openB, mutB, rootB := compile(b)
	return rootA == rootB && reflect.DeepEqual(openA, openB) && reflect.DeepEqual(mutA, mutB)
}

// ValidateOpenRulesForTest exposes the kernel-load validation for external tests.
func ValidateOpenRulesForTest(rules []PolicyRule) error {
	return validateOpenPolicyRules(ConvertToFileOpenRules(rules))
}
