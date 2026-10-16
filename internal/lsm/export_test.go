package lsm

import "sort"

// OpenDecisionForTest runs rules through the same pipeline LoadPolicies uses
// (conversion, longest-first stable sort, root default, full-byte index
// compilation) and evaluates path/operation with the userspace model of
// check_open_indexed_policy. It lets external tests (package lsm_test) check
// front-end output (Cedar, line format) against enforcement semantics without
// a kernel.
func OpenDecisionForTest(rules []PolicyRule, path string, operation uint32) uint32 {
	converted := ConvertToFileOpenRules(rules)
	sort.SliceStable(converted, func(i, j int) bool { return converted[i].PathLen > converted[j].PathLen })
	return indexedOpenDecision(compileOpenIndex(converted), rootPathPolicy(converted), path, operation)
}

// ValidateOpenRulesForTest exposes the kernel-load validation for external tests.
func ValidateOpenRulesForTest(rules []PolicyRule) error {
	return validateOpenPolicyRules(ConvertToFileOpenRules(rules))
}
