package transpiler

import (
	"fmt"

	cedarlib "github.com/cedar-policy/cedar-go"

	"github.com/strongdm/leash/internal/engine"
)

// Semantics is how a policy file is read (#142).
type Semantics int

const (
	// SemanticsLegacy is Leash's historical reading: file and exec rules are
	// most-specific-wins, MCP is default-allow, Host::"*" is the connect
	// default, principals and most conditions are ignored. A legacy file is
	// rewritten to strict Cedar at load (RewriteLegacy).
	SemanticsLegacy Semantics = iota
	// SemanticsCedar is plain Cedar: forbid overrides permit, default deny,
	// over Leash's entity hierarchy (see package engine).
	SemanticsCedar
)

func (s Semantics) String() string {
	if s == SemanticsCedar {
		return "cedar"
	}
	return "legacy"
}

// AnnotationSemantics marks a policy file's semantics:
//
//	@leash_semantics("cedar")
//	permit (...);
//
// An annotation, not a comment, because it is part of the policy: cedar-go
// keeps it in the AST and in MarshalCedar, so it survives every path that
// parses and re-emits policies (the policy API, the Control UI, runtime
// layers). A comment is dropped by the parser.
//
// A file is strict when any of its policies carries @leash_semantics("cedar");
// `leash policy migrate` marks every policy, so deleting or reordering
// policies cannot silently turn a file back to legacy. "legacy" is accepted
// as an explicit value; mixing the two values in one file is an error.
const AnnotationSemantics = "leash_semantics"

// annotationRewrite marks a policy the legacy rewrite synthesized (e.g. the
// MCP default allow); annotationSource records the legacy policy a
// rewritten policy came from ("<file>:<line>").
const (
	annotationRewrite = "leash_rewrite"
	annotationSource  = engine.AnnotationSource
)

// DetectSemantics reads the @leash_semantics marker of a parsed file.
func DetectSemantics(ps *cedarlib.PolicySet) (Semantics, error) {
	if ps == nil {
		return SemanticsLegacy, nil
	}
	seen := map[string]bool{}
	for _, p := range ps.All() {
		v, ok := p.Annotations()[AnnotationSemantics]
		if !ok {
			continue
		}
		switch string(v) {
		case "cedar", "legacy":
			seen[string(v)] = true
		default:
			return SemanticsLegacy, fmt.Errorf("@%s(%q): want \"cedar\" or \"legacy\"", AnnotationSemantics, string(v))
		}
	}
	if seen["cedar"] && seen["legacy"] {
		return SemanticsLegacy, fmt.Errorf("policies disagree on @%s: use one value per file", AnnotationSemantics)
	}
	if seen["cedar"] {
		return SemanticsCedar, nil
	}
	return SemanticsLegacy, nil
}
