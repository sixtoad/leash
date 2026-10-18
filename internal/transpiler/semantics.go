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
	// default, principals and most conditions are ignored. Only a file marked
	// @leash_semantics("legacy") is read this way; it is rewritten to strict
	// Cedar at load (RewriteLegacy).
	SemanticsLegacy Semantics = iota
	// SemanticsCedar is plain Cedar: forbid overrides permit, default deny,
	// over Leash's entity hierarchy (see package engine). The default.
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
//	@leash_semantics("legacy")
//	permit (...);
//
// Strict Cedar is the default: a file without the marker is plain Cedar.
// The legacy dialect is an explicit opt-in, @leash_semantics("legacy");
// @leash_semantics("cedar") is accepted as an explicit strict marker.
//
// An annotation, not a comment, because it is part of the policy: cedar-go
// keeps it in the AST and in MarshalCedar, so it survives every path that
// parses and re-emits policies (the policy API, the Control UI, runtime
// layers). A comment is dropped by the parser.
//
// A file is legacy when any of its policies carries
// @leash_semantics("legacy"), so a policy added to a legacy file (the policy
// API prepends it to the layer's text) is read as legacy too. Mixing the two
// values in one file is an error.
const AnnotationSemantics = "leash_semantics"

// The @leash_semantics values. MarkerNone is a file without the marker.
const (
	MarkerNone   = ""
	MarkerCedar  = "cedar"
	MarkerLegacy = "legacy"
)

// annotationRewrite marks a policy the legacy rewrite synthesized (e.g. the
// MCP default allow); annotationSource records the legacy policy a
// rewritten policy came from ("<file>:<line>").
const (
	annotationRewrite = "leash_rewrite"
	annotationSource  = engine.AnnotationSource
)

// SemanticsMarker returns the @leash_semantics value a parsed file carries:
// MarkerNone, MarkerCedar or MarkerLegacy. An unknown value, or both values
// in one file, is an error.
func SemanticsMarker(ps *cedarlib.PolicySet) (string, error) {
	if ps == nil {
		return MarkerNone, nil
	}
	seen := map[string]bool{}
	for _, p := range ps.All() {
		v, ok := p.Annotations()[AnnotationSemantics]
		if !ok {
			continue
		}
		switch string(v) {
		case MarkerCedar, MarkerLegacy:
			seen[string(v)] = true
		default:
			return MarkerNone, fmt.Errorf("@%s(%q): want \"cedar\" or \"legacy\"", AnnotationSemantics, string(v))
		}
	}
	switch {
	case seen[MarkerCedar] && seen[MarkerLegacy]:
		return MarkerNone, fmt.Errorf("policies disagree on @%s: use one value per file", AnnotationSemantics)
	case seen[MarkerLegacy]:
		return MarkerLegacy, nil
	case seen[MarkerCedar]:
		return MarkerCedar, nil
	}
	return MarkerNone, nil
}

// DetectSemantics reads how a parsed file is to be read: legacy only when it
// is marked @leash_semantics("legacy"), strict Cedar otherwise.
func DetectSemantics(ps *cedarlib.PolicySet) (Semantics, error) {
	m, err := SemanticsMarker(ps)
	if err != nil {
		return SemanticsCedar, err
	}
	if m == MarkerLegacy {
		return SemanticsLegacy, nil
	}
	return SemanticsCedar, nil
}
