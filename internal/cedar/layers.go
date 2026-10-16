package cedar

import (
	"fmt"

	cedarlib "github.com/cedar-policy/cedar-go"

	"github.com/strongdm/leash/internal/engine"
	"github.com/strongdm/leash/internal/lsm"
	"github.com/strongdm/leash/internal/proxy"
	"github.com/strongdm/leash/internal/transpiler"
)

// PolicyKind classifies a PolicyError.
type PolicyKind string

const (
	// PolicyInvalid: the policy parses but is not a valid Leash policy (an
	// invalid action scope or annotation, mixed namespaces).
	PolicyInvalid PolicyKind = "invalid_policy"
	// PolicyNotEnforceable: a policy the kernel cannot enforce exactly.
	PolicyNotEnforceable PolicyKind = "not_enforceable"
)

// PolicyError is a policy that parses but does not compile. Its message
// names the policy and its position ("policy <id> at <file>:<line>:<col>").
type PolicyError struct {
	Kind PolicyKind
	Err  error
}

func (e *PolicyError) Error() string { return e.Err.Error() }
func (e *PolicyError) Unwrap() error { return e.Err }

// Layer is one policy layer for CompileLayers: Cedar source text, or rules
// built in code (Source nil), which are legacy IR by definition.
type Layer struct {
	Source *lsm.PolicySource
	IR     *lsm.PolicySet
	HTTP   []proxy.HeaderRewriteRule
}

// LayerOf returns the layer a compiled PolicySet came from: its Cedar source
// when it has one, otherwise its rules as an IR layer.
func LayerOf(ps *lsm.PolicySet, http []proxy.HeaderRewriteRule) Layer {
	if ps != nil && ps.Source != nil {
		return Layer{Source: ps.Source}
	}
	return Layer{IR: ps, HTTP: http}
}

// CompileLayers merges policy layers, in order, into one enforceable
// policy (#142). Legacy layers (files without @leash_semantics("cedar"), and
// IR layers) are rewritten to strict Cedar together, because legacy
// most-specific-wins crosses layers; strict layers are added as written.
// One engine is built and one set of kernel tables compiled from the merged
// strict set. Any failure fails the whole merge.
func CompileLayers(layers []Layer) (*Compilation, error) {
	tr := transpiler.NewCedarToLeashTranspiler()
	var legacy []transpiler.LegacyLayer
	type strictLayer struct {
		name string
		text string
		ps   *cedarlib.PolicySet
	}
	var strict []strictLayer
	http := []proxy.HeaderRewriteRule{}
	for _, l := range layers {
		switch {
		case l.Source != nil:
			parsed, err := transpiler.NewCedarParser().ParseFromNamedString(l.Source.Name, l.Source.Text)
			if err != nil {
				return nil, err
			}
			sem, err := transpiler.DetectSemantics(parsed.NativePolicySet)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", l.Source.Name, err)
			}
			http = append(http, tr.HTTPRewrites(parsed)...)
			if sem == transpiler.SemanticsCedar {
				strict = append(strict, strictLayer{name: l.Source.Name, text: l.Source.Text, ps: parsed.NativePolicySet})
			} else {
				legacy = append(legacy, transpiler.LegacyLayer{Name: l.Source.Name, Policies: parsed})
			}
		case l.IR != nil:
			legacy = append(legacy, transpiler.LegacyLayer{Name: "rules", IR: l.IR})
			http = append(http, l.HTTP...)
		default:
			http = append(http, l.HTTP...)
		}
	}

	comp := &Compilation{Semantics: transpiler.SemanticsCedar, HTTPRules: http}
	merged := cedarlib.NewPolicySet()
	prefix := len(legacy)+len(strict) > 1
	add := func(layer string, ps *cedarlib.PolicySet) {
		for id, p := range ps.All() {
			if prefix {
				id = cedarlib.PolicyID(layer + "/" + string(id))
			}
			merged.Add(id, p)
		}
	}
	if len(legacy) > 0 {
		rw, err := transpiler.RewriteLegacy(transpiler.RewriteOptions{Provenance: true, Name: "legacy-rewrite.cedar", OmitGlobalDefaults: len(strict) > 0}, legacy...)
		if err != nil {
			return nil, &PolicyError{Kind: PolicyInvalid, Err: err}
		}
		comp.Semantics = transpiler.SemanticsLegacy
		comp.Rewrite = &rw.Report
		comp.StrictText = rw.Text
		add("legacy", rw.Policies)
	}
	for _, s := range strict {
		if comp.StrictText != "" {
			comp.StrictText += "\n"
		}
		comp.StrictText += s.text
		add(s.name, s.ps)
	}

	eng, err := engine.New(merged)
	if err != nil {
		return nil, &PolicyError{Kind: PolicyInvalid, Err: err}
	}
	ir, warnings, err := transpiler.CompileKernelReport(merged, eng)
	if err != nil {
		return nil, &PolicyError{Kind: PolicyNotEnforceable, Err: err}
	}
	comp.Warnings = warnings
	comp.Strict = merged
	comp.Engine = eng
	comp.Policies = ir
	return comp, nil
}
