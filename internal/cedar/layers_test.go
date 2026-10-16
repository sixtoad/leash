package cedar

import (
	"errors"
	"strings"
	"testing"

	"github.com/strongdm/leash/internal/engine"
	"github.com/strongdm/leash/internal/lsm"
	"github.com/strongdm/leash/internal/transpiler"
)

func TestCompileStringReadsSemantics(t *testing.T) {
	legacy, err := CompileString("leash.cedar", `
forbid (principal, action == Action::"FileOpen", resource) when { resource in [Dir::"/a/"] };
permit (principal, action == Action::"FileOpen", resource) when { resource in [Dir::"/a/b/"] };`)
	if err != nil {
		t.Fatal(err)
	}
	if legacy.Semantics != transpiler.SemanticsLegacy || legacy.Rewrite == nil || len(legacy.Rewrite.Exceptions) != 1 {
		t.Fatalf("legacy: %+v", legacy.Rewrite)
	}
	if !legacy.Engine.DecideOpen("/a/b/x", engine.ActionFileOpenReadOnly).Allow || !legacy.Engine.DecideMCP("s", "t").Allow {
		t.Fatal("legacy decisions")
	}
	if legacy.Policies.Source == nil || legacy.Policies.Source.Name != "leash.cedar" {
		t.Fatal("the kernel tables must carry their source")
	}

	strict, err := CompileString("leash.cedar", `@leash_semantics("cedar")
forbid (principal, action in Action::"FileOpen", resource in Dir::"/a/");
permit (principal, action in Action::"FileOpen", resource in Dir::"/a/b/");`)
	if err != nil {
		t.Fatal(err)
	}
	if strict.Semantics != transpiler.SemanticsCedar || strict.Rewrite != nil {
		t.Fatal("strict file must not be rewritten")
	}
	if strict.Engine.DecideOpen("/a/b/x", engine.ActionFileOpenReadOnly).Allow || strict.Engine.DecideMCP("s", "t").Allow {
		t.Fatal("strict: forbid overrides permit, MCP default deny")
	}
}

func TestCompileStringReportsKernelRejectionWithPosition(t *testing.T) {
	_, err := CompileString("leash.cedar", `@leash_semantics("cedar")
permit (principal, action in Action::"FileOpen", resource in Dir::"/a/");

permit (principal, action == Action::"ProcessExec", resource) when { context.tty == true };`)
	var detail *ErrorDetail
	if !errors.As(err, &detail) {
		t.Fatalf("want an ErrorDetail, got %v", err)
	}
	if detail.Line != 4 || !strings.Contains(detail.Message, "context") {
		t.Fatalf("detail: line %d message %q", detail.Line, detail.Message)
	}
}

func sourceOf(name, text string) *lsm.PolicySource { return &lsm.PolicySource{Name: name, Text: text} }

func TestCompileLayersPrefixesPolicyIDs(t *testing.T) {
	comp, err := CompileLayers([]Layer{
		{Source: sourceOf("a.cedar", `@leash_semantics("cedar") permit (principal == Plugin::"p", action == Secret::Action::"Read", resource);`)},
		{Source: sourceOf("b.cedar", `@leash_semantics("cedar") forbid (principal, action == Secret::Action::"Read", resource == Secret::Item::"x");`)},
	})
	if err != nil {
		t.Fatal(err)
	}
	d := comp.Engine.Decide(engine.Request{Principal: engine.EntityUID{Type: "Plugin", ID: "p"}, Action: engine.EntityUID{Type: "Secret::Action", ID: "Read"}, Resource: engine.EntityUID{Type: "Secret::Item", ID: "x"}})
	if d.Allow || len(d.PolicyIDs) != 1 || d.PolicyIDs[0] != "b.cedar/policy0" {
		t.Fatalf("decision %+v", d)
	}
}
