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
	legacy, err := CompileString("leash.cedar", `@leash_semantics("legacy")
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

	// Strict Cedar is the default: an unmarked file is read like the
	// explicitly marked one.
	unmarked, err := CompileString("leash.cedar", `
forbid (principal, action in Action::"FileOpen", resource in Dir::"/a/");
permit (principal, action in Action::"FileOpen", resource in Dir::"/a/b/");`)
	if err != nil {
		t.Fatal(err)
	}
	if unmarked.Semantics != transpiler.SemanticsCedar || unmarked.Rewrite != nil {
		t.Fatal("an unmarked file is strict and must not be rewritten")
	}
	if unmarked.Engine.DecideOpen("/a/b/x", engine.ActionFileOpenReadOnly).Allow || unmarked.Engine.DecideMCP("s", "t").Allow {
		t.Fatal("unmarked: forbid overrides permit, MCP default deny")
	}
}

// A legacy-only construct in an unmarked file fails the load, and the error
// points at the two ways out: migrate, or mark the file legacy.
func TestCompileStringHintsMigrateForUnmarkedLegacyFile(t *testing.T) {
	_, err := CompileString("leash.cedar", `permit (principal, action == Action::"FileOpen", resource in Dir::"/a/");`)
	var detail *ErrorDetail
	if !errors.As(err, &detail) {
		t.Fatalf("want an ErrorDetail, got %v", err)
	}
	if !strings.Contains(detail.Suggestion, "leash policy migrate") || !strings.Contains(detail.Suggestion, `@leash_semantics("legacy")`) {
		t.Fatalf("suggestion %q", detail.Suggestion)
	}
	if _, err := CompileString("leash.cedar", `@leash_semantics("legacy")
permit (principal, action == Action::"FileOpen", resource in Dir::"/a/");`); err != nil {
		t.Fatalf("marked legacy: %v", err)
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

// #164: a permit whose condition no adapter can enforce fails the load with
// the policy, its line and the reason, in legacy and strict files.
func TestCompileStringRejectsUnenforceablePermits(t *testing.T) {
	for _, tc := range []struct {
		name, text, want string
		line             int
	}{
		{"legacy", `@leash_semantics("legacy")
permit (principal, action == Action::"FileOpen", resource in Dir::"/a/");

@id("tty-only")
permit (principal, action == Action::"ProcessExec", resource in Dir::"/usr/bin/") when { context.tty == true };`, "tty-only", 4},
		{"legacy-principal", `@leash_semantics("legacy") permit (principal == User::"alice", action == Action::"NetworkConnect", resource == Host::"api.example.com");`, "policy0", 1},
		{"strict-mcp", `@leash_semantics("cedar")
permit (principal, action == Action::"McpCall", resource in MCP::Server::"s");
@leash_semantics("cedar")
permit (principal, action == Action::"McpCall", resource) when { context.args == "x" };`, "policy1", 3},
	} {
		_, err := CompileString("leash.cedar", tc.text)
		var detail *ErrorDetail
		if !errors.As(err, &detail) {
			t.Fatalf("%s: want an ErrorDetail, got %v", tc.name, err)
		}
		if detail.Code != "CEDAR_UNENFORCEABLE_CONDITION" || detail.Line != tc.line || detail.Policy != tc.want || detail.File != "leash.cedar" {
			t.Errorf("%s: code %s line %d policy %q file %q: %s", tc.name, detail.Code, detail.Line, detail.Policy, detail.File, detail.Message)
		}
		if !strings.Contains(detail.Message, "cannot be enforced as written") {
			t.Errorf("%s: message %q", tc.name, detail.Message)
		}
	}
}

// A forbid enforced without its condition is stricter and still loads.
func TestCompileStringKeepsForbidWithDroppedCondition(t *testing.T) {
	comp, err := CompileString("leash.cedar", `@leash_semantics("legacy")
permit (principal, action == Action::"ProcessExec", resource in Dir::"/");
forbid (principal, action == Action::"ProcessExec", resource in Dir::"/opt/") when { context.tty == true };`)
	if err != nil {
		t.Fatal(err)
	}
	if comp.Engine.DecideExec("/opt/x").Allow || !comp.Engine.DecideExec("/bin/x").Allow {
		t.Fatal("the forbid applies unconditionally")
	}
	if !strings.Contains(strings.Join(comp.Rewrite.Summary(), "\n"), "(stricter)") {
		t.Fatalf("the rewrite report must say the forbid got stricter: %v", comp.Rewrite.Summary())
	}
}
