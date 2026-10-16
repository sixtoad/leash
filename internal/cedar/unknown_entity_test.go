package cedar

import (
	"errors"
	"strings"
	"testing"
)

// An unknown entity type or action used to compile to nothing — a typo'd
// forbid was silently dropped (issue #162). It must now be a compile error.
func TestCompileStringRejectsUnknownEntity(t *testing.T) {
	cases := []struct {
		name, cedar, want string
	}{
		{"resource type", `permit (principal, action == Action::"FileOpen", resource in Bogus::"/");`, `Resource type "Bogus"`},
		{"forbid on unknown type", "permit (principal, action == Action::\"FileOpen\", resource in Dir::\"/\");\nforbid (principal, action == Action::\"FileOpen\", resource in Dirr::\"/etc/\");", `Resource type "Dirr"`},
		{"action", `permit (principal, action == Action::"FileOpne", resource in Dir::"/");`, `Action "FileOpne"`},
	}
	for _, tc := range cases {
		_, err := CompileString("p.cedar", tc.cedar)
		var detail *ErrorDetail
		if !errors.As(err, &detail) {
			t.Fatalf("%s: want an *ErrorDetail, got %v", tc.name, err)
		}
		if detail.Code != "CEDAR_UNKNOWN_ENTITY" || !strings.Contains(detail.Message, tc.want) {
			t.Fatalf("%s: detail = %+v", tc.name, detail)
		}
		if detail.Line <= 0 || detail.Snippet == "" {
			t.Fatalf("%s: the offending line should be located: %+v", tc.name, detail)
		}
		if out := FormatForCLI(detail); !strings.Contains(out, tc.want) || !strings.Contains(out, "p.cedar:") {
			t.Fatalf("%s: CLI rendering lost the reason:\n%s", tc.name, out)
		}
	}
	for _, ok := range []string{
		`permit (principal, action == Action::"FileOpen", resource in Dir::"/");`,
		`permit (principal, action == Action::"NetworkConnect", resource == Host::"example.com");`,
		`forbid (principal, action == Action::"McpCall", resource) when { resource in [ MCP::Server::"mcp.example.com" ] };`,
	} {
		if _, err := CompileString("ok.cedar", ok); err != nil {
			t.Fatalf("supported policy rejected: %q: %v", ok, err)
		}
	}
}

// The unknown-entity check uses the engine's type knowledge (#150/#152), so
// strict policies using the engine's newer types and plugin (authz) actions
// must still compile.
func TestCompileStringAcceptsEngineTypesAndPluginActions(t *testing.T) {
	for _, ok := range []string{
		// FilePrefix (engine-only resource type), strict semantics.
		"@leash_semantics(\"cedar\")\npermit (principal, action == Action::\"ProcessExec\", resource in FilePrefix::\"/usr/bin/\");",
		"@leash_semantics(\"cedar\")\npermit (principal, action == Action::\"FileOpenReadOnly\", resource in FilePrefix::\"/etc/\");\nforbid (principal, action == Action::\"FileOpenReadOnly\", resource) when { resource in FilePrefix::\"/etc/shadow\" };",
		// Authz plugin action with plugin-defined principal and resource types.
		"@leash_semantics(\"cedar\")\npermit (principal == Plugin::\"secretbroker\", action == Secret::Action::\"Read\", resource == Secret::Item::\"gemini\");",
		"@leash_semantics(\"cedar\")\npermit (principal, action == Action::\"FileOpenReadOnly\", resource in Dir::\"/\");\npermit (principal == Plugin::\"dns\", action in [Net::Action::\"Resolve\"], resource in Net::DnsZone::\"example.com\");",
		// MCP built-in types.
		"@leash_semantics(\"cedar\")\nforbid (principal, action == Action::\"McpCall\", resource == MCP::Tool::\"rm\");",
	} {
		if _, err := CompileString("ok.cedar", ok); err != nil {
			t.Fatalf("valid policy rejected:\n%s\n%v", ok, err)
		}
	}

	// Still rejected in strict mode: an unknown type on a built-in action,
	// including one hiding in a condition, and an unknown built-in action. The
	// kernel compiler or this check may be the one that refuses; either way the
	// error names the offending token.
	for _, bad := range []struct{ cedar, want string }{
		{"@leash_semantics(\"cedar\")\nforbid (principal, action == Action::\"FileOpenReadOnly\", resource in FilePrefx::\"/etc/\");", "FilePrefx"},
		{"@leash_semantics(\"cedar\")\npermit (principal, action == Action::\"FileOpenReadOnly\", resource in Dir::\"/\");\nforbid (principal, action == Action::\"FileOpenReadOnly\", resource) when { resource in [Dir::\"/tmp/\", Fiel::\"/etc/passwd\"] };", "Fiel"},
		{"@leash_semantics(\"cedar\")\npermit (principal, action == Action::\"ProcesExec\", resource in FilePrefix::\"/bin/\");", "ProcesExec"},
	} {
		_, err := CompileString("bad.cedar", bad.cedar)
		var detail *ErrorDetail
		if !errors.As(err, &detail) || !strings.Contains(detail.Message, bad.want) {
			t.Fatalf("want a compile error naming %s for:\n%s\ngot %v", bad.want, bad.cedar, err)
		}
	}
}

// The engine-aware check itself, independent of what the kernel compiler
// happens to catch first: valid engine types and plugin actions pass, unknown
// built-in types and actions are reported with a location.
func TestUnknownEntityErrorUsesEngineTypes(t *testing.T) {
	for _, ok := range []string{
		`permit (principal, action == Action::"ProcessExec", resource in FilePrefix::"/usr/bin/");`,
		`forbid (principal, action == Action::"McpCall", resource) when { resource in [MCP::Server::"s", MCP::Tool::"t"] };`,
		`permit (principal == Plugin::"secretbroker", action == Secret::Action::"Read", resource == Secret::Item::"gemini");`,
		`permit (principal, action in [Net::Action::"Resolve"], resource is Net::DnsZone);`,
	} {
		if d := unknownEntityError("ok.cedar", ok, nil); d != nil {
			t.Fatalf("valid policy flagged: %s\n%+v", ok, d)
		}
	}
	for _, bad := range []struct{ cedar, want string }{
		{"permit (principal, action == Action::\"FileOpen\", resource in Dir::\"/\");\nforbid (principal, action == Action::\"FileOpen\", resource) when { resource in [Dir::\"/tmp/\", Fiel::\"/x\"] };", `Resource type "Fiel"`},
		{`forbid (principal, action == Action::"ProcesExec", resource is FilePrefix);`, `Action "ProcesExec"`},
		{`forbid (principal, action == Action::"FileOpen", resource is Directory);`, `Resource type "Directory"`},
	} {
		d := unknownEntityError("bad.cedar", bad.cedar, nil)
		if d == nil || d.Code != "CEDAR_UNKNOWN_ENTITY" || !strings.Contains(d.Message, bad.want) {
			t.Fatalf("want %s for %s, got %+v", bad.want, bad.cedar, d)
		}
		if d.Line <= 0 || d.Snippet == "" {
			t.Fatalf("offending line not located: %+v", d)
		}
	}
}

// Without a snippet the message must still be printed (previously only the
// location and a generic hint were).
func TestFormatForCLIIncludesMessageWithoutSnippet(t *testing.T) {
	out := FormatForCLI(&ErrorDetail{File: "/p.cedar", Message: "not enforceable by the kernel: X", Suggestion: "hint text"})
	for _, want := range []string{"/p.cedar:1:1", "message: not enforceable by the kernel: X", "hint: hint text"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}
