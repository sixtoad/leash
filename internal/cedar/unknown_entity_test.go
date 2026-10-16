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
