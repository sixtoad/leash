package leashd

import (
	"strings"
	"testing"

	"github.com/strongdm/leash/internal/policy"
)

func TestRenderPolicyLinesHumanization(t *testing.T) {
	custom := `permit (principal, action == Action::"FileOpenReadOnly", resource == File::"/etc/inputrc");`
	cedar := strings.TrimSpace(custom) + "\n\n" + strings.TrimSpace(policy.DefaultCedar()) + "\n"

	lines, err := renderPolicyLines(cedar)
	if err != nil {
		t.Fatalf("renderPolicyLines failed: %v", err)
	}
	if len(lines) != 6 {
		t.Fatalf("expected 6 lines, got %d", len(lines))
	}

	expected := []string{
		"Allow read files /etc/inputrc",
		"Allow read files, write files directory /",
		"Allow run processes directory /",
		"Allow network connect any resource",
		"Allow read files, write files any resource",
		"Allow call MCP tool any resource",
	}

	for i, line := range lines {
		if line.Sequence != i {
			t.Errorf("sequence mismatch at %d: got %d", i, line.Sequence)
		}
		if line.Effect != "permit" {
			t.Errorf("effect mismatch at %d: got %s", i, line.Effect)
		}
		if line.Humanized != expected[i] {
			t.Errorf("humanized mismatch at %d: got %q want %q", i, line.Humanized, expected[i])
		}
	}
}

// Strict Cedar (the default) writes a single entity without brackets and an
// exception as `unless`; the humanized line must show both.
func TestRenderPolicyLinesStrictConditions(t *testing.T) {
	lines, err := renderPolicyLines(`forbid (principal, action in Action::"FileOpen", resource) when { resource in Dir::"/a/" } unless { resource in [Dir::"/a/b/"] };` + "\n")
	if err != nil || len(lines) != 1 {
		t.Fatalf("%v %v", lines, err)
	}
	if got := lines[0].Humanized; !strings.Contains(got, "/a/") || !strings.Contains(got, "except") || !strings.Contains(got, "/a/b/") {
		t.Fatalf("humanized %q", got)
	}
}

func TestRenderPolicyLinesStripsEscapedQuotes(t *testing.T) {
	cedar := `forbid (
        principal == User::"alice",
        action == Action::"McpCall",
        resource == MCP::Server::"mcp.context7.com"
    );`

	lines, err := renderPolicyLines(strings.TrimSpace(cedar) + "\n")
	if err != nil {
		t.Fatalf("renderPolicyLines failed: %v", err)
	}
	if len(lines) == 0 {
		t.Fatal("expected at least one policy line")
	}

	found := false
	for _, line := range lines {
		if !strings.Contains(line.Humanized, "mcp.context7.com") {
			continue
		}
		found = true
		if strings.Contains(line.Humanized, `\"`) {
			t.Fatalf("expected humanized line without escaped quotes, got %q", line.Humanized)
		}
	}
	if !found {
		t.Fatalf("expected to find MCP server entry in humanized output: %+v", lines)
	}
}

func TestRenderPolicyLinesDedupesDuplicateStatements(t *testing.T) {
	stmt := `forbid (principal, action == Action::"FileOpenReadOnly", resource == File::"/tmp/foo");`
	cedar := strings.Join([]string{strings.TrimSpace(stmt), strings.TrimSpace(stmt)}, "\n")

	lines, err := renderPolicyLines(cedar)
	if err != nil {
		t.Fatalf("renderPolicyLines failed: %v", err)
	}
	if len(lines) != 1 {
		t.Fatalf("expected 1 unique line, got %d", len(lines))
	}
	if lines[0].Sequence != 0 {
		t.Fatalf("expected sequence 0, got %d", lines[0].Sequence)
	}
	if got := strings.TrimSpace(lines[0].Cedar); got != strings.TrimSpace(stmt) {
		t.Fatalf("unexpected cedar payload: got %q", got)
	}
}
