package transpiler

import (
	"strings"
	"testing"

	cedarlib "github.com/cedar-policy/cedar-go"

	"github.com/strongdm/leash/internal/engine"
	"github.com/strongdm/leash/internal/lsm"
)

func rewriteText(t *testing.T, text string) *Rewrite {
	t.Helper()
	parsed, err := NewCedarParser().ParseFromNamedString("leash.cedar", text)
	if err != nil {
		t.Fatal(err)
	}
	rw, err := RewriteLegacy(RewriteOptions{Provenance: true}, LegacyLayer{Name: "leash.cedar", Policies: parsed})
	if err != nil {
		t.Fatal(err)
	}
	return rw
}

func TestDetectSemantics(t *testing.T) {
	for text, want := range map[string]Semantics{
		``:                                      SemanticsCedar,
		`permit (principal, action, resource);`: SemanticsCedar,
		`@leash_semantics("cedar") permit (principal, action, resource);`:                                           SemanticsCedar,
		"permit (principal, action, resource);\n@leash_semantics(\"cedar\") forbid (principal, action, resource);":  SemanticsCedar,
		`@leash_semantics("legacy") permit (principal, action, resource);`:                                          SemanticsLegacy,
		"permit (principal, action, resource);\n@leash_semantics(\"legacy\") forbid (principal, action, resource);": SemanticsLegacy,
	} {
		ps, err := cedarlib.NewPolicySetFromBytes("x", []byte(text))
		if err != nil {
			t.Fatal(err)
		}
		got, err := DetectSemantics(ps)
		if err != nil || got != want {
			t.Errorf("%q: got %v, %v; want %v", text, got, err, want)
		}
	}
	for _, text := range []string{
		`@leash_semantics("strict") permit (principal, action, resource);`,
		"@leash_semantics(\"cedar\") permit (principal, action, resource);\n@leash_semantics(\"legacy\") permit (principal, action, resource);",
	} {
		ps, _ := cedarlib.NewPolicySetFromBytes("x", []byte(text))
		if _, err := DetectSemantics(ps); err == nil {
			t.Errorf("%q: want an error", text)
		}
	}
}

// The nesting example of docs/design/AUTHZ-SERVICE.md.
func TestRewriteNestedForbidsGainExceptions(t *testing.T) {
	rw := rewriteText(t, `
forbid (principal, action == Action::"FileOpen", resource) when { resource in [Dir::"/a/"] };
permit (principal, action == Action::"FileOpen", resource) when { resource in [Dir::"/a/b/"] };
forbid (principal, action == Action::"FileOpen", resource) when { resource in [Dir::"/a/b/c/"] };
permit (principal, action == Action::"FileOpen", resource) when { resource in [Dir::"/a/b/c/d/"] };
`)
	if len(rw.Report.Exceptions) != 2 {
		t.Fatalf("exceptions: %v\n%s", rw.Report.Exceptions, rw.Text)
	}
	if got := rw.Report.Exceptions[0]; strings.Join(got.Exceptions, ",") != `Dir::"/a/b/",Dir::"/a/b/c/d/"` {
		t.Errorf("forbid /a/: %v", got)
	}
	if got := rw.Report.Exceptions[1]; strings.Join(got.Exceptions, ",") != `Dir::"/a/b/c/d/"` {
		t.Errorf("forbid /a/b/c/: %v", got)
	}
	e, err := engine.New(rw.Policies)
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]bool{"/a/x": false, "/a/b/x": true, "/a/b/c/x": false, "/a/b/c/d/x": true, "/a/b": true, "/z": false} {
		if got := e.DecideOpen(path, engine.ActionFileOpenReadWrite).Allow; got != want {
			t.Errorf("%s: %v, want %v", path, got, want)
		}
	}
	// Strict is the default: the rewrite carries no @leash_semantics marker.
	if strings.Contains(rw.Text, `@leash_semantics`) || !strings.Contains(rw.Text, `@leash_source("leash.cedar:2")`) {
		t.Errorf("want provenance and no semantics marker:\n%s", rw.Text)
	}
}

func TestRewriteEqualSpecificityForbidWins(t *testing.T) {
	rw := rewriteText(t, `
permit (principal, action == Action::"FileOpenReadOnly", resource) when { resource in [Dir::"/a/"] };
forbid (principal, action == Action::"FileOpenReadOnly", resource) when { resource in [Dir::"/a/"] };
permit (principal, action == Action::"FileOpenReadWrite", resource) when { resource in [Dir::"/a/b/"] };
`)
	if len(rw.Report.Exceptions) != 0 {
		t.Fatalf("equal specificity or another action must not add an exception: %v", rw.Report.Exceptions)
	}
}

func TestRewriteLegacyDeviations(t *testing.T) {
	rw := rewriteText(t, `
permit (principal, action == Action::"FileOpenReadOnly", resource) when { resource in [Dir::"/"] };
permit (principal == User::"alice", action == Action::"ProcessExec", resource) when { resource in [Dir::"/bin/"] && context.tty == true };
forbid (principal, action == Action::"ProcessExec", resource in File::"/bin/rm") unless { resource in [File::"/bin/rmdir"] };
permit (principal, action == Action::"NetworkConnect", resource == Host::"*");
forbid (principal, action == Action::"McpCall", resource) when { resource in [MCP::Server::"mcp.evil.com"] };
permit (principal, action == Action::"McpCall", resource == MCP::Tool::"search");
permit (principal, action, resource);
`)
	text := rw.Text
	for _, want := range []string{
		`@leash_rewrite("file-open-default-allow")`, // the read-only "/" made every mode default-allow
		`@leash_rewrite("mcp-default-allow")`,
		`when { resource in Host::"mcp.evil.com" }`, // MCP server forbids also forbid the connect
		"permit (\n    principal,\n    action == Action::\"NetworkConnect\",\n    resource\n);",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
	notes := strings.Join(rw.Report.Summary(), "\n")
	for _, want := range []string{"principal constraint ignored", "read as `when`", "MCP was default-allow", "no effect"} {
		if !strings.Contains(notes, want) {
			t.Errorf("missing note %q in:\n%s", want, notes)
		}
	}
	e, err := engine.New(rw.Policies)
	if err != nil {
		t.Fatal(err)
	}
	if !e.DecideOpen("/etc/passwd", engine.ActionFileOpenReadWrite).Allow {
		t.Error("legacy default allow from a read-only \"/\" must carry to writes")
	}
	if e.DecideExec("/bin/rm").Allow || e.DecideExec("/bin/rmdir").Allow {
		t.Error("legacy read `unless { resource in [File::\"/bin/rmdir\"] }` as when (stricter for a forbid): a byte-prefix forbid")
	}
	if !e.DecideMCP("other", "x").Allow || e.DecideMCP("mcp.evil.com", "x").Allow {
		t.Error("MCP default allow with server forbid")
	}
}

func TestRewriteConnectDefaultDenyWins(t *testing.T) {
	rw := rewriteText(t, `
permit (principal, action == Action::"NetworkConnect", resource == Host::"*");
forbid (principal, action == Action::"NetworkConnect", resource == Host::"*");
permit (principal, action == Action::"NetworkConnect", resource == Host::"api.example.com");
`)
	e, err := engine.New(rw.Policies)
	if err != nil {
		t.Fatal(err)
	}
	if e.DecideConnect("other.example.com", "", 443).Allow || !e.DecideConnect("api.example.com", "", 443).Allow {
		t.Fatalf("forbid Host::\"*\" is the default deny:\n%s", rw.Text)
	}
}

func TestRewriteKeepsPluginPolicies(t *testing.T) {
	rw := rewriteText(t, `
@id("grant")
permit (principal == Plugin::"sb", action == Secret::Action::"Read", resource == Secret::Item::"g") when { context.agent == "x" };
`)
	if !strings.Contains(rw.Text, `@id("grant")`) || !strings.Contains(rw.Text, `context.agent == "x"`) {
		t.Fatalf("plugin policy must be kept as written:\n%s", rw.Text)
	}
}

func TestRewriteRejectsMixedNamespaces(t *testing.T) {
	parsed, err := NewCedarParser().ParseFromNamedString("x", `permit (principal, action in [Action::"FileOpen", Secret::Action::"Read"], resource);`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RewriteLegacy(RewriteOptions{}, LegacyLayer{Name: "x", Policies: parsed}); err == nil || !strings.Contains(err.Error(), "mixes") {
		t.Fatalf("got %v", err)
	}
}

func TestRewriteRejectsLineFormatArgRules(t *testing.T) {
	r := lsm.PolicyRule{Action: lsm.PolicyDeny, Operation: lsm.OpExec, PathLen: 9, ArgCount: 1}
	copy(r.Path[:], "/bin/git ")
	copy(r.Args[0][:], "push")
	r.ArgLens[0] = 4
	if _, err := RewriteLegacy(RewriteOptions{}, LegacyLayer{Name: "lines", IR: &lsm.PolicySet{Exec: []lsm.PolicyRule{r}}}); err == nil {
		t.Fatal("an argument deny rule has no Cedar form")
	}
}

func TestMigrateText(t *testing.T) {
	out, report, already, err := MigrateText("leash.cedar", `
forbid (principal, action == Action::"FileOpen", resource) when { resource in [Dir::"/a/"] };
permit (principal, action == Action::"FileOpen", resource) when { resource in [Dir::"/a/b/"] };
`)
	if err != nil || already {
		t.Fatalf("migrate: %v already=%v", err, already)
	}
	if len(report.Exceptions) != 1 || !strings.HasPrefix(out, "// Migrated from legacy") || strings.Contains(out, "@leash_source") {
		t.Fatalf("unexpected output:\n%s", out)
	}
	// The output is strict and migrates to itself.
	if _, _, already, err := MigrateText("leash.cedar", out); err != nil || !already {
		t.Fatalf("migrated file must be strict: %v %v", already, err)
	}
}

// legacyMarker opts a test fixture into the legacy dialect: strict Cedar is
// the default, so a fixture written for legacy semantics must say so.
const legacyMarker = "@leash_semantics(\"legacy\")\n"

func TestMigrateTextInputs(t *testing.T) {
	const legacyText = `forbid (principal, action == Action::"FileOpen", resource) when { resource in [Dir::"/a/"] };
permit (principal, action == Action::"FileOpen", resource) when { resource in [Dir::"/a/b/"] };`
	// Unmarked and legacy-marked input migrate the same way, without marker.
	unmarked, _, _, err := MigrateText("leash.cedar", legacyText)
	if err != nil {
		t.Fatal(err)
	}
	marked, _, _, err := MigrateText("leash.cedar", legacyMarker+legacyText)
	if err != nil {
		t.Fatal(err)
	}
	if unmarked != marked || strings.Contains(marked, "@leash_semantics") {
		t.Fatalf("unmarked:\n%s\nmarked:\n%s", unmarked, marked)
	}
	// An explicit strict file has nothing to migrate.
	if _, _, already, err := MigrateText("leash.cedar", `@leash_semantics("cedar") permit (principal, action, resource);`); err != nil || !already {
		t.Fatalf("explicit strict: %v %v", already, err)
	}
}

func TestLintWarnsWhenAnUnmarkedFileReliesOnLegacy(t *testing.T) {
	codes := func(text string) []string {
		rep, err := LintFromString(text)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, is := range rep.Issues {
			if is.Code == LintLegacySemantics {
				if !strings.Contains(is.Suggestion, "leash policy migrate") {
					t.Errorf("no migrate hint: %+v", is)
				}
				out = append(out, is.Message)
			}
		}
		return out
	}
	for _, text := range []string{
		// File:: as a prefix: legacy covered /bin/rmdir.
		`permit (principal, action == Action::"ProcessExec", resource in File::"/bin/rm");
permit (principal, action == Action::"ProcessExec", resource in File::"/usr/bin/rmdir");`,
		// A longer permit beat a shorter forbid.
		`permit (principal, action in Action::"FileOpen", resource in Dir::"/");
forbid (principal, action in Action::"FileOpen", resource in Dir::"/a/");
permit (principal, action in Action::"FileOpen", resource in Dir::"/a/b/");`,
		// unless read as when.
		`forbid (principal, action == Action::"ProcessExec", resource in Dir::"/bin/") unless { resource in [File::"/bin/ls"] };`,
		// MCP forbids that relied on the MCP default allow.
		`forbid (principal, action == Action::"McpCall", resource) when { resource in [MCP::Server::"evil.example.com"] };`,
	} {
		if got := codes(text); len(got) == 0 {
			t.Errorf("no %s warning for:\n%s", LintLegacySemantics, text)
		}
		// Marked, the file states its dialect: no hint.
		if got := codes(`@leash_semantics("cedar")` + "\n" + text); len(got) != 0 {
			t.Errorf("explicit strict file warned: %v", got)
		}
	}
	// migrate's own output, and strict-only syntax, are strict by intent.
	migrated, _, _, err := MigrateText("leash.cedar", `forbid (principal, action == Action::"FileOpen", resource) when { resource in [Dir::"/a/"] };
permit (principal, action == Action::"FileOpen", resource) when { resource in [Dir::"/a/b/"] };
forbid (principal, action == Action::"McpCall", resource) when { resource in [MCP::Server::"x.example.com"] };`)
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{migrated, `permit (principal, action == Action::"ProcessExec", resource in Dir::"/");
forbid (principal, action == Action::"ProcessExec", resource) when { resource in FilePrefix::"/bin/rm" };`} {
		if got := codes(text); len(got) != 0 {
			t.Errorf("warned on a strict file: %v\n%s", got, text)
		}
	}
	// A plain strict file that decides the same either way.
	if got := codes(`permit (principal, action == Action::"ProcessExec", resource in Dir::"/usr/bin/");`); len(got) != 0 {
		t.Errorf("warned on a file that decides the same: %v", got)
	}
}
