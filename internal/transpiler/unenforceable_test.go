package transpiler

import (
	"errors"
	"strings"
	"testing"

	cedarlib "github.com/cedar-policy/cedar-go"

	"github.com/strongdm/leash/internal/engine"
)

// rewriteLegacyErr rewrites a legacy file and returns the rewrite error.
func rewriteLegacyErr(t *testing.T, text string) (*Rewrite, error) {
	t.Helper()
	parsed, err := NewCedarParser().ParseFromNamedString("leash.cedar", text)
	if err != nil {
		t.Fatal(err)
	}
	return RewriteLegacy(RewriteOptions{Provenance: true}, LegacyLayer{Name: "leash.cedar", Policies: parsed})
}

// #164: a legacy permit whose condition or principal constraint legacy
// semantics did not enforce must not load: the rewrite would grant it
// unconditionally. Each case is on line 3, after an unrelated policy.
func TestLegacyRejectsUnenforceablePermits(t *testing.T) {
	for _, tc := range []struct{ policy, want string }{
		{`permit (principal, action == Action::"ProcessExec", resource in Dir::"/a/") when { context.tty == true };`, "the condition `when { context.tty == true }`"},
		{`permit (principal, action == Action::"FileOpen", resource) when { resource in [Dir::"/a/"] } when { context has approved };`, "context has approved"},
		{`permit (principal == User::"alice", action == Action::"ProcessExec", resource in Dir::"/a/");`, "principal constraint"},
		{`permit (principal is User, action == Action::"ProcessExec", resource in Dir::"/a/");`, "principal constraint"},
		{`permit (principal, action == Action::"ProcessExec", resource in Dir::"/a/") when { principal in Group::"admins" };`, `principal in Group::"admins"`},
		{`permit (principal, action == Action::"ProcessExec", resource in Dir::"/a/") when { resource.owner == "me" };`, `resource.owner == "me"`},
		// The legacy parser read any `x in [...]` as resources.
		{`permit (principal, action == Action::"ProcessExec", resource) when { context.path in [Dir::"/a/"] };`, "context.path in"},
		// `unless` was read as `when`: it granted what it excludes.
		{`permit (principal, action == Action::"FileOpen", resource in Dir::"/a/") unless { resource in Dir::"/a/secret/" };`, "read `unless` as `when`"},
		{`permit (principal, action == Action::"NetworkConnect", resource) unless { context.hostname == "evil.com" };`, "read `unless` as `when`"},
		{`permit (principal, action == Action::"NetworkConnect", resource == Host::"a.com") when { context.port == 443 };`, "context.port == 443"},
		{`permit (principal, action == Action::"NetworkConnect", resource) when { context.hostname == context.other };`, "context.hostname == context.other"},
		{`permit (principal, action == Action::"FileOpen", resource is Dir in Dir::"/a/");`, "resource is Dir"},
		{`permit (principal, action == Action::"ProcessExec", resource in Dir::"/a/") when { false };`, "when { false }"},
	} {
		text := "forbid (principal, action == Action::\"ProcessExec\", resource) when { resource in [File::\"/bin/rm\"] };\n\n" + tc.policy
		_, err := rewriteLegacyErr(t, text)
		var ue *UnenforceableError
		if !errors.As(err, &ue) || len(ue.Findings) != 1 {
			t.Errorf("%s: want one unenforceable finding, got %v", tc.policy, err)
			continue
		}
		f := ue.Findings[0]
		if f.ID != "policy1" || !strings.HasPrefix(f.Policy, "policy1 at leash.cedar:3:1") || f.Effect != "permit" {
			t.Errorf("%s: finding names %q/%q (%s), want policy1 at leash.cedar:3:1", tc.policy, f.ID, f.Policy, f.Effect)
		}
		if !strings.Contains(f.Reason, tc.want) || !strings.Contains(f.Reason, "allowing more than the policy says") {
			t.Errorf("%s: reason %q lacks %q", tc.policy, f.Reason, tc.want)
		}
		if !strings.HasPrefix(err.Error(), "policy policy1 at leash.cedar:3:1: permit cannot be enforced") {
			t.Errorf("error must start with the policy and its position: %v", err)
		}
	}
}

// Every unenforceable policy of a file is reported, not only the first.
func TestLegacyReportsEveryUnenforceablePolicy(t *testing.T) {
	_, err := rewriteLegacyErr(t, `@id("a")
permit (principal == User::"x", action == Action::"ProcessExec", resource in Dir::"/a/");
permit (principal, action == Action::"ProcessExec", resource in Dir::"/b/");
@id("c")
permit (principal, action == Action::"NetworkConnect", resource == Host::"c.com") when { context.port == 1 };`)
	var ue *UnenforceableError
	if !errors.As(err, &ue) || len(ue.Findings) != 2 {
		t.Fatalf("want two findings, got %v", err)
	}
	if ue.Findings[0].ID != "a" || !strings.Contains(ue.Findings[0].Policy, "leash.cedar:1:1") ||
		ue.Findings[1].ID != "c" || !strings.Contains(ue.Findings[1].Policy, "leash.cedar:4:1") {
		t.Fatalf("findings: %+v", ue.Findings)
	}
}

// What legacy semantics enforce exactly, or what grants nothing, still loads.
func TestLegacyAcceptsEnforceablePermits(t *testing.T) {
	for _, policy := range []string{
		`permit (principal, action == Action::"FileOpen", resource) when { resource in [Dir::"/a/", File::"/etc/hosts"] };`,
		`permit (principal, action == Action::"ProcessExec", resource in Dir::"/a/") when { true };`,
		`permit (principal, action == Action::"NetworkConnect", resource) when { context.hostname == "a.com" };`,
		`permit (principal, action == Action::"NetworkConnect", resource) when { context.hostname like "*.a.com" };`,
		`permit (principal, action == Action::"FileOpen", resource is File in Dir::"/a/");`,
		// MCP permits had no effect (MCP was default-allow).
		`permit (principal == User::"x", action == Action::"McpCall", resource) when { context.args == "x" };`,
		// HTTP rewrites are configuration; their header/value conditions are used.
		`permit (principal, action == Action::"HttpRewrite", resource == Host::"a.com") when { context.header == "A" && context.value == "b" };`,
		// Plugin actions keep Cedar semantics, conditions included.
		`permit (principal == Plugin::"sb", action == Secret::Action::"Read", resource == Secret::Item::"g") when { context.agent == "x" };`,
		// Lowers to no rule (the resource is inside an unparsed `&&`): grants nothing.
		`permit (principal, action == Action::"ProcessExec", resource) when { resource in Dir::"/a/" && context.x == 1 };`,
	} {
		if _, err := rewriteLegacyErr(t, policy); err != nil {
			t.Errorf("%s: %v", policy, err)
		}
	}
}

// A forbid enforced without its unenforceable constraint is stricter: it
// loads, with a note saying so.
func TestLegacyForbidWithDroppedConditionIsStricter(t *testing.T) {
	rw, err := rewriteLegacyErr(t, `
permit (principal, action == Action::"ProcessExec", resource in Dir::"/");
forbid (principal == User::"x", action == Action::"ProcessExec", resource in Dir::"/a/") when { context.tty == true };
forbid (principal, action == Action::"ProcessExec", resource in Dir::"/b/") unless { resource in Dir::"/b/ok/" };
forbid (principal, action == Action::"McpCall", resource == MCP::Tool::"shell") when { context.args == "x" };
`)
	if err != nil {
		t.Fatal(err)
	}
	notes := strings.Join(rw.Report.Summary(), "\n")
	if strings.Count(notes, "the forbid applies without it (stricter)") < 3 {
		t.Errorf("forbid notes must say the forbid is stricter:\n%s", notes)
	}
	e, err := engine.New(rw.Policies)
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]bool{"/a/x": false, "/b/x": false, "/b/ok/x": false, "/c": true} {
		if got := e.DecideExec(path).Allow; got != want {
			t.Errorf("exec %s: %v, want %v", path, got, want)
		}
	}
	if e.DecideMCP("s", "shell").Allow || !e.DecideMCP("s", "other").Allow {
		t.Error("the MCP forbid applies to its tool unconditionally")
	}
}

// A forbid whose resources legacy semantics would take from an unenforced
// constraint would forbid less than written (or the opposite): rejected.
func TestLegacyRejectsNarrowedForbids(t *testing.T) {
	for _, tc := range []struct{ policy, want string }{
		// Read as `when`: forbids only /bin/rm, the opposite of what is written.
		{`forbid (principal, action == Action::"ProcessExec", resource) unless { resource in [File::"/bin/rm"] };`, "read as `when`"},
		// Its only constraint is ignored: legacy dropped the forbid.
		{`forbid (principal, action == Action::"ProcessExec", resource) when { context.tty == true };`, "context.tty == true"},
		{`forbid (principal, action == Action::"FileOpen", resource) when { resource in Dir::"/a/" || resource in Dir::"/b/" };`, "||"},
		// MCP forbids scan the whole policy for servers.
		{`forbid (principal, action == Action::"McpCall", resource) unless { resource in MCP::Server::"trusted" };`, "MCP::Server"},
		{`forbid (principal, action == Action::"McpCall", resource == MCP::Tool::"t") when { !(resource in MCP::Server::"a") };`, "MCP::Server"},
	} {
		_, err := rewriteLegacyErr(t, tc.policy)
		var ue *UnenforceableError
		if !errors.As(err, &ue) || len(ue.Findings) != 1 || ue.Findings[0].Effect != "forbid" {
			t.Errorf("%s: want a forbid finding, got %v", tc.policy, err)
			continue
		}
		if r := ue.Findings[0].Reason; !strings.Contains(r, tc.want) || !strings.Contains(r, "forbid") {
			t.Errorf("%s: reason %q lacks %q", tc.policy, r, tc.want)
		}
	}
}

func TestLintReportsUnenforceablePermit(t *testing.T) {
	rep, err := LintFromString(legacyMarker + `@id("tty-only")
permit (principal, action == Action::"ProcessExec", resource in Dir::"/a/") when { context.tty == true };`)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, is := range rep.Issues {
		if is.Code == "unenforceable_condition" {
			found = true
			if is.Severity != LintError || is.PolicyID != "tty-only" || !strings.Contains(is.Message, "tty-only at policies:1:1") {
				t.Errorf("issue: %+v", is)
			}
		}
	}
	if !found {
		t.Fatalf("no unenforceable_condition issue: %+v", rep.Issues)
	}
}

func TestMigrateRefusesUnenforceablePermit(t *testing.T) {
	_, _, _, err := MigrateText("leash.cedar", legacyMarker+`permit (principal == User::"x", action == Action::"ProcessExec", resource in Dir::"/a/");`)
	var ue *UnenforceableError
	if !errors.As(err, &ue) {
		t.Fatalf("migrate must refuse an unenforceable permit, got %v", err)
	}
}

func compileStrictText(t *testing.T, text string) error {
	t.Helper()
	ps, err := cedarlib.NewPolicySetFromBytes("strict.cedar", []byte(text))
	if err != nil {
		t.Fatal(err)
	}
	eng, err := engine.New(ps)
	if err != nil {
		t.Fatal(err)
	}
	_, err = CompileKernel(ps, eng)
	return err
}

// Strict McpCall policies are evaluated in userspace, but the MCP adapters
// supply context.server, context.args and context.argNames (#113): anything
// else could never apply as written.
func TestStrictMCPConditionsMustBeSupplied(t *testing.T) {
	for _, tc := range []struct {
		policy string
		ok     bool
	}{
		{`permit (principal, action == Action::"McpCall", resource) when { context.server == "mcp.example.com" };`, true},
		{`permit (principal, action == Action::"McpCall", resource) when { context has server && context["server"] like "*.example.com" };`, true},
		{`permit (principal, action == Action::"McpCall", resource in MCP::Server::"s") unless { resource == MCP::Tool::"shell" };`, true},
		{`forbid (principal, action == Action::"McpCall", resource) when { context.server == "evil" };`, true},
		// #113: the call's arguments.
		{`permit (principal, action == Action::"McpCall", resource) when { context has args };`, true},
		{`permit (principal, action == Action::"McpCall", resource) when { context has args && context.args has repo && context.args.repo == "github.com/o/r" };`, true},
		{`permit (principal, action == Action::"McpCall", resource) when { context.args["repo-id"] == "r" && context.args.limit < 50 && context.args.exact == true };`, true},
		{`permit (principal, action == Action::"McpCall", resource) when { context has argNames && ["repo", "query"].containsAll(context.argNames) };`, true},
		{`forbid (principal, action == Action::"McpCall", resource) unless { context has args && context.args has repo && context.args.repo == "r" && !context.argNames.contains("repos") };`, true},
		{`permit (principal, action == Action::"McpCall", resource) when { context.args == "x" };`, false},
		{`permit (principal, action == Action::"McpCall", resource) when { context.args == {"repo": "r"} };`, false},
		{`permit (principal, action == Action::"McpCall", resource) when { context.args.repo.owner == "o" };`, false},
		{`permit (principal, action == Action::"McpCall", resource) when { context.tool == "search" };`, false},
		{`permit (principal, action == Action::"McpCall", resource) when { context has method };`, false},
		{`permit (principal, action == Action::"McpCall", resource) when { context == {"server": "s"} };`, false},
		{`permit (principal, action == Action::"McpCall", resource) when { principal == Workload::"workload" };`, false},
		{`permit (principal, action == Action::"McpCall", resource) when { resource.owner == "me" };`, false},
		{`permit (principal, action == Action::"McpCall", resource) when { resource has owner };`, false},
		{`forbid (principal, action == Action::"McpCall", resource) when { context.args like "*rm*" };`, false},
	} {
		err := compileStrictText(t, "@leash_semantics(\"cedar\")\n"+tc.policy)
		var ue *UnenforceableError
		switch {
		case tc.ok && err != nil:
			t.Errorf("%s: %v", tc.policy, err)
		case !tc.ok && !errors.As(err, &ue):
			t.Errorf("%s: want an unenforceable error, got %v", tc.policy, err)
		case !tc.ok && !strings.HasPrefix(err.Error(), "policy policy0 at strict.cedar:1:1: "):
			t.Errorf("%s: error must name the policy and its position: %v", tc.policy, err)
		}
	}
}

// The policy shape Walk generates for a repo-pinned, retrieval-only
// code-indexer MCP endpoint (#113; docs/design/CEDAR.md) loads in a strict
// file next to kernel-enforced rules.
func TestPinnedRetrievalCapabilityPolicyLoads(t *testing.T) {
	const cond = `resource in MCP::Server::"ci.example.com" &&
  resource in [MCP::Tool::"search", MCP::Tool::"bundle"] &&
  context has args && context.args has repo && context.args.repo == "github.com/o/r" &&
  context has argNames && ["repo", "query", "limit"].containsAll(context.argNames)`
	text := `@leash_semantics("cedar")
@id("walk-code-indexer-retrieval")
permit (principal, action == Action::"McpCall", resource) when { ` + cond + ` };
@id("walk-code-indexer-only")
forbid (principal, action == Action::"McpCall", resource) unless { ` + cond + ` };
permit (principal, action == Action::"NetworkConnect", resource in Host::"ci.example.com");
permit (principal, action in Action::"FileOpen", resource in Dir::"/workspace/");`
	if err := compileStrictText(t, text); err != nil {
		t.Fatal(err)
	}
}

// Plugin-action policies keep every condition the plugin's request context
// supplies, in legacy and strict files: cedar.Authorize decides them.
func TestPluginConditionsAreEvaluatedWithRequestContext(t *testing.T) {
	const policy = `@id("grant")
permit (principal == Plugin::"sb", action == Secret::Action::"Read", resource == Secret::Item::"g")
when { context has agent && context.agent == "antigravity" && context.attempt < 3 };`
	legacy, err := rewriteLegacyErr(t, policy)
	if err != nil {
		t.Fatal(err)
	}
	strict, err := cedarlib.NewPolicySetFromBytes("strict.cedar", []byte("@leash_semantics(\"cedar\")\n"+policy))
	if err != nil {
		t.Fatal(err)
	}
	for name, ps := range map[string]*cedarlib.PolicySet{"legacy": legacy.Policies, "strict": strict} {
		e, err := engine.New(ps)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := CompileKernel(ps, e); err != nil {
			t.Fatalf("%s: a plugin condition must load: %v", name, err)
		}
		req := func(ctx map[string]engine.Value) engine.Request {
			return engine.Request{
				Principal: engine.EntityUID{Type: "Plugin", ID: "sb"},
				Action:    engine.EntityUID{Type: "Secret::Action", ID: "Read"},
				Resource:  engine.EntityUID{Type: "Secret::Item", ID: "g"},
				Context:   ctx,
			}
		}
		if d := e.Decide(req(map[string]engine.Value{"agent": {Kind: engine.ValueString, Str: "antigravity"}, "attempt": {Kind: engine.ValueLong, Long: 1}})); !d.Allow {
			t.Errorf("%s: the condition holds: %+v", name, d)
		}
		if d := e.Decide(req(map[string]engine.Value{"agent": {Kind: engine.ValueString, Str: "other"}, "attempt": {Kind: engine.ValueLong, Long: 1}})); d.Allow {
			t.Errorf("%s: the condition fails: %+v", name, d)
		}
		if d := e.Decide(req(nil)); d.Allow {
			t.Errorf("%s: no context: %+v", name, d)
		}
	}
}
