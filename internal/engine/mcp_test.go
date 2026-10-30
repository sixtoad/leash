package engine

import (
	"fmt"
	"math/rand"
	"slices"
	"sort"
	"strings"
	"testing"
)

// pinnedRetrievalPolicy is the policy shape Walk generates for a
// repo-pinned, retrieval-only code-indexer MCP endpoint (#113): one permit
// for the pinned calls, and a forbid of every other McpCall so a broader
// permit in another layer cannot widen it.
func pinnedRetrievalPolicy(server, repo string, tools, names []string) string {
	quote := func(xs []string, f func(string) string) string {
		out := make([]string, len(xs))
		for i, x := range xs {
			out[i] = f(x)
		}
		return strings.Join(out, ", ")
	}
	toolSet := "[" + quote(tools, func(s string) string { return fmt.Sprintf("MCP::Tool::%q", s) }) + "]"
	nameSet := "[" + quote(names, func(s string) string { return fmt.Sprintf("%q", s) }) + "]"
	cond := fmt.Sprintf(`resource in MCP::Server::%q && resource in %s && context has args && context.args has repo && context.args.repo == %q && context has argNames && %s.containsAll(context.argNames)`, server, toolSet, repo, nameSet)
	return fmt.Sprintf(`@id("walk-code-indexer-retrieval")
permit (principal, action == Action::"McpCall", resource) when { %s };
@id("walk-code-indexer-only")
forbid (principal, action == Action::"McpCall", resource) unless { %s };
`, cond, cond)
}

func TestDecideMCPCallContext(t *testing.T) {
	e := mustEngine(t, pinnedRetrievalPolicy("ci.example.com", "github.com/o/r", []string{"search", "bundle"}, []string{"repo", "query", "limit"}))
	args := func(kv ...any) map[string]Value {
		m := map[string]Value{}
		for i := 0; i < len(kv); i += 2 {
			switch v := kv[i+1].(type) {
			case string:
				m[kv[i].(string)] = StringValue(v)
			case int:
				m[kv[i].(string)] = LongValue(int64(v))
			case bool:
				m[kv[i].(string)] = BoolValue(v)
			}
		}
		return m
	}
	known := func(server, tool string, a map[string]Value, names ...string) MCPCall {
		if names == nil {
			for k := range a {
				names = append(names, k)
			}
		}
		return MCPCall{Server: server, Tool: tool, ArgsKnown: true, Args: a, ArgNames: names}
	}
	for _, tc := range []struct {
		name   string
		call   MCPCall
		allow  bool
		reason string
	}{
		{"pinned", known("ci.example.com", "search", args("repo", "github.com/o/r", "query", "auth", "limit", 5)), true, ReasonMatchedPermit},
		{"server URL normalized", known("https://CI.example.com:443/mcp", "Bundle", args("repo", "github.com/o/r")), true, ReasonMatchedPermit},
		{"other repo", known("ci.example.com", "search", args("repo", "github.com/o/x")), false, ReasonMatchedForbid},
		{"repo case differs", known("ci.example.com", "search", args("repo", "github.com/O/r")), false, ReasonMatchedForbid},
		{"repo not a string", known("ci.example.com", "search", args("repo", 7)), false, ReasonMatchedForbid},
		{"repo omitted (unrepresentable)", known("ci.example.com", "search", args(), "repo"), false, ReasonMatchedForbid},
		{"repo missing", known("ci.example.com", "search", args("query", "x")), false, ReasonMatchedForbid},
		{"extra argument", known("ci.example.com", "search", args("repo", "github.com/o/r"), "repo", "repos"), false, ReasonMatchedForbid},
		{"mutation tool", known("ci.example.com", "index", args("repo", "github.com/o/r")), false, ReasonMatchedForbid},
		{"other server", known("mcp.example.com", "search", args("repo", "github.com/o/r")), false, ReasonMatchedForbid},
		{"arguments unknown", MCPCall{Server: "ci.example.com", Tool: "search"}, false, ReasonMatchedForbid},
		{"invalid: arg outside names", known("ci.example.com", "search", args("repo", "github.com/o/r"), "query"), false, ReasonInvalidRequest},
		{"invalid: duplicate name", known("ci.example.com", "search", args("repo", "github.com/o/r"), "repo", "repo"), false, ReasonInvalidRequest},
		{"invalid: long string", known("ci.example.com", "search", args("repo", strings.Repeat("a", MaxMCPArgStringBytes+1))), false, ReasonInvalidRequest},
		{"invalid: long name", known("ci.example.com", "search", args(), strings.Repeat("n", MaxMCPArgNameBytes+1)), false, ReasonInvalidRequest},
		{"invalid: set value", known("ci.example.com", "search", map[string]Value{"repo": SetValue(StringValue("github.com/o/r"))}), false, ReasonInvalidRequest},
		{"invalid: args not known", MCPCall{Server: "ci.example.com", Tool: "search", Args: args("repo", "x")}, false, ReasonInvalidRequest},
	} {
		got := e.DecideMCPCall(tc.call)
		if got.Allow != tc.allow || got.Reason != tc.reason {
			t.Errorf("%s: got %+v, want allow=%v reason=%s", tc.name, got, tc.allow, tc.reason)
		}
	}
	many := MCPCall{Server: "ci.example.com", Tool: "search", ArgsKnown: true}
	for i := 0; i <= MaxMCPArgs; i++ {
		many.ArgNames = append(many.ArgNames, fmt.Sprintf("a%d", i))
	}
	if got := e.DecideMCPCall(many); got.Reason != ReasonInvalidRequest {
		t.Errorf("over MaxMCPArgs: %+v", got)
	}
	// DecideMCP (no arguments) is the arguments-unknown request.
	if got := e.DecideMCP("ci.example.com", "search"); got.Allow {
		t.Errorf("DecideMCP without arguments must not satisfy an argument pin: %+v", got)
	}
}

// A broader permit in another policy layer cannot widen the pinned
// capability: the forbid applies to every call the permit does not cover.
func TestPinnedRetrievalForbidOverridesBroaderPermits(t *testing.T) {
	e := mustEngine(t, pinnedRetrievalPolicy("ci.example.com", "github.com/o/r", []string{"search"}, []string{"repo"})+`
permit (principal, action == Action::"McpCall", resource);
permit (principal, action, resource);`)
	if !e.HasMCPPolicies() {
		t.Fatal("the proxy must inspect MCP")
	}
	ok := MCPCall{Server: "ci.example.com", Tool: "search", ArgsKnown: true, Args: map[string]Value{"repo": StringValue("github.com/o/r")}, ArgNames: []string{"repo"}}
	if d := e.DecideMCPCall(ok); !d.Allow {
		t.Fatalf("pinned call: %+v", d)
	}
	for _, c := range []MCPCall{
		{Server: "other.example.com", Tool: "anything"},
		{Server: "ci.example.com", Tool: "index", ArgsKnown: true, Args: map[string]Value{"repo": StringValue("github.com/o/r")}, ArgNames: []string{"repo"}},
		{Server: "ci.example.com", Tool: "search", ArgsKnown: true, Args: map[string]Value{"repo": StringValue("github.com/o/x")}, ArgNames: []string{"repo"}},
		{Server: "ci.example.com", Tool: "search"},
	} {
		if d := e.DecideMCPCall(c); d.Allow || !slices.Contains(d.PolicyIDs, "walk-code-indexer-only") {
			t.Errorf("%+v: %+v", c, d)
		}
	}
}

// Oracle test: random pinned-capability policies and random calls; the
// engine's decision (cedar.Authorize) equals the intended semantics, and
// the generic request (the authz socket's shape) decides like DecideMCPCall.
func TestPinnedRetrievalOracle(t *testing.T) {
	rng := rand.New(rand.NewSource(113))
	servers := []string{"ci.example.com", "mcp.example.com", "CI.example.com", "ci.example.com.evil.net", "https://ci.example.com/mcp"}
	tools := []string{"search", "bundle", "graph", "index", "reindex", "delete", "Search"}
	repos := []string{"github.com/o/r", "github.com/o/r", "github.com/o/r", "github.com/o/x", "github.com/O/r", "", "github.com/o/r "}
	allNames := []string{"repo", "query", "limit", "scope", "repos", "path"}
	pick := func(xs []string) string { return xs[rng.Intn(len(xs))] }
	subset := func(xs []string) []string {
		var out []string
		for _, x := range xs {
			if rng.Intn(2) == 0 {
				out = append(out, x)
			}
		}
		return out
	}
	const policies, calls = 60, 400
	allowed := 0
	for p := 0; p < policies; p++ {
		pinServer := "ci.example.com"
		pinRepo := "github.com/o/r"
		pinTools := append([]string{"search"}, subset([]string{"bundle", "graph"})...)
		pinNames := append([]string{"repo"}, subset([]string{"query", "limit", "scope"})...)
		text := pinnedRetrievalPolicy(pinServer, pinRepo, pinTools, pinNames)
		if rng.Intn(2) == 0 {
			text += "permit (principal, action == Action::\"McpCall\", resource);\n"
		}
		e := mustEngine(t, text)
		for c := 0; c < calls; c++ {
			call := MCPCall{Server: pick(servers), Tool: pick(tools)}
			if rng.Intn(6) != 0 {
				call.ArgsKnown = true
				call.Args = map[string]Value{}
				call.ArgNames = subset(allNames)
				for _, n := range call.ArgNames {
					switch rng.Intn(5) {
					case 0: // omitted: unrepresentable value
					case 1:
						call.Args[n] = LongValue(rng.Int63n(100))
					default:
						call.Args[n] = StringValue(pick(repos))
					}
				}
			}
			want := NormalizeMCPServer(call.Server) == pinServer &&
				slices.Contains(pinTools, NormalizeMCPTool(call.Tool)) &&
				call.ArgsKnown &&
				call.Args["repo"].Kind == ValueString && call.Args["repo"].Str == pinRepo
			if want {
				for _, n := range call.ArgNames {
					if !slices.Contains(pinNames, n) {
						want = false
					}
				}
			}
			got := e.DecideMCPCall(call)
			if got.Allow {
				allowed++
			}
			if got.Allow != want {
				t.Fatalf("policy:\n%s\ncall %+v: engine allow=%v (%+v), oracle %v", text, call, got.Allow, got, want)
			}
			ctx := map[string]Value{"server": StringValue(call.Server)}
			if call.ArgsKnown {
				ctx["args"] = RecordValue(call.Args)
				names := append([]string(nil), call.ArgNames...)
				sort.Strings(names)
				set := make([]Value, len(names))
				for i, n := range names {
					set[i] = StringValue(n)
				}
				ctx["argNames"] = SetValue(set...)
			}
			generic := e.Decide(Request{Action: EntityUID{BuiltinActionType, ActionMcpCall}, Resource: EntityUID{TypeMCPTool, call.Tool}, Context: ctx})
			if generic.Allow != got.Allow || generic.Reason != got.Reason || !slices.Equal(generic.PolicyIDs, got.PolicyIDs) {
				t.Fatalf("call %+v: generic request %+v != DecideMCPCall %+v", call, generic, got)
			}
		}
	}
	if allowed < 50 {
		t.Fatalf("only %d allowed calls: the generator does not exercise the permit", allowed)
	}
}

func TestGenericMCPRequestValidation(t *testing.T) {
	e := mustEngine(t, `permit (principal, action == Action::"McpCall", resource);`)
	req := func(ctx map[string]Value) Request {
		return Request{Action: EntityUID{BuiltinActionType, ActionMcpCall}, Resource: EntityUID{TypeMCPTool, "search"}, Context: ctx}
	}
	for name, ctx := range map[string]map[string]Value{
		"server not string":     {"server": LongValue(1)},
		"args not record":       {"args": StringValue("repo")},
		"argNames without args": {"argNames": SetValue(StringValue("repo"))},
		"argNames not set":      {"args": RecordValue(map[string]Value{}), "argNames": StringValue("repo")},
		"argNames not strings":  {"args": RecordValue(map[string]Value{}), "argNames": SetValue(LongValue(1))},
		"nested record":         {"args": RecordValue(map[string]Value{"a": RecordValue(nil)})},
	} {
		if d := e.Decide(req(ctx)); d.Allow || d.Reason != ReasonInvalidRequest {
			t.Errorf("%s: %+v", name, d)
		}
	}
	// argNames defaults to the keys of args.
	pinned := mustEngine(t, `permit (principal, action == Action::"McpCall", resource) when { context has argNames && context.argNames == ["repo"] };`)
	if d := pinned.Decide(req(map[string]Value{"args": RecordValue(map[string]Value{"repo": StringValue("r")})})); !d.Allow {
		t.Errorf("argNames from args: %+v", d)
	}
	if got := RecordValue(map[string]Value{"b": LongValue(1), "a": StringValue("x")}).String(); got != `{"a": "x", "b": 1}` {
		t.Errorf("record rendering %s", got)
	}
}
