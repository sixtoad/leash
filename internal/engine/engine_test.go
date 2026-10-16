package engine

import (
	"math/rand"
	"slices"
	"strings"
	"testing"
	"time"

	cedar "github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
)

func mustEngine(t *testing.T, text string) *Engine {
	t.Helper()
	e, err := NewFromText("test.cedar", text)
	if err != nil {
		t.Fatalf("NewFromText: %v\n%s", err, text)
	}
	return e
}

func fileReq(action, path string) Request {
	return Request{Action: EntityUID{Type: BuiltinActionType, ID: action}, Resource: EntityUID{Type: TypeFile, ID: path}}
}

func TestFileHierarchy(t *testing.T) {
	e := mustEngine(t, `
permit (principal, action in Action::"FileOpen", resource in Dir::"/work");
permit (principal, action == Action::"ProcessExec", resource in Dir::"/opt/");
permit (principal, action == Action::"FileOpenReadOnly", resource in FilePrefix::"/bin/rm");
permit (principal, action == Action::"ProcessExec", resource == File::"/usr/bin/git");
`)
	cases := []struct {
		action, path string
		want         bool
	}{
		{ActionFileOpenReadWrite, "/work/a", true},
		{ActionFileOpenReadWrite, "/work", true}, // directory self (#119), also for Dir::"/work" without the slash
		{ActionFileOpenReadWrite, "/workx", false},
		{ActionProcessExec, "/opt/tool", true},
		{ActionProcessExec, "/opt", false}, // exec has no directory-self match
		{ActionFileOpenReadOnly, "/bin/rm", true},
		{ActionFileOpenReadOnly, "/bin/rmdir", true}, // FilePrefix is a byte prefix
		{ActionProcessExec, "/usr/bin/git", true},    // File is exact
		{ActionProcessExec, "/usr/bin/git2", false},
		{ActionFileOpenReadWrite, "/bin/rm", false},
	}
	for _, tc := range cases {
		if got := e.Decide(fileReq(tc.action, tc.path)); got.Allow != tc.want {
			t.Errorf("%s %s: got %+v, want allow=%v", tc.action, tc.path, got, tc.want)
		}
	}
}

func TestConnectHierarchy(t *testing.T) {
	e := mustEngine(t, `
permit (principal, action == Action::"NetworkConnect", resource in Host::"*.example.com");
permit (principal, action == Action::"NetworkConnect", resource in Host::"10.0.0.1:22");
permit (principal, action == Action::"NetworkConnect", resource in Host::"*:8443");
forbid (principal, action == Action::"NetworkConnect", resource in Host::"bad.example.com");
`)
	cases := []struct {
		host, ip string
		port     uint16
		want     bool
	}{
		{"api.example.com", "1.2.3.4", 443, true},
		{"API.Example.COM.", "", 0, true},
		{"example.com", "", 443, false},     // a wildcard excludes the apex
		{"evilexample.com", "", 443, false}, // and needs a label boundary
		{"bad.example.com", "", 443, false}, // forbid overrides permit
		{"", "10.0.0.1", 22, true},
		{"db.internal", "10.0.0.1", 22, true}, // IP rules match the destination address
		{"", "10.0.0.1", 23, false},
		{"anything.org", "", 8443, true},
		{"10.0.0.1", "", 22, true}, // an IP literal is an address, not a name
	}
	for _, tc := range cases {
		if got := e.DecideConnect(tc.host, tc.ip, tc.port); got.Allow != tc.want {
			t.Errorf("connect %q %q %d: got %+v, want allow=%v", tc.host, tc.ip, tc.port, got, tc.want)
		}
	}
	if got := e.DecideConnect("", "", 443); got.Reason != ReasonInvalidRequest {
		t.Errorf("connect without host or ip: %+v", got)
	}
}

func TestMCPHierarchyAndNormalization(t *testing.T) {
	e := mustEngine(t, `
forbid (principal, action == Action::"McpCall", resource in MCP::Tool::"execute-shell") when { resource in MCP::Server::"mcp.example.com" };
permit (principal, action == Action::"McpCall", resource);
`)
	if e.HasMCPPolicies() != true {
		t.Fatal("a forbid on McpCall must make the proxy inspect MCP")
	}
	for _, tc := range []struct {
		server, tool string
		want         bool
	}{
		{"https://MCP.example.com:8443/mcp", " Execute-Shell ", false},
		{"mcp.example.com", "search", true},
		{"other.example.com", "execute-shell", true},
	} {
		if got := e.DecideMCP(tc.server, tc.tool); got.Allow != tc.want {
			t.Errorf("mcp %q %q: %+v, want %v", tc.server, tc.tool, got, tc.want)
		}
	}
}

func TestHasMCPPolicies(t *testing.T) {
	for text, want := range map[string]bool{
		``: true, // strict default deny: every call must be inspected and refused
		`permit (principal, action == Action::"McpCall", resource);`:                                                                            false,
		`permit (principal, action, resource);`:                                                                                                 false,
		`permit (principal, action == Action::"McpCall", resource) when { context.server == "x" };`:                                             true,
		`permit (principal, action == Action::"NetworkConnect", resource);`:                                                                     true,
		"permit (principal, action == Action::\"McpCall\", resource);\nforbid (principal, action, resource) when { resource in Dir::\"/x/\" };": true,
	} {
		if got := mustEngine(t, text).HasMCPPolicies(); got != want {
			t.Errorf("%q: HasMCPPolicies=%v, want %v", text, got, want)
		}
	}
}

func TestNamespaceRule(t *testing.T) {
	e := mustEngine(t, `
@id("grant")
permit (principal == Plugin::"sb", action == Secret::Action::"Read", resource == Secret::Item::"g");
// An unconstrained action applies to Leash's actions only.
forbid (principal, action, resource);
permit (principal, action, resource);
// Another namespace never decides a Secret request.
forbid (principal, action == Other::Action::"Read", resource);
`)
	read := Request{Principal: EntityUID{TypePlugin, "sb"}, Action: EntityUID{"Secret::Action", "Read"}, Resource: EntityUID{"Secret::Item", "g"}}
	got := e.Decide(read)
	if !got.Allow || got.Reason != ReasonMatchedPermit || !slices.Equal(got.PolicyIDs, []string{"grant"}) {
		t.Fatalf("plugin grant: %+v", got)
	}
	read.Resource.ID = "other"
	if got := e.Decide(read); got.Allow || got.Reason != ReasonDefaultDeny {
		t.Fatalf("ungranted secret: %+v", got)
	}
	if got := e.DecideConnect("x.org", "", 443); got.Allow || got.Reason != ReasonMatchedForbid {
		t.Fatalf("built-in request under forbid-all: %+v", got)
	}
}

func TestPluginDecisionsAreCedarAuthorize(t *testing.T) {
	text := `
permit (principal == Plugin::"sb", action == Secret::Action::"Read", resource == Secret::Item::"gemini");
permit (principal, action in [Secret::Action::"Read", Secret::Action::"List"], resource is Secret::Item) when { context.approved == true };
forbid (principal, action == Secret::Action::"Read", resource) when { context has agent && context.agent like "*evil*" };
forbid (principal, action == Secret::Action::"List", resource) unless { context.n < 3 };
`
	e := mustEngine(t, text)
	ps, err := cedar.NewPolicySetFromBytes("test.cedar", []byte(text))
	if err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewSource(142))
	for i := 0; i < 5000; i++ {
		req := Request{
			Principal: EntityUID{TypePlugin, []string{"sb", "other"}[rng.Intn(2)]},
			Action:    EntityUID{"Secret::Action", []string{"Read", "List", "Write"}[rng.Intn(3)]},
			Resource:  EntityUID{[]string{"Secret::Item", "Secret::Vault"}[rng.Intn(2)], []string{"gemini", "x"}[rng.Intn(2)]},
			Context:   map[string]Value{},
		}
		if rng.Intn(2) == 0 {
			req.Context["approved"] = BoolValue(rng.Intn(2) == 0)
		}
		if rng.Intn(2) == 0 {
			req.Context["agent"] = StringValue([]string{"antigravity", "evilbot"}[rng.Intn(2)])
		}
		if rng.Intn(2) == 0 {
			req.Context["n"] = LongValue(int64(rng.Intn(6)))
		}
		got := e.Decide(req)
		ctx, _ := contextRecord(req.Context)
		want, diag := cedar.Authorize(ps, nil, cedar.Request{Principal: uid(req.Principal), Action: uid(req.Action), Resource: uid(req.Resource), Context: ctx})
		if got.Allow != bool(want) || len(got.PolicyIDs) != len(diag.Reasons) {
			t.Fatalf("%+v: engine %+v, cedar %v %+v", req, got, want, diag)
		}
	}
}

func TestExpires(t *testing.T) {
	e := mustEngine(t, `
@id("until-noon")
@expires("2026-10-16T12:00:00Z")
permit (principal, action == Secret::Action::"Read", resource);
`)
	req := Request{Principal: EntityUID{TypePlugin, "sb"}, Action: EntityUID{"Secret::Action", "Read"}, Resource: EntityUID{"Secret::Item", "g"}}
	before := e.WithClock(func() time.Time { return time.Date(2026, 10, 16, 11, 59, 0, 0, time.UTC) })
	after := e.WithClock(func() time.Time { return time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC) })
	if !before.Decide(req).Allow {
		t.Fatal("grant must apply before it expires")
	}
	if after.Decide(req).Allow {
		t.Fatal("grant must not apply from its expiry on")
	}
	if _, err := NewFromText("x", `@expires("tomorrow") permit (principal, action, resource);`); err == nil {
		t.Fatal("a malformed @expires must fail the load")
	}
}

func TestInvalidActionScopes(t *testing.T) {
	for _, text := range []string{
		`permit (principal, action in [Action::"FileOpen", Secret::Action::"Read"], resource);`,
		`permit (principal, action == Secret::Verb::"Read", resource);`,
	} {
		if _, err := NewFromText("x", text); err == nil {
			t.Errorf("%s: want an error", text)
		}
	}
}

func TestBuiltinRouting(t *testing.T) {
	e := mustEngine(t, `
@id("etc-read")
permit (principal, action == Action::"FileOpenReadOnly", resource in Dir::"/etc/");
forbid (principal, action in Action::"FileOpen", resource in File::"/etc/shadow");
permit (principal, action == Action::"ProcessExec", resource in Dir::"/usr/bin/");
permit (principal, action == Action::"NetworkConnect", resource in Host::"api.example.com");
@leash_source("leash.cedar:9")
forbid (principal, action == Action::"McpCall", resource in MCP::Tool::"delete") when { resource in MCP::Server::"mcp.example.com" };
permit (principal, action == Action::"McpCall", resource);
`)
	connect := func(host string, port int64) Request {
		return Request{Action: EntityUID{BuiltinActionType, ActionNetworkConnect}, Resource: EntityUID{TypeHost, host}, Context: map[string]Value{"port": LongValue(port)}}
	}
	mcp := func(server, tool string) Request {
		return Request{Action: EntityUID{BuiltinActionType, ActionMcpCall}, Resource: EntityUID{TypeMCPTool, tool}, Context: map[string]Value{"server": StringValue(server)}}
	}
	cases := []struct {
		name   string
		req    Request
		allow  bool
		reason string
		ids    []string
	}{
		{"read allowed", fileReq(ActionFileOpenReadOnly, "/etc/hosts"), true, ReasonMatchedPermit, []string{"etc-read"}},
		{"write not granted", fileReq(ActionFileOpenReadWrite, "/etc/hosts"), false, ReasonDefaultDeny, nil},
		{"generic open needs both", fileReq(ActionFileOpen, "/etc/hosts"), false, ReasonDefaultDeny, nil},
		{"forbid overrides permit", fileReq(ActionFileOpenReadOnly, "/etc/shadow"), false, ReasonMatchedForbid, []string{"policy1"}},
		{"exec", fileReq(ActionProcessExec, "/usr/bin/git"), true, ReasonMatchedPermit, []string{"policy2"}},
		{"connect", connect("API.example.com", 443), true, ReasonMatchedPermit, []string{"policy3"}},
		{"connect default deny", connect("other.example.com", 443), false, ReasonDefaultDeny, nil},
		{"mcp forbid", mcp("https://mcp.example.com/mcp", "delete"), false, ReasonMatchedForbid, []string{"leash.cedar:9"}},
		{"mcp permit", mcp("mcp.example.com", "search"), true, ReasonMatchedPermit, []string{"policy5"}},
		{"relative path", fileReq(ActionFileOpenReadOnly, "etc/hosts"), false, ReasonInvalidRequest, nil},
		{"bad port", connect("x", 70000), false, ReasonInvalidRequest, nil},
		{"rewrite not queryable", Request{Action: EntityUID{BuiltinActionType, ActionHttpRewrite}}, false, ReasonUnsupportedAction, nil},
		{"unknown type", Request{Action: EntityUID{"Bogus", "x"}}, false, ReasonUnsupportedAction, nil},
		{"plugin default deny", Request{Principal: EntityUID{TypePlugin, "p"}, Action: EntityUID{"Secret::Action", "Read"}, Resource: EntityUID{"Secret::Item", "g"}}, false, ReasonDefaultDeny, nil},
	}
	for _, tc := range cases {
		got := e.Decide(tc.req)
		if got.Allow != tc.allow || got.Reason != tc.reason || !slices.Equal(got.PolicyIDs, tc.ids) {
			t.Errorf("%s: got %+v, want allow=%v reason=%s ids=%v", tc.name, got, tc.allow, tc.reason, tc.ids)
		}
	}
	var nilEngine *Engine
	if got := nilEngine.Decide(fileReq(ActionFileOpenReadOnly, "/etc/hosts")); got.Allow || got.Reason != ReasonNoPolicy {
		t.Errorf("nil engine: %+v", got)
	}
}

func TestEvaluationErrorsDoNotApply(t *testing.T) {
	e := mustEngine(t, `
forbid (principal, action == Secret::Action::"Read", resource) when { context.agent == "evil" };
permit (principal, action == Secret::Action::"Read", resource);
`)
	got := e.Decide(Request{Principal: EntityUID{TypePlugin, "p"}, Action: EntityUID{"Secret::Action", "Read"}, Resource: EntityUID{"Secret::Item", "g"}})
	if !got.Allow || !strings.Contains(got.Detail, "evaluation error") {
		t.Fatalf("a forbid whose condition errors does not apply (Cedar): %+v", got)
	}
}

func TestFileParents(t *testing.T) {
	got := map[string]bool{}
	for _, p := range fileParents("/a/b", true) {
		got[p.String()] = true
	}
	for _, want := range []string{`FilePrefix::"/"`, `FilePrefix::"/a"`, `FilePrefix::"/a/"`, `FilePrefix::"/a/b"`, `Dir::"/"`, `Dir::"/a/"`, `Dir::"/a"`, `Dir::"/a/b/"`, `Dir::"/a/b"`} {
		if !got[want] {
			t.Errorf("missing parent %s in %v", want, got)
		}
	}
	// File is exact: a path has no File parent.
	if got[`File::"/a"`] || got[`File::"/a/b"`] || got[`Dir::"/a/b/c/"`] {
		t.Errorf("unexpected parents %v", got)
	}
	for _, p := range fileParents("/a/b", false) {
		if p == types.NewEntityUID(TypeDir, "/a/b/") {
			t.Error("exec paths have no directory-self parent")
		}
	}
}
