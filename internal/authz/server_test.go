package authz

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/strongdm/leash/internal/cedar"
	"github.com/strongdm/leash/internal/engine"
	"github.com/strongdm/leash/internal/lsm"
	"github.com/strongdm/leash/internal/policy"
	wire "github.com/strongdm/leash/pkg/authz"
)

const testPolicy = `
@id("gemini")
permit (principal == Plugin::"secretbroker", action == Secret::Action::"Read", resource == Secret::Item::"gemini");

@id("no-ssh")
forbid (principal, action == Secret::Action::"Read", resource == Secret::Item::"ssh");

@id("agent-scoped")
permit (principal, action == Secret::Action::"Read", resource is Secret::Item)
when { context has agent && context.agent == "antigravity" && context.tags.contains("ci") };

forbid (principal, action == Action::"McpCall", resource == MCP::Tool::"delete");

permit (principal, action == Action::"NetworkConnect", resource == Host::"api.example.com");
`

func publish(t *testing.T, d *policy.Decisions, text string) {
	t.Helper()
	comp, err := cedar.CompileString("test.cedar", text)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	d.Publish(comp.Engine)
}

// shortTempDir keeps socket paths under the 104-byte sun_path limit on macOS.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "lz")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

type testServer struct {
	srv       *Server
	decisions *policy.Decisions
	socket    string
	logPath   string
}

func startServer(t *testing.T, grant PluginGrant, mutate func(*Config)) *testServer {
	t.Helper()
	dir := shortTempDir(t)
	if grant.Socket == "" {
		grant.Socket = filepath.Join(dir, "authz.sock")
	}
	if grant.UID == 0 {
		grant.UID = os.Getuid()
	}
	logPath := filepath.Join(dir, "events.log")
	logger, err := lsm.NewSharedLogger(logPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { logger.Close() })
	decisions := &policy.Decisions{}
	cfg := Config{Grants: []PluginGrant{grant}, Source: decisions.Current, Logger: logger}
	if mutate != nil {
		mutate(&cfg)
	}
	srv := New(cfg)
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	return &testServer{srv: srv, decisions: decisions, socket: grant.Socket, logPath: logPath}
}

func secretbroker() PluginGrant {
	return PluginGrant{ID: "secretbroker", Namespaces: []string{"Secret"}}
}

func read(id string) wire.Request {
	return wire.Request{Action: wire.UID("Secret::Action", "Read"), Resource: wire.UID("Secret::Item", id)}
}

func TestServerDecidesThroughTheDecisionCore(t *testing.T) {
	ts := startServer(t, secretbroker(), nil)
	c := wire.New(ts.socket)
	defer c.Close()
	ctx := context.Background()

	if d := c.Check(ctx, read("gemini")); d.Allowed() || d.Reason != wire.ReasonNoPolicy {
		t.Fatalf("before a policy loads: %+v", d)
	}
	publish(t, ts.decisions, testPolicy)

	cases := []struct {
		name   string
		req    wire.Request
		allow  bool
		reason string
	}{
		{"static grant", read("gemini"), true, wire.ReasonMatchedPermit},
		{"forbid", read("ssh"), false, wire.ReasonMatchedForbid},
		{"default deny", read("aws"), false, wire.ReasonDefaultDeny},
		{"context grant", wire.Request{Action: wire.UID("Secret::Action", "Read"), Resource: wire.UID("Secret::Item", "aws"),
			Context: map[string]any{"agent": "antigravity", "tags": []string{"ci", "x"}}}, true, wire.ReasonMatchedPermit},
		{"context mismatch", wire.Request{Action: wire.UID("Secret::Action", "Read"), Resource: wire.UID("Secret::Item", "aws"),
			Context: map[string]any{"agent": "antigravity", "tags": []string{"dev"}}}, false, wire.ReasonDefaultDeny},
		{"namespace not granted", wire.Request{Action: wire.UID("CodeIndex::Action", "Retrieve"), Resource: wire.UID("CodeIndex::Repo", "x")}, false, wire.ReasonNamespaceNotGranted},
		{"builtin not granted", wire.Request{Action: wire.UID("Action", "McpCall"), Resource: wire.UID("MCP::Tool", "delete")}, false, wire.ReasonNamespaceNotGranted},
		{"bad context", wire.Request{Action: wire.UID("Secret::Action", "Read"), Resource: wire.UID("Secret::Item", "aws"),
			Context: map[string]any{"n": 1.5}}, false, wire.ReasonInvalidRequest},
		{"flat record context", wire.Request{Action: wire.UID("Secret::Action", "Read"), Resource: wire.UID("Secret::Item", "aws"),
			Context: map[string]any{"r": map[string]any{"a": 1}}}, false, wire.ReasonDefaultDeny},
		{"nested record context", wire.Request{Action: wire.UID("Secret::Action", "Read"), Resource: wire.UID("Secret::Item", "aws"),
			Context: map[string]any{"r": map[string]any{"a": map[string]any{"b": 1}}}}, false, wire.ReasonInvalidRequest},
		{"record holding a set", wire.Request{Action: wire.UID("Secret::Action", "Read"), Resource: wire.UID("Secret::Item", "aws"),
			Context: map[string]any{"r": map[string]any{"a": []string{"x"}}}}, false, wire.ReasonInvalidRequest},
		{"record in a set", wire.Request{Action: wire.UID("Secret::Action", "Read"), Resource: wire.UID("Secret::Item", "aws"),
			Context: map[string]any{"r": []any{map[string]any{"a": 1}}}}, false, wire.ReasonInvalidRequest},
		{"unknown action type", wire.Request{Action: wire.UID("Bogus", "x"), Resource: wire.UID("X", "y")}, false, wire.ReasonUnsupportedAction},
	}
	for _, tc := range cases {
		d := c.Check(ctx, tc.req)
		if d.Err != nil {
			t.Fatalf("%s: transport error %v", tc.name, d.Err)
		}
		if d.Allowed() != tc.allow || d.Reason != tc.reason {
			t.Errorf("%s: got allow=%v reason=%s (%s), want allow=%v reason=%s", tc.name, d.Allowed(), d.Reason, d.Error, tc.allow, tc.reason)
		}
		if d.Principal != wire.UID("Plugin", "secretbroker") {
			t.Errorf("%s: principal = %v", tc.name, d.Principal)
		}
	}

	// Hot reload: the next request sees the new policy and generation.
	before := c.Check(ctx, read("gemini"))
	publish(t, ts.decisions, `forbid (principal, action, resource);`)
	after := c.Check(ctx, read("gemini"))
	if after.Allowed() || after.Generation <= before.Generation {
		t.Fatalf("reload not observed: before=%+v after=%+v", before.Response, after.Response)
	}

	logData, _ := os.ReadFile(ts.logPath)
	log := string(logData)
	if !strings.Contains(log, `event=authz.decision plugin=secretbroker action="Secret::Action::\"Read\"" resource="Secret::Item::\"gemini\"" decision=allow reason=matched_permit policies="gemini"`) {
		t.Fatalf("audit log missing the allow decision:\n%s", log)
	}
	if strings.Contains(log, "antigravity") {
		t.Fatal("audit log leaked a context value")
	}
	if !strings.Contains(log, `context_keys="agent,tags"`) {
		t.Fatalf("audit log missing context keys:\n%s", log)
	}
}

// #164 rejects permits whose condition no adapter can enforce. Plugin
// policies are evaluated with the context the plugin sends, so their
// conditions keep loading and deciding, in strict files as in legacy ones
// (testPolicy above is legacy). A built-in McpCall query may test
// context.server, which the socket passes on.
func TestServerPluginConditionsSurviveTheUnenforceableCheck(t *testing.T) {
	ts := startServer(t, PluginGrant{ID: "secretbroker", Namespaces: []string{"Secret", "Action"}}, nil)
	c := wire.New(ts.socket)
	defer c.Close()
	ctx := context.Background()
	publish(t, ts.decisions, `@leash_semantics("cedar")
@id("agent-scoped")
permit (principal == Plugin::"secretbroker", action == Secret::Action::"Read", resource is Secret::Item)
when { context has agent && context.agent == "antigravity" && context.attempt < 3 };
@leash_semantics("cedar")
permit (principal, action == Action::"McpCall", resource) when { context.server == "mcp.example.com" };`)
	for _, tc := range []struct {
		name  string
		req   wire.Request
		allow bool
	}{
		{"context holds", wire.Request{Action: wire.UID("Secret::Action", "Read"), Resource: wire.UID("Secret::Item", "aws"),
			Context: map[string]any{"agent": "antigravity", "attempt": 1}}, true},
		{"context fails", wire.Request{Action: wire.UID("Secret::Action", "Read"), Resource: wire.UID("Secret::Item", "aws"),
			Context: map[string]any{"agent": "antigravity", "attempt": 5}}, false},
		{"no context", read("aws"), false},
		{"mcp server holds", wire.Request{Action: wire.UID("Action", "McpCall"), Resource: wire.UID("MCP::Tool", "search"),
			Context: map[string]any{"server": "mcp.example.com"}}, true},
		{"mcp server fails", wire.Request{Action: wire.UID("Action", "McpCall"), Resource: wire.UID("MCP::Tool", "search"),
			Context: map[string]any{"server": "other.example.com"}}, false},
	} {
		d := c.Check(ctx, tc.req)
		if d.Err != nil || d.Allowed() != tc.allow {
			t.Errorf("%s: allow=%v reason=%s err=%v, want allow=%v", tc.name, d.Allowed(), d.Reason, d.Err, tc.allow)
		}
	}
}

func TestServerBuiltinQueriesMatchTheProxy(t *testing.T) {
	ts := startServer(t, PluginGrant{ID: "mcp-gate", Namespaces: []string{"Action"}}, nil)
	publish(t, ts.decisions, testPolicy)
	c := wire.New(ts.socket)
	defer c.Close()
	proxy := ts.decisions.Current().Engine

	for _, tool := range []string{"delete", "search"} {
		d := c.Check(context.Background(), wire.Request{Action: wire.UID("Action", "McpCall"), Resource: wire.UID("MCP::Tool", tool), Context: map[string]any{"server": "mcp.example.com"}})
		if want := proxy.CheckMCPCall("mcp.example.com", tool); d.Allowed() != want {
			t.Errorf("McpCall %s: socket=%v proxy=%v", tool, d.Allowed(), want)
		}
	}
	// #113: context.args and context.argNames reach the same decision as the
	// proxy's DecideMCPCall.
	publish(t, ts.decisions, `@id("pinned")
permit (principal, action == Action::"McpCall", resource in MCP::Server::"ci.example.com")
when { resource in [MCP::Tool::"search"] && context has args && context.args has repo && context.args.repo == "github.com/o/r" && ["repo", "query"].containsAll(context.argNames) };`)
	proxy = ts.decisions.Current().Engine
	for _, tc := range []struct {
		name string
		ctx  map[string]any
		call engine.MCPCall
	}{
		{"pinned", map[string]any{"server": "ci.example.com", "args": map[string]any{"repo": "github.com/o/r", "query": "x"}},
			engine.MCPCall{Server: "ci.example.com", Tool: "search", ArgsKnown: true, Args: map[string]engine.Value{"repo": engine.StringValue("github.com/o/r"), "query": engine.StringValue("x")}, ArgNames: []string{"query", "repo"}}},
		{"other repo", map[string]any{"server": "ci.example.com", "args": map[string]any{"repo": "github.com/o/x"}},
			engine.MCPCall{Server: "ci.example.com", Tool: "search", ArgsKnown: true, Args: map[string]engine.Value{"repo": engine.StringValue("github.com/o/x")}, ArgNames: []string{"repo"}}},
		{"extra argument named", map[string]any{"server": "ci.example.com", "args": map[string]any{"repo": "github.com/o/r"}, "argNames": []string{"repo", "repos"}},
			engine.MCPCall{Server: "ci.example.com", Tool: "search", ArgsKnown: true, Args: map[string]engine.Value{"repo": engine.StringValue("github.com/o/r")}, ArgNames: []string{"repo", "repos"}}},
		{"no args", map[string]any{"server": "ci.example.com"}, engine.MCPCall{Server: "ci.example.com", Tool: "search"}},
	} {
		d := c.Check(context.Background(), wire.Request{Action: wire.UID("Action", "McpCall"), Resource: wire.UID("MCP::Tool", "search"), Context: tc.ctx})
		want := proxy.DecideMCPCall(tc.call)
		if d.Err != nil || d.Allowed() != want.Allow || d.Reason != want.Reason {
			t.Errorf("McpCall %s: socket=%v/%s (%v) proxy=%+v", tc.name, d.Allowed(), d.Reason, d.Err, want)
		}
	}
	if d := c.Check(context.Background(), wire.Request{Action: wire.UID("Action", "McpCall"), Resource: wire.UID("MCP::Tool", "search"),
		Context: map[string]any{"server": "ci.example.com", "args": map[string]any{"repo": "github.com/o/r"}, "argNames": []string{"query"}}}); d.Allowed() || d.Reason != wire.ReasonInvalidRequest {
		t.Errorf("args outside argNames must be an invalid request: %+v", d.Response)
	}
	for _, host := range []string{"api.example.com", "evil.example.com"} {
		d := c.Check(context.Background(), wire.Request{Action: wire.UID("Action", "NetworkConnect"), Resource: wire.UID("Host", host), Context: map[string]any{"port": 443}})
		if want := proxy.CheckConnect(host, "", 443); d.Allowed() != want {
			t.Errorf("NetworkConnect %s: socket=%v proxy=%v", host, d.Allowed(), want)
		}
	}
}

func rawExchange(t *testing.T, socket string, lines ...string) []wire.Response {
	t.Helper()
	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	rd := bufio.NewReader(conn)
	var out []wire.Response
	for _, l := range lines {
		if _, err := conn.Write([]byte(l + "\n")); err != nil {
			t.Fatal(err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		raw, err := rd.ReadBytes('\n')
		if err != nil {
			t.Fatalf("read reply to %q: %v", l, err)
		}
		var resp wire.Response
		if err := json.Unmarshal(raw, &resp); err != nil {
			t.Fatal(err)
		}
		out = append(out, resp)
	}
	return out
}

func TestServerProtocolErrorsFailClosed(t *testing.T) {
	ts := startServer(t, secretbroker(), nil)
	publish(t, ts.decisions, `permit (principal, action == Secret::Action::"Read", resource);`)
	resps := rawExchange(t, ts.socket,
		`{not json`,
		`{"v":2,"id":"a","action":{"type":"Secret::Action","id":"Read"},"resource":{"type":"Secret::Item","id":"x"}}`,
		`{"v":1,"id":"b","action":{"type":"Secret::Action","id":""},"resource":{"type":"Secret::Item","id":"x"}}`,
		`{"v":1,"id":"c","action":{"type":"Secret::Action","id":"Read"},"resource":{"type":"Secret::Item","id":"x"},"context":{"n":null}}`,
		`{"v":1,"id":"d","action":{"type":"Secret::Action","id":"Read"},"resource":{"type":"Secret::Item","id":"x"},"unknown":true}`,
	)
	want := []struct {
		decision, reason string
	}{
		{"deny", wire.ReasonInvalidRequest},
		{"deny", wire.ReasonUnsupportedVersion},
		{"deny", wire.ReasonInvalidRequest},
		{"deny", wire.ReasonInvalidRequest},
		{"allow", wire.ReasonMatchedPermit}, // unknown fields are ignored
	}
	for i, w := range want {
		if resps[i].Decision != w.decision || resps[i].Reason != w.reason || resps[i].V != wire.ProtocolVersion {
			t.Errorf("line %d: got %+v, want %s/%s", i, resps[i], w.decision, w.reason)
		}
	}

	// An oversized line is answered with a deny and the connection closed.
	conn, err := net.Dial("unix", ts.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	big := `{"v":1,"id":"` + strings.Repeat("x", wire.MaxLineBytes) + "\"}\n"
	go conn.Write([]byte(big))
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	raw, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	var resp wire.Response
	_ = json.Unmarshal(raw, &resp)
	if resp.Decision != "deny" || resp.Reason != wire.ReasonInvalidRequest {
		t.Fatalf("oversized line: %+v", resp)
	}
}

// A policy with an unconstrained action applies to Leash's built-in actions
// only: it never answers a plugin's question. Built-in actions need the
// explicit Action grant.
func TestServerNamespaceRule(t *testing.T) {
	ts := startServer(t, secretbroker(), nil)
	publish(t, ts.decisions, `@leash_semantics("cedar")
permit (principal, action, resource);`)
	c := wire.New(ts.socket)
	defer c.Close()
	if d := c.Check(context.Background(), read("x")); d.Allowed() || d.Reason != wire.ReasonDefaultDeny {
		t.Fatalf("an unconstrained permit must not grant plugin actions: %+v", d)
	}
	if d := c.Check(context.Background(), wire.Request{Action: wire.UID("Action", "NetworkConnect"), Resource: wire.UID("Host", "x.org")}); d.Allowed() || d.Reason != wire.ReasonNamespaceNotGranted {
		t.Fatalf("built-in query without the Action grant: %+v", d)
	}
}

func TestServerRateLimit(t *testing.T) {
	now := time.Unix(1000, 0)
	ts := startServer(t, secretbroker(), func(c *Config) { c.Now = func() time.Time { return now } })
	publish(t, ts.decisions, `permit (principal, action == Secret::Action::"Read", resource);`)
	c := wire.New(ts.socket)
	defer c.Close()
	limited := 0
	for i := 0; i < RateBurst+10; i++ {
		if d := c.Check(context.Background(), read("x")); d.Reason == wire.ReasonRateLimited {
			limited++
			if d.Allowed() {
				t.Fatal("rate-limited request allowed")
			}
		}
	}
	if limited != 10 {
		t.Fatalf("rate limited %d requests, want 10", limited)
	}
}

func TestServerRejectsOtherUIDsAndTheWorkload(t *testing.T) {
	origChown := chownSocket
	chownSocket = func(string, int) error { return nil }
	t.Cleanup(func() { chownSocket = origChown })
	ts := startServer(t, PluginGrant{ID: "p", Namespaces: []string{"Secret"}, UID: os.Getuid() + 4242}, nil)
	publish(t, ts.decisions, `permit (principal, action == Secret::Action::"Read", resource);`)
	if os.Getuid() == 0 {
		t.Skip("root peers are always accepted")
	}
	if d := wire.New(ts.socket).Check(context.Background(), read("x")); d.Allowed() || d.Err == nil {
		t.Fatalf("foreign-uid peer got %+v", d)
	}

	// Workload exclusion: a peer whose cgroup is inside the box is refused.
	var cgroup atomic.Value
	cgroup.Store("0::/leash/box/sub\n")
	ts2 := startServer(t, secretbroker(), func(c *Config) {
		c.BoxCgroup = "/sys/fs/cgroup/leash/box"
		c.ProcCgroup = func(int) ([]byte, error) { return []byte(cgroup.Load().(string)), nil }
	})
	publish(t, ts2.decisions, `permit (principal, action == Secret::Action::"Read", resource);`)
	if d := wire.New(ts2.socket).Check(context.Background(), read("x")); d.Allowed() {
		t.Fatal("workload peer was answered")
	}
	cgroup.Store("0::/user.slice/plugin\n")
	if d := wire.New(ts2.socket).Check(context.Background(), read("x")); !d.Allowed() {
		t.Fatalf("plugin peer outside the box refused: %+v", d)
	}
	logData, _ := os.ReadFile(ts2.logPath)
	if !strings.Contains(string(logData), "reason=peer_rejected") {
		t.Fatal("peer rejection not audited")
	}
}

func TestPidInCgroup(t *testing.T) {
	for content, want := range map[string]bool{
		"0::/leash/box\n":         true,
		"0::/leash/box/nested\n":  true,
		"0::/leash/boxer\n":       false,
		"1:name=x:/\n0::/other\n": false,
	} {
		read := func(int) ([]byte, error) { return []byte(content), nil }
		got, err := pidInCgroup(read, 1, "/sys/fs/cgroup/leash/box")
		if err != nil || got != want {
			t.Errorf("%q: got %v, %v want %v", content, got, err, want)
		}
	}
	gone := func(int) ([]byte, error) { return nil, errors.New("gone") }
	if _, err := pidInCgroup(gone, 1, "/sys/fs/cgroup/leash/box"); err == nil {
		t.Error("unreadable /proc must be an error (fail closed)")
	}
}

func TestParseGrants(t *testing.T) {
	good := `[{"id":"secretbroker","socket":"/tmp/a/authz.sock","uid":1000,"namespaces":["Secret","Walk::Secret"]}]`
	if g, err := ParseGrants(good); err != nil || len(g) != 1 {
		t.Fatalf("good grants: %v %v", g, err)
	}
	for _, bad := range []string{
		`not json`,
		`[{"id":"","socket":"/tmp/a.sock","uid":1,"namespaces":["Secret"]}]`,
		`[{"id":"a","socket":"rel.sock","uid":1,"namespaces":["Secret"]}]`,
		`[{"id":"a","socket":"/tmp/a.sock","uid":1,"namespaces":[]}]`,
		`[{"id":"a","socket":"/tmp/a.sock","uid":1,"namespaces":["Bad-NS"]}]`,
		`[{"id":"a","socket":"/tmp/a.sock","uid":1,"namespaces":["S"]},{"id":"a","socket":"/tmp/b.sock","uid":1,"namespaces":["S"]}]`,
	} {
		if _, err := ParseGrants(bad); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestClientFailsClosed(t *testing.T) {
	dir := shortTempDir(t)
	// No server.
	c := wire.New(filepath.Join(dir, "missing.sock"), wire.WithTimeout(200*time.Millisecond))
	if d := c.Check(context.Background(), read("x")); d.Allowed() || d.Err == nil || d.Decision != wire.DecisionDeny {
		t.Fatalf("no server: %+v", d)
	}
	// A server that answers garbage, a wrong id, an unknown decision, or nothing.
	for name, reply := range map[string]string{
		"garbage":          "nope\n",
		"wrong id":         `{"v":1,"id":"other","decision":"allow"}` + "\n",
		"unknown decision": `{"v":1,"id":"1","decision":"maybe"}` + "\n",
		"wrong version":    `{"v":9,"id":"1","decision":"allow"}` + "\n",
		"silent":           "",
	} {
		sock := filepath.Join(dir, strings.ReplaceAll(name, " ", "")+".sock")
		ln, err := net.Listen("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		go func(ln net.Listener, reply string) {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			_, _ = bufio.NewReader(conn).ReadBytes('\n')
			if reply != "" {
				_, _ = conn.Write([]byte(reply))
			}
			time.Sleep(time.Second)
		}(ln, reply)
		d := wire.New(sock, wire.WithTimeout(300*time.Millisecond)).Check(context.Background(), read("x"))
		if d.Allowed() || d.Err == nil {
			t.Errorf("%s: %+v", name, d)
		}
		ln.Close()
	}
	if _, err := wire.NewFromEnv(); err == nil && os.Getenv(wire.EnvSocket) == "" {
		t.Error("NewFromEnv without the env var must fail")
	}
}

// Integration: a separate plugin process (this test binary re-executed)
// queries the socket through pkg/authz, the way a real plugin does.
const fakePluginEnv = "LEASH_AUTHZ_TEST_FAKE_PLUGIN"

func TestMain(m *testing.M) {
	if os.Getenv(fakePluginEnv) == "1" {
		os.Exit(runFakePlugin())
	}
	os.Exit(m.Run())
}

func runFakePlugin() int {
	c, err := wire.NewFromEnv()
	if err != nil {
		os.Stderr.WriteString(err.Error())
		return 2
	}
	defer c.Close()
	enc := json.NewEncoder(os.Stdout)
	for _, id := range []string{"gemini", "ssh", "aws"} {
		d := c.Check(context.Background(), read(id))
		errText := ""
		if d.Err != nil {
			errText = d.Err.Error()
		}
		_ = enc.Encode(map[string]any{"id": id, "allowed": d.Allowed(), "reason": d.Reason, "principal": d.Principal.String(), "err": errText})
	}
	return 0
}

func TestFakePluginProcessIntegration(t *testing.T) {
	ts := startServer(t, secretbroker(), nil)
	publish(t, ts.decisions, testPolicy)

	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), fakePluginEnv+"=1", wire.EnvSocket+"="+ts.socket, wire.EnvPluginID+"=secretbroker")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("fake plugin: %v", err)
	}
	want := map[string]struct {
		allowed bool
		reason  string
	}{
		"gemini": {true, wire.ReasonMatchedPermit},
		"ssh":    {false, wire.ReasonMatchedForbid},
		"aws":    {false, wire.ReasonDefaultDeny},
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) != len(want) {
		t.Fatalf("fake plugin output:\n%s", out)
	}
	for _, line := range lines {
		var got struct {
			ID, Reason, Principal, Err string
			Allowed                    bool
		}
		if err := json.Unmarshal([]byte(line), &got); err != nil {
			t.Fatal(err)
		}
		w := want[got.ID]
		if got.Allowed != w.allowed || got.Reason != w.reason || got.Err != "" || got.Principal != `Plugin::"secretbroker"` {
			t.Errorf("%s: %+v, want %+v", got.ID, got, w)
		}
	}

	// After leashd goes away the plugin fails closed.
	ts.srv.Close()
	cmd = exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), fakePluginEnv+"=1", wire.EnvSocket+"="+ts.socket)
	out, err = cmd.Output()
	if err != nil {
		t.Fatalf("fake plugin after close: %v", err)
	}
	if strings.Contains(string(out), `"allowed":true`) {
		t.Fatalf("plugin allowed with leashd gone:\n%s", out)
	}
}
