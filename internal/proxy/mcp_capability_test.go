package proxy

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/strongdm/leash/internal/engine"
)

// The policy shape Walk generates for a repo-pinned, retrieval-only
// code-indexer MCP endpoint (#113), with the endpoint at example.com (the
// test origin's certificate name). NetworkConnect is open so only the MCP
// decision is under test.
const pinnedCapabilityPolicy = `
@id("walk-code-indexer-retrieval")
permit (principal, action == Action::"McpCall", resource)
when {
  resource in MCP::Server::"example.com" &&
  resource in [MCP::Tool::"search", MCP::Tool::"bundle"] &&
  context has args && context.args has repo && context.args.repo == "github.com/o/r" &&
  context has argNames && ["repo", "query", "limit"].containsAll(context.argNames)
};
@id("walk-code-indexer-only")
forbid (principal, action == Action::"McpCall", resource)
unless {
  resource in MCP::Server::"example.com" &&
  resource in [MCP::Tool::"search", MCP::Tool::"bundle"] &&
  context has args && context.args has repo && context.args.repo == "github.com/o/r" &&
  context has argNames && ["repo", "query", "limit"].containsAll(context.argNames)
};
permit (principal, action == Action::"NetworkConnect", resource);
`

func mustTestEngine(t *testing.T, text string) *engine.Engine {
	t.Helper()
	e, err := engine.NewFromText("p.cedar", text)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

type capabilityCase struct {
	name  string
	path  string
	body  string
	allow bool
	// why is a substring of the denial message.
	why string
}

func call(tool, args string) string {
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":"1","method":"tools/call","params":{"name":%q,"arguments":%s}}`, tool, args)
}

var capabilityCases = []capabilityCase{
	{name: "pinned search", body: call("search", `{"repo":"github.com/o/r","query":"auth","limit":5}`), allow: true},
	{name: "pinned bundle", body: call("bundle", `{"repo":"github.com/o/r"}`), allow: true},
	{name: "discovery is not a call", body: `{"jsonrpc":"2.0","id":"1","method":"tools/list"}`, allow: true},
	{name: "initialize", body: `{"jsonrpc":"2.0","id":"1","method":"initialize","params":{}}`, allow: true},
	// Legacy HTTP+SSE transport: requests are POSTed to the message endpoint.
	{name: "legacy SSE message endpoint", path: "/messages?sessionId=abc", body: call("search", `{"repo":"github.com/o/r"}`), allow: true},
	{name: "legacy SSE message endpoint, mutation", path: "/messages?sessionId=abc", body: call("index", `{"repo":"github.com/o/r"}`), why: "denied by policy"},

	{name: "other repository", body: call("search", `{"repo":"github.com/o/other"}`), why: "walk-code-indexer-only"},
	{name: "repository missing", body: call("search", `{"query":"x"}`), why: "denied by policy"},
	{name: "no arguments", body: `{"jsonrpc":"2.0","id":"1","method":"tools/call","params":{"name":"search"}}`, why: "denied by policy"},
	{name: "repository not a string", body: call("search", `{"repo":["github.com/o/r","github.com/o/other"]}`), why: "denied by policy"},
	{name: "extra scope argument", body: call("search", `{"repo":"github.com/o/r","repos":["github.com/o/other"]}`), why: "denied by policy"},
	{name: "mutation tool", body: call("index", `{"repo":"github.com/o/r"}`), why: "denied by policy"},
	{name: "configuration tool", body: call("config_set", `{"repo":"github.com/o/r"}`), why: "denied by policy"},
	{name: "duplicate repository key", body: call("search", `{"repo":"github.com/o/r","repo":"github.com/o/other"}`), why: "duplicate object key"},
	{name: "duplicate tool name", body: `{"jsonrpc":"2.0","id":"1","method":"tools/call","params":{"name":"search","name":"index","arguments":{"repo":"github.com/o/r"}}}`, why: "duplicate object key"},
	{name: "batch smuggling a mutation", body: "[" + call("search", `{"repo":"github.com/o/r"}`) + "," + call("index", `{"repo":"github.com/o/r"}`) + "]", why: "denied by policy"},
	{name: "invalid JSON", body: `{"jsonrpc":"2.0","id":"1","method":"tools/call","params":{"name":"index","arguments":{"n":NaN}}}`, why: "not valid JSON"},
}

func capabilityRequest(t *testing.T, tc capabilityCase) *http.Request {
	t.Helper()
	path := tc.path
	if path == "" {
		path = "/mcp"
	}
	req, err := http.NewRequest(http.MethodPost, "https://example.com"+path, strings.NewReader(tc.body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	return req
}

// recordingOrigin answers every request and records the bodies it saw.
type recordingOrigin struct {
	mu     sync.Mutex
	bodies []string
}

func (o *recordingOrigin) handler(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	o.mu.Lock()
	o.bodies = append(o.bodies, string(b))
	o.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":"1","result":{}}`)
}

func (o *recordingOrigin) seen() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.bodies...)
}

// The pinned capability over HTTPS, for HTTP/1.1 and h2 clients: only the
// pinned retrieval calls reach the origin; every other call is answered with
// a JSON-RPC denial naming the reason, and audited.
func TestPinnedCapabilityOverHTTPS(t *testing.T) {
	for _, proto := range []string{"h2", "http/1.1"} {
		t.Run(proto, func(t *testing.T) {
			origin := &recordingOrigin{}
			f := newH2Fixture(t, true, origin.handler, func(p *MITMProxy) {
				p.SetEngine(mustTestEngine(t, pinnedCapabilityPolicy))
			})
			client := f.client
			if proto == "http/1.1" {
				tr := f.client.Transport.(*http.Transport).Clone()
				tr.ForceAttemptHTTP2 = false
				tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}} //nolint:gosec
				t.Cleanup(tr.CloseIdleConnections)
				client = &http.Client{Transport: tr, Timeout: 10 * time.Second}
			}
			wantProto := map[string]string{"h2": "HTTP/2.0", "http/1.1": "HTTP/1.1"}[proto]
			var forwarded []string
			for _, tc := range capabilityCases {
				resp, err := client.Do(capabilityRequest(t, tc))
				if err != nil {
					t.Fatalf("%s: %v", tc.name, err)
				}
				out := readAllClose(t, resp)
				if resp.Proto != wantProto {
					t.Fatalf("%s: proto %s", tc.name, resp.Proto)
				}
				if tc.allow {
					if resp.StatusCode != http.StatusOK {
						t.Errorf("%s: want forwarded, got %d %q", tc.name, resp.StatusCode, out)
					}
					forwarded = append(forwarded, tc.body)
					continue
				}
				if resp.StatusCode != http.StatusForbidden || !strings.Contains(out, `"error"`) || !strings.Contains(out, tc.why) {
					t.Errorf("%s: want 403 JSON-RPC denial containing %q, got %d %q", tc.name, tc.why, resp.StatusCode, out)
				}
			}
			if got := origin.seen(); strings.Join(got, "\n") != strings.Join(forwarded, "\n") {
				t.Fatalf("origin saw\n%s\nwant only the allowed calls\n%s", strings.Join(got, "\n"), strings.Join(forwarded, "\n"))
			}
			denied := waitForEntry(t, f.capture, `tool="index"`)
			if !strings.Contains(denied, "decision=denied") || !strings.Contains(denied, `policies="walk-code-indexer-only"`) || !strings.Contains(denied, `arg_names="repo"`) {
				t.Fatalf("denial audit: %s", denied)
			}
			if strings.Contains(strings.Join(f.capture.all(), "\n"), "auth\"") {
				t.Fatal("audit log leaked an argument value")
			}
			allowed := waitForEntry(t, f.capture, `tool="bundle"`)
			if !strings.Contains(allowed, "decision=allowed") || !strings.Contains(allowed, `policies="walk-code-indexer-retrieval"`) {
				t.Fatalf("grant audit: %s", allowed)
			}
		})
	}
}

// A second, undeclared MCP server is unreachable: every tools/call to it is
// denied, whatever the tool and arguments (plain HTTP path).
func TestPinnedCapabilityDeniesOtherServersOverHTTP(t *testing.T) {
	e := mustTestEngine(t, pinnedCapabilityPolicy)
	for _, tc := range []struct {
		host  string
		body  string
		allow bool
	}{
		{"example.com", call("search", `{"repo":"github.com/o/r"}`), true},
		{"example.com", call("index", `{"repo":"github.com/o/r"}`), false},
		{"mcp.other.test", call("search", `{"repo":"github.com/o/r"}`), false},
		{"example.com.other.test", call("search", `{"repo":"github.com/o/r"}`), false},
	} {
		status, forwarded := plainHTTPExchange(t, e, tc.host, tc.body, "application/json")
		if forwarded != tc.allow || (tc.allow && status != 200) || (!tc.allow && status != 403) {
			t.Errorf("%s %s: status %d forwarded=%v, want allow=%v", tc.host, tc.body, status, forwarded, tc.allow)
		}
	}
}

// Fail-closed only while MCP policies are active: with an unconditional
// MCP permit the proxy forwards bodies it cannot parse, as before.
func TestMalformedBodiesAreDeniedOnlyWhenMCPIsGoverned(t *testing.T) {
	bad := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"x","name":"y"}}`
	governed := mustTestEngine(t, pinnedCapabilityPolicy)
	if status, forwarded := plainHTTPExchange(t, governed, "example.com", bad, "application/json"); forwarded || status != 403 {
		t.Errorf("governed: status %d forwarded=%v", status, forwarded)
	}
	open := mustTestEngine(t, `permit (principal, action, resource);`)
	if status, forwarded := plainHTTPExchange(t, open, "example.com", bad, "application/json"); !forwarded || status != 200 {
		t.Errorf("ungoverned: status %d forwarded=%v", status, forwarded)
	}
	// Non-JSON content is not MCP (MCP requests are application/json).
	if status, forwarded := plainHTTPExchange(t, governed, "example.com", "not json", "text/plain"); !forwarded || status != 200 {
		t.Errorf("non-JSON body: status %d forwarded=%v", status, forwarded)
	}
}

// A body larger than the read-ahead cannot be checked: denied while
// governed. The limit is lowered for the test.
func TestOversizedJSONBodyIsDeniedWhenGoverned(t *testing.T) {
	o := newMCPObserver(MCPConfig{SniffLimit: 64}, nil)
	o.setForceParse(true)
	pad := strings.Repeat("x", 128)
	req, _ := http.NewRequest(http.MethodPost, "http://example.com/mcp", strings.NewReader(`{"pad":"`+pad+`","jsonrpc":"2.0","method":"tools/call","params":{"name":"index"}}`))
	req.Header.Set("Content-Type", "application/json")
	defer func(old int64) { governedMCPBodyLimit = old }(governedMCPBodyLimit)
	governedMCPBodyLimit = 64
	ctx, err := o.inspectHTTPRequest(req, "example.com")
	if err != nil || ctx == nil || !strings.Contains(ctx.malformed, "larger than 64 bytes") {
		t.Fatalf("ctx=%+v err=%v", ctx, err)
	}
	// The body is restored for forwarding either way.
	if b, _ := io.ReadAll(req.Body); !strings.Contains(string(b), pad) {
		t.Fatal("body not restored")
	}
	o.setForceParse(false)
	req, _ = http.NewRequest(http.MethodPost, "http://example.com/mcp", strings.NewReader(`{"pad":"`+pad+`"}`))
	req.Header.Set("Content-Type", "application/json")
	if ctx, _ := o.inspectHTTPRequest(req, "example.com"); ctx != nil {
		t.Fatalf("ungoverned oversized body must pass unobserved: %+v", ctx)
	}
}

// plainHTTPExchange sends one POST through handleTransparentHTTP and
// reports the response status and whether it was forwarded upstream.
func plainHTTPExchange(t *testing.T, e *engine.Engine, host, body, contentType string) (int, bool) {
	t.Helper()
	var mu sync.Mutex
	forwarded := false
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		_, _ = io.ReadAll(req.Body)
		mu.Lock()
		forwarded = true
		mu.Unlock()
		return &http.Response{StatusCode: 200, Status: "200 OK", Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
			Body: io.NopCloser(strings.NewReader("{}")), ContentLength: 2, Header: http.Header{"Content-Length": []string{"2"}}, Request: req}, nil
	})
	p := &MITMProxy{
		certCache:      make(map[string]*tls.Certificate),
		headerRewriter: NewHeaderRewriter(),
		httpClient:     &http.Client{Transport: transport},
		mcpObserver:    newMCPObserver(MCPConfig{}, nil),
	}
	p.SetEngine(e)
	raw := fmt.Sprintf("POST /mcp HTTP/1.1\r\nHost: %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n%s", host, contentType, len(body), body)
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() { _ = serverConn.Close() }()
		p.handleTransparentHTTP(serverConn, host+":80", nil)
	}()
	go func() { _, _ = clientConn.Write([]byte(raw)) }()
	_ = clientConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp, err := io.ReadAll(clientConn)
	if err != nil && !isTimeout(err) {
		t.Fatalf("read: %v", err)
	}
	<-done
	status := 0
	_, _ = fmt.Sscanf(string(resp), "HTTP/1.1 %d", &status)
	mu.Lock()
	defer mu.Unlock()
	return status, forwarded
}

func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}
