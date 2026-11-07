package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/strongdm/leash/internal/engine"
)

func TestLoadH2Mode(t *testing.T) {
	for raw, want := range map[string]string{
		"":           h2ModeInspect,
		"inspect":    h2ModeInspect,
		" Inspect ":  h2ModeInspect,
		"downgrade":  h2ModeDowngrade,
		"DOWNGRADE":  h2ModeDowngrade,
		"bogus-mode": h2ModeInspect,
	} {
		t.Setenv(h2ModeEnv, raw)
		if got := loadH2Mode(); got != want {
			t.Errorf("%s=%q: got %q, want %q", h2ModeEnv, raw, got, want)
		}
	}
}

func TestChooseALPNInspectMode(t *testing.T) {
	rewriter := NewHeaderRewriter()
	rewriter.SetRules([]HeaderRewriteRule{{Host: "rewrite.example.com", Header: "X-A", Value: "v"}})
	p := &MITMProxy{headerRewriter: rewriter} // zero h2Mode == inspect
	both := []string{"h2", "http/1.1"}

	for _, tc := range []struct {
		host     string
		offered  []string
		wantNext []string
		wantMode string
	}{
		{"rewrite.example.com", both, both, alpnModeInspect},
		{"rewrite.example.com", []string{"h2"}, both, alpnModeInspect}, // h2-only clients are inspected, not refused
		{"plain.example.com", both, both, alpnModeTunnel},
		{"rewrite.example.com", []string{"http/1.1"}, both, alpnModeTunnel},
	} {
		d := p.chooseALPN(tc.host, tc.offered)
		if !reflect.DeepEqual(d.nextProto, tc.wantNext) || d.mode != tc.wantMode {
			t.Errorf("chooseALPN(%s, %v) = %v/%s, want %v/%s", tc.host, tc.offered, d.nextProto, d.mode, tc.wantNext, tc.wantMode)
		}
	}
}

// h2Fixture wires an h2-preferring client to a leash MITM (inspect mode) in
// front of a test origin, with logs captured.
type h2Fixture struct {
	origin  *h2TestOrigin
	proxy   *MITMProxy
	client  *http.Client
	capture *capturingBroadcaster

	dialMu sync.Mutex
	dialed []string // upstream addresses the proxy dialed
}

func (f *h2Fixture) dialedAddrs() []string {
	f.dialMu.Lock()
	defer f.dialMu.Unlock()
	return append([]string(nil), f.dialed...)
}

func newH2Fixture(t *testing.T, originH2 bool, handler http.HandlerFunc, configure func(*MITMProxy)) *h2Fixture {
	t.Helper()
	origin := newH2TestOrigin(t, originH2, handler)
	p := newTestMITM(t)
	logger, _, capture := newMCPTestLogger(t)
	p.sharedLogger = logger
	p.headerRewriter.SetSharedLogger(logger)
	p.mcpObserver = newMCPObserver(MCPConfig{Mode: MCPModeBasic}, logger)
	if configure != nil {
		configure(p)
	}
	proxyAddr := startTestMITM(t, p, origin)
	f := &h2Fixture{origin: origin, proxy: p, client: h2PreferringClient(t, proxyAddr), capture: capture}
	// Record the address each upstream dial asked for, then reach the origin.
	p.upstreamDialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		f.dialMu.Lock()
		f.dialed = append(f.dialed, addr)
		f.dialMu.Unlock()
		var d net.Dialer
		return d.DialContext(ctx, network, origin.addr())
	}
	return f
}

func readAllClose(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(b)
}

func waitForEntry(t *testing.T, capture *capturingBroadcaster, substr string) string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if got := entriesWith(capture, substr); len(got) > 0 {
			return got[0]
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no log entry containing %q; have %v", substr, capture.all())
	return ""
}

func TestH2MITMAppliesHeaderRewrite(t *testing.T) {
	f := newH2Fixture(t, true, nil, func(p *MITMProxy) {
		p.headerRewriter.SetRules([]HeaderRewriteRule{{Host: "example.com", Header: "X-Injected", Value: "rewritten"}})
	})

	resp, err := f.client.Get("https://example.com/rewrite?q=1")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	readAllClose(t, resp)
	if resp.Proto != "HTTP/2.0" || resp.StatusCode != http.StatusOK {
		t.Fatalf("client got %s %d, want HTTP/2.0 200", resp.Proto, resp.StatusCode)
	}
	recs := f.origin.records()
	if len(recs) != 1 || recs[0].proto != "HTTP/2.0" || recs[0].injected != "rewritten" {
		t.Fatalf("origin should see an h2 request with the rewritten header: %+v", recs)
	}
	waitForEntry(t, f.capture, "event=http.rewrite")
	alpn := waitForEntry(t, f.capture, "event=http.alpn")
	if !strings.Contains(alpn, "alpn_mode=inspect") || !strings.Contains(alpn, `alpn_negotiated="h2"`) {
		t.Fatalf("unexpected alpn log: %s", alpn)
	}
	req := waitForEntry(t, f.capture, "event=http.request")
	if !strings.Contains(req, `path="/rewrite?q=1"`) || !strings.Contains(req, "status=200") || !strings.Contains(req, "decision=allowed") {
		t.Fatalf("unexpected request log: %s", req)
	}
}

func TestH2MITMFallsBackToHTTP11Origin(t *testing.T) {
	f := newH2Fixture(t, false, nil, func(p *MITMProxy) {
		p.headerRewriter.SetRules([]HeaderRewriteRule{{Host: "example.com", Header: "X-Injected", Value: "rewritten"}})
	})
	for i := 0; i < 3; i++ {
		resp, err := f.client.Get(fmt.Sprintf("https://example.com/h1/%d", i))
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		readAllClose(t, resp)
		if resp.Proto != "HTTP/2.0" {
			t.Fatalf("client side should stay h2, got %s", resp.Proto)
		}
	}
	for _, rec := range f.origin.records() {
		if rec.proto != "HTTP/1.1" || rec.injected != "rewritten" {
			t.Fatalf("http/1.1-only origin should get rewritten HTTP/1.1 requests: %+v", rec)
		}
	}
}

func TestH2MITMDeniesMCPToolsCall(t *testing.T) {
	f := newH2Fixture(t, true, nil, func(p *MITMProxy) {
		p.SetPolicyChecker(toolOnlyPolicyChecker{tool: "shell"})
	})

	var conns int32
	trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
		if !info.Reused {
			atomic.AddInt32(&conns, 1)
		}
	}}
	do := func(req *http.Request) *http.Response {
		t.Helper()
		resp, err := f.client.Do(req.WithContext(httptrace.WithClientTrace(req.Context(), trace)))
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		return resp
	}

	for _, accept := range []string{"application/json", "application/json, text/event-stream"} {
		body := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"shell"}}`
		req, _ := http.NewRequest(http.MethodPost, "https://example.com/mcp", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", accept)
		resp := do(req)
		out := readAllClose(t, resp)
		if resp.Proto != "HTTP/2.0" || resp.StatusCode != http.StatusForbidden ||
			!strings.Contains(out, `"id":"7"`) || !strings.Contains(out, "denied by policy") {
			t.Fatalf("accept %q: want h2 403 JSON-RPC denial, got %s %d %q", accept, resp.Proto, resp.StatusCode, out)
		}
		if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
			t.Fatalf("denial content-type = %q", ct)
		}
	}
	if n := len(f.origin.records()); n != 0 {
		t.Fatalf("denied tools/call reached the origin (%d requests)", n)
	}
	mcp := waitForEntry(t, f.capture, "event=mcp.call")
	if !strings.Contains(mcp, `tool="shell"`) || !strings.Contains(mcp, "decision=denied") {
		t.Fatalf("unexpected mcp log: %s", mcp)
	}

	// The denial is per stream: the same h2 connection keeps serving.
	resp := do(mustRequest(t, http.MethodGet, "https://example.com/after-deny"))
	readAllClose(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("request after denial: %d", resp.StatusCode)
	}
	if got := atomic.LoadInt32(&conns); got != 1 {
		t.Fatalf("expected one client connection for all streams, got %d", got)
	}
}

func mustRequest(t *testing.T, method, url string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	return req
}

// An allowed tools/call answered with an SSE stream is observed while it
// streams: the client receives the event before the origin ends the stream,
// and the MCP call is logged from the SSE payload.
func TestH2MITMObservesAllowedToolsCallOverSSE(t *testing.T) {
	release := make(chan struct{})
	f := newH2Fixture(t, true, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":\"9\",\"error\":{\"code\":1,\"message\":\"boom\"}}\n\n")
		w.(http.Flusher).Flush()
		<-release
	}, func(p *MITMProxy) {
		p.SetPolicyChecker(toolOnlyPolicyChecker{tool: "shell"})
		p.mcpObserver = newMCPObserver(MCPConfig{Mode: MCPModeEnhanced}, p.sharedLogger)
	})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()

	body := `{"jsonrpc":"2.0","id":"9","method":"tools/call","params":{"name":"search"}}`
	req, _ := http.NewRequest(http.MethodPost, "https://example.com/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "1.1")
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.Proto != "HTTP/2.0" || resp.StatusCode != http.StatusOK {
		t.Fatalf("got %s %d", resp.Proto, resp.StatusCode)
	}
	lineCh := make(chan string, 1)
	go func() {
		br := bufio.NewReader(resp.Body)
		for {
			line, err := br.ReadString('\n')
			if strings.HasPrefix(line, "data:") || err != nil {
				lineCh <- line
				return
			}
		}
	}()
	select {
	case line := <-lineCh:
		if !strings.Contains(line, `"id":"9"`) {
			t.Fatalf("unexpected SSE line %q", line)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("SSE event was not streamed to the client while the origin held the stream open")
	}
	close(release)
	_, _ = io.Copy(io.Discard, resp.Body)

	call := waitForEntry(t, f.capture, "event=mcp.call")
	if !strings.Contains(call, `tool="search"`) || !strings.Contains(call, `transport="sse"`) || !strings.Contains(call, `error="boom"`) {
		t.Fatalf("unexpected mcp.call log: %s", call)
	}
	if len(f.origin.records()) != 1 {
		t.Fatalf("allowed call should reach the origin once")
	}
}

func TestH2MITMStreamsBodiesWithoutBuffering(t *testing.T) {
	gotFirstReqChunk := make(chan struct{})
	release := make(chan struct{})
	f := newH2Fixture(t, true, func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 5)
		if _, err := io.ReadFull(r.Body, buf); err != nil || string(buf) != "first" {
			http.Error(w, "bad first chunk", http.StatusBadRequest)
			return
		}
		close(gotFirstReqChunk)
		rest, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("X-Request-Rest", string(rest))
		_, _ = io.WriteString(w, "chunk-1;")
		w.(http.Flusher).Flush()
		<-release
		_, _ = io.WriteString(w, "chunk-2")
	}, nil)

	pr, pw := io.Pipe()
	req, _ := http.NewRequest(http.MethodPost, "https://example.com/stream", pr)
	req.Header.Set("Content-Type", "application/octet-stream")
	respCh := make(chan *http.Response, 1)
	errCh := make(chan error, 1)
	go func() {
		resp, err := f.client.Do(req)
		if err != nil {
			errCh <- err
			return
		}
		respCh <- resp
	}()
	if _, err := pw.Write([]byte("first")); err != nil {
		t.Fatalf("write first chunk: %v", err)
	}
	select {
	case <-gotFirstReqChunk:
	case err := <-errCh:
		t.Fatalf("request: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("origin did not receive the first request chunk before the body ended (request buffered)")
	}
	_, _ = pw.Write([]byte("-second"))
	_ = pw.Close()

	var resp *http.Response
	select {
	case resp = <-respCh:
	case err := <-errCh:
		t.Fatalf("request: %v", err)
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("response headers not received")
	}
	defer resp.Body.Close()
	if got := resp.Header.Get("X-Request-Rest"); got != "-second" {
		t.Fatalf("origin saw request rest %q", got)
	}
	first := make([]byte, len("chunk-1;"))
	readDone := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(resp.Body, first)
		readDone <- err
	}()
	select {
	case err := <-readDone:
		if err != nil || string(first) != "chunk-1;" {
			t.Fatalf("first response chunk: %q %v", first, err)
		}
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("first response chunk not streamed before the origin finished (response buffered)")
	}
	close(release)
	rest, _ := io.ReadAll(resp.Body)
	if string(rest) != "chunk-2" {
		t.Fatalf("rest of response %q", rest)
	}
}

func TestH2MITMLargeBodiesAndTrailers(t *testing.T) {
	const size = 8 << 20 // well past the default h2 flow-control windows
	f := newH2Fixture(t, true, func(w http.ResponseWriter, r *http.Request) {
		h := sha256.New()
		n, _ := io.Copy(h, r.Body)
		w.Header().Set("Trailer", "X-Upload-Sum")
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = io.Copy(w, io.LimitReader(repeatReader('z'), size))
		w.Header().Set("X-Upload-Sum", fmt.Sprintf("%d:%x", n, h.Sum(nil)))
		// An undeclared trailer, as gRPC servers send.
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
	}, func(p *MITMProxy) {
		p.headerRewriter.SetRules([]HeaderRewriteRule{{Host: "example.com", Header: "X-Injected", Value: "v"}})
	})

	upload := bytes.Repeat([]byte("a"), size)
	req, _ := http.NewRequest(http.MethodPut, "https://example.com/big", bytes.NewReader(upload))
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	h := sha256.New()
	n, err := io.Copy(h, resp.Body)
	resp.Body.Close()
	if err != nil || n != size {
		t.Fatalf("download: %d bytes, %v", n, err)
	}
	want := sha256.Sum256(upload)
	if got := resp.Trailer.Get("X-Upload-Sum"); got != fmt.Sprintf("%d:%x", size, want) {
		t.Fatalf("upload trailer = %q", got)
	}
	if got := resp.Trailer.Get("Grpc-Status"); got != "0" {
		t.Fatalf("undeclared trailer Grpc-Status = %q (trailers %v)", got, resp.Trailer)
	}
}

type repeatReader byte

func (r repeatReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(r)
	}
	return len(p), nil
}

func TestH2MITMConcurrentStreams(t *testing.T) {
	var inFlight, maxInFlight int32
	f := newH2Fixture(t, true, func(w http.ResponseWriter, r *http.Request) {
		cur := atomic.AddInt32(&inFlight, 1)
		for {
			prev := atomic.LoadInt32(&maxInFlight)
			if cur <= prev || atomic.CompareAndSwapInt32(&maxInFlight, prev, cur) {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
		atomic.AddInt32(&inFlight, -1)
		_, _ = io.WriteString(w, r.URL.Path)
	}, func(p *MITMProxy) {
		p.headerRewriter.SetRules([]HeaderRewriteRule{{Host: "example.com", Header: "X-Injected", Value: "v"}})
	})

	var newConns int32
	trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
		if !info.Reused {
			atomic.AddInt32(&newConns, 1)
		}
	}}
	// Establish the connection first so every stream shares it.
	warm := mustRequest(t, http.MethodGet, "https://example.com/warm")
	resp, err := f.client.Do(warm.WithContext(httptrace.WithClientTrace(context.Background(), trace)))
	if err != nil {
		t.Fatalf("warm: %v", err)
	}
	readAllClose(t, resp)

	const streams = 40
	var wg sync.WaitGroup
	errs := make(chan error, streams)
	for i := 0; i < streams; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			path := fmt.Sprintf("/s/%d", i)
			req, _ := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), trace), http.MethodGet, "https://example.com"+path, nil)
			resp, err := f.client.Do(req)
			if err != nil {
				errs <- err
				return
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			if string(b) != path || resp.Proto != "HTTP/2.0" {
				errs <- fmt.Errorf("stream %d: %s %q", i, resp.Proto, b)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if got := atomic.LoadInt32(&newConns); got != 1 {
		t.Fatalf("expected all streams on one client connection, got %d connections", got)
	}
	if atomic.LoadInt32(&maxInFlight) < 2 {
		t.Fatalf("streams were not concurrent at the origin (max in flight %d)", maxInFlight)
	}
	for _, rec := range f.origin.records() {
		if rec.injected != "v" {
			t.Fatalf("stream missed the rewrite: %+v", rec)
		}
	}
}

func TestH2MITMPropagatesClientCancellation(t *testing.T) {
	originCanceled := make(chan struct{})
	started := make(chan struct{})
	f := newH2Fixture(t, true, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		close(started)
		select {
		case <-r.Context().Done():
			close(originCanceled)
		case <-time.After(10 * time.Second):
		}
	}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/hang", nil)
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	<-started
	cancel()
	select {
	case <-originCanceled:
	case <-time.After(3 * time.Second):
		t.Fatal("client cancellation did not reach the origin request")
	}
}

// A stream whose :authority names another host than the connection's SNI is
// refused with 421 before any rewrite, even when a rule exists for both hosts.
func TestH2MITMRefusesMisdirectedAuthority(t *testing.T) {
	f := newH2Fixture(t, true, nil, func(p *MITMProxy) {
		p.headerRewriter.SetRules([]HeaderRewriteRule{
			{Host: "example.com", Header: "X-Injected", Value: "for-example"},
			{Host: "other.example.com", Header: "X-Injected", Value: "for-other"},
		})
	})
	req := mustRequest(t, http.MethodGet, "https://example.com/coalesced")
	req.Host = "other.example.com" // :authority differs from the SNI the connection was checked for
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	readAllClose(t, resp)
	if resp.StatusCode != http.StatusMisdirectedRequest || resp.Proto != "HTTP/2.0" {
		t.Fatalf("got %s %d, want h2 421", resp.Proto, resp.StatusCode)
	}
	if n := len(f.origin.records()); n != 0 {
		t.Fatalf("misdirected request reached the origin")
	}
	if got := entriesWith(f.capture, "event=http.rewrite"); len(got) != 0 {
		t.Fatalf("rewrite applied to a misdirected stream: %v", got)
	}
	entry := waitForEntry(t, f.capture, "event=http.misdirected")
	if !strings.Contains(entry, `host="other.example.com"`) || !strings.Contains(entry, `sni="example.com"`) || !strings.Contains(entry, "status=421") {
		t.Fatalf("unexpected misdirected log: %s", entry)
	}

	// The connection survives: a matching stream is still served and rewritten.
	resp, err = f.client.Get("https://example.com/ok")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	readAllClose(t, resp)
	if recs := f.origin.records(); resp.StatusCode != http.StatusOK || len(recs) != 1 || recs[0].injected != "for-example" {
		t.Fatalf("follow-up stream: %d %+v", resp.StatusCode, recs)
	}
}

// On a connection without a hostname SNI (bound to the destination IP), a
// :authority is accepted only if it resolves to that IP, and the rewrite
// follows the verified host.
func TestH2MITMNoSNIVerifiesAuthorityByResolution(t *testing.T) {
	f := newH2Fixture(t, true, nil, func(p *MITMProxy) {
		p.headerRewriter.SetRules([]HeaderRewriteRule{
			{Host: "good.test", Header: "X-Injected", Value: "for-good"},
			{Host: "evil.test", Header: "X-Injected", Value: "for-evil"},
		})
		p.lookupIP = func(_ context.Context, host string) ([]net.IP, error) {
			if host == "good.test" {
				return []net.IP{net.ParseIP("127.0.0.1")}, nil
			}
			return []net.IP{net.ParseIP("192.0.2.1")}, nil
		}
	})
	_, originPort, _ := net.SplitHostPort(f.origin.addr())
	base := "https://" + net.JoinHostPort("127.0.0.1", originPort) // IP URL: the client sends no SNI

	evil := mustRequest(t, http.MethodGet, base+"/evil")
	evil.Host = net.JoinHostPort("evil.test", originPort)
	resp, err := f.client.Do(evil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	readAllClose(t, resp)
	if resp.StatusCode != http.StatusMisdirectedRequest || resp.Proto != "HTTP/2.0" {
		t.Fatalf("authority not resolving to the destination: got %s %d, want h2 421", resp.Proto, resp.StatusCode)
	}

	good := mustRequest(t, http.MethodGet, base+"/good")
	good.Host = net.JoinHostPort("good.test", originPort)
	resp, err = f.client.Do(good)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	readAllClose(t, resp)
	recs := f.origin.records()
	if resp.StatusCode != http.StatusOK || len(recs) != 1 || recs[0].injected != "for-good" {
		t.Fatalf("resolving authority: %d %+v", resp.StatusCode, recs)
	}
}

// ipOnlyPolicy permits a connection only through a rule bound to the
// destination IP: the SNI hostname on its own (ip == "") is not permitted.
type ipOnlyPolicy struct{}

func (ipOnlyPolicy) CheckConnect(hostname, ip string, port uint16) bool { return ip != "" }
func (ipOnlyPolicy) DecideMCPCall(engine.MCPCall) engine.Decision {
	return engine.Decision{Allow: true}
}
func (ipOnlyPolicy) HasMCPPolicies() bool { return false }

// When the connect policy permits only the original destination IP, the h2
// MITM dials that IP (SNI preserved for the upstream handshake) rather than
// resolving and dialing the client-chosen SNI name (issue #154). When the
// name itself is permitted, the name is dialed.
func TestH2MITMDialsSelectedUpstream(t *testing.T) {
	for _, tc := range []struct {
		name     string
		policy   PolicyChecker
		wantHost string
	}{
		{"ip-only permit dials original IP", ipOnlyPolicy{}, "127.0.0.1"},
		{"name permit dials name", stubPolicyChecker{allowConnect: true}, "example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newH2Fixture(t, true, nil, func(p *MITMProxy) {
				p.SetPolicyChecker(tc.policy)
				p.headerRewriter.SetRules([]HeaderRewriteRule{{Host: "example.com", Header: "X-Injected", Value: "v"}})
			})
			resp, err := f.client.Get("https://example.com/dial")
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			readAllClose(t, resp)
			if resp.StatusCode != http.StatusOK || resp.Proto != "HTTP/2.0" {
				t.Fatalf("got %s %d", resp.Proto, resp.StatusCode)
			}
			_, originPort, _ := net.SplitHostPort(f.origin.addr())
			want := net.JoinHostPort(tc.wantHost, originPort)
			dialed := f.dialedAddrs()
			if len(dialed) == 0 {
				t.Fatal("no upstream dial recorded")
			}
			for _, addr := range dialed {
				if addr != want {
					t.Fatalf("dialed %q, want %q (all: %v)", addr, want, dialed)
				}
			}
			// The upstream handshake still verified the origin as example.com
			// (the test origin's certificate), and the rewrite followed the SNI host.
			if recs := f.origin.records(); len(recs) != 1 || recs[0].proto != "HTTP/2.0" || recs[0].injected != "v" {
				t.Fatalf("origin records %+v", recs)
			}
		})
	}
}

func TestH2MITMUpstreamErrorIs502(t *testing.T) {
	f := newH2Fixture(t, true, nil, nil)
	f.proxy.upstreamDialContext = func(context.Context, string, string) (net.Conn, error) {
		return nil, fmt.Errorf("dial refused for test")
	}
	resp, err := f.client.Get("https://example.com/down")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	readAllClose(t, resp)
	if resp.StatusCode != http.StatusBadGateway || resp.Proto != "HTTP/2.0" {
		t.Fatalf("got %s %d, want h2 502", resp.Proto, resp.StatusCode)
	}
	entry := waitForEntry(t, f.capture, "event=http.request")
	if !strings.Contains(entry, "status=502") || !strings.Contains(entry, "decision=denied") || !strings.Contains(entry, "dial refused") {
		t.Fatalf("unexpected request log: %s", entry)
	}
}

// The ALPN offer to the client is unchanged by inspect mode for h1 clients.
func TestH2MITMLeavesHTTP11ClientsOnHTTP11Path(t *testing.T) {
	f := newH2Fixture(t, true, nil, func(p *MITMProxy) {
		p.headerRewriter.SetRules([]HeaderRewriteRule{{Host: "example.com", Header: "X-Injected", Value: "v"}})
	})
	tr := f.client.Transport.(*http.Transport).Clone()
	tr.ForceAttemptHTTP2 = false
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}} //nolint:gosec
	t.Cleanup(tr.CloseIdleConnections)
	resp, err := (&http.Client{Transport: tr}).Get("https://example.com/h1client")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	readAllClose(t, resp)
	if resp.Proto != "HTTP/1.1" {
		t.Fatalf("h1 client got %s", resp.Proto)
	}
	if recs := f.origin.records(); len(recs) != 1 || recs[0].injected != "v" {
		t.Fatalf("origin records %+v", recs)
	}
}
