package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestChooseALPNDowngradeMode(t *testing.T) {
	rewriter := NewHeaderRewriter()
	rewriter.SetRules([]HeaderRewriteRule{{Host: "rewrite.example.com", Header: "X-A", Value: "v"}})

	both := []string{"h2", "http/1.1"}
	cases := []struct {
		name     string
		proxy    *MITMProxy
		host     string
		offered  []string
		wantNext []string
		wantMode string
		reasons  []string
	}{
		{"no features keeps h2", &MITMProxy{headerRewriter: rewriter}, "plain.example.com", both, both, alpnModeTunnel, nil},
		{"rewrite host downgrades", &MITMProxy{headerRewriter: rewriter}, "rewrite.example.com", both, []string{"http/1.1"}, alpnModeDowngrade, []string{alpnReasonHeaderRewrite}},
		{"rewrite match ignores port", &MITMProxy{headerRewriter: rewriter}, "rewrite.example.com:443", both, []string{"http/1.1"}, alpnModeDowngrade, []string{alpnReasonHeaderRewrite}},
		{"rewrite match is normalized", &MITMProxy{headerRewriter: rewriter}, "Rewrite.Example.COM.", both, []string{"http/1.1"}, alpnModeDowngrade, []string{alpnReasonHeaderRewrite}},
		{"mcp policy downgrades every host", &MITMProxy{headerRewriter: rewriter, policyChecker: stubPolicyChecker{mcp: true}}, "plain.example.com", both, []string{"http/1.1"}, alpnModeDowngrade, []string{alpnReasonMCPPolicy}},
		{"mcp observe downgrades every host", &MITMProxy{headerRewriter: rewriter, mcpObserver: newMCPObserver(MCPConfig{Mode: MCPModeBasic}, nil)}, "plain.example.com", both, []string{"http/1.1"}, alpnModeDowngrade, []string{alpnReasonMCPObserve}},
		{"mcp observe off is no feature", &MITMProxy{headerRewriter: rewriter, mcpObserver: newMCPObserver(MCPConfig{Mode: MCPModeOff}, nil)}, "plain.example.com", both, both, alpnModeTunnel, nil},
		{"h1 client unaffected", &MITMProxy{headerRewriter: rewriter}, "rewrite.example.com", []string{"http/1.1"}, both, alpnModeTunnel, []string{alpnReasonHeaderRewrite}},
		{"no alpn unaffected", &MITMProxy{headerRewriter: rewriter}, "rewrite.example.com", nil, both, alpnModeTunnel, []string{alpnReasonHeaderRewrite}},
		{"h2-only client refused when rewrite applies", &MITMProxy{headerRewriter: rewriter}, "rewrite.example.com", []string{"h2"}, []string{"http/1.1"}, alpnModeRefuse, []string{alpnReasonHeaderRewrite, alpnReasonClientH2Only}},
		{"h2-only client tunneled for observability only", &MITMProxy{headerRewriter: rewriter, mcpObserver: newMCPObserver(MCPConfig{Mode: MCPModeBasic}, nil)}, "plain.example.com", []string{"h2"}, both, alpnModeTunnel, []string{alpnReasonMCPObserve, alpnReasonClientH2Only}},
		{"nil rewriter is safe", &MITMProxy{}, "rewrite.example.com", both, both, alpnModeTunnel, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.proxy.h2Mode = h2ModeDowngrade
			d := tc.proxy.chooseALPN(tc.host, tc.offered)
			if !reflect.DeepEqual(d.nextProto, tc.wantNext) {
				t.Errorf("nextProto = %v, want %v", d.nextProto, tc.wantNext)
			}
			if d.mode != tc.wantMode {
				t.Errorf("mode = %q, want %q", d.mode, tc.wantMode)
			}
			if !reflect.DeepEqual(d.reasons, tc.reasons) {
				t.Errorf("reasons = %v, want %v", d.reasons, tc.reasons)
			}
		})
	}
}

func TestLogSafeStripsControlBytes(t *testing.T) {
	got := logSafe("h2\" injected=1\nnext\\")
	if strings.ContainsAny(got, "\"\n\\") {
		t.Fatalf("logSafe left unsafe bytes: %q", got)
	}
}

// originRecord is what the test origin saw for one request.
type originRecord struct {
	proto    string
	injected string
	path     string
}

// h2TestOrigin is an httptest TLS origin with HTTP/2 enabled that records each
// request it serves. Its certificate is valid for example.com.
type h2TestOrigin struct {
	srv  *httptest.Server
	pool *x509.CertPool
	mu   sync.Mutex
	seen []originRecord
}

func newH2TestOrigin(t *testing.T, enableH2 bool, handler http.HandlerFunc) *h2TestOrigin {
	t.Helper()
	o := &h2TestOrigin{}
	o.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		o.mu.Lock()
		o.seen = append(o.seen, originRecord{proto: r.Proto, injected: r.Header.Get("X-Injected"), path: r.URL.Path})
		o.mu.Unlock()
		if handler != nil {
			handler(w, r)
			return
		}
		w.Header().Set("X-Origin-Proto", r.Proto)
		_, _ = io.WriteString(w, "ok")
	}))
	o.srv.EnableHTTP2 = enableH2
	o.srv.StartTLS()
	t.Cleanup(o.srv.Close)
	o.pool = x509.NewCertPool()
	o.pool.AddCert(o.srv.Certificate())
	return o
}

func (o *h2TestOrigin) records() []originRecord {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]originRecord(nil), o.seen...)
}

func (o *h2TestOrigin) addr() string { return o.srv.Listener.Addr().String() }

// startTestMITM runs p's HTTPS MITM handler on a local listener and returns its
// address. Every accepted connection is treated as transparently redirected to
// originalDest; upstream dials are pointed at the origin.
func startTestMITM(t *testing.T, p *MITMProxy, origin *h2TestOrigin) string {
	t.Helper()
	p.upstreamDialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, origin.addr())
	}
	p.upstreamRootCAs = origin.pool
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen: %v", err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})
	_, originPort, _ := net.SplitHostPort(origin.addr())
	originalDest := net.JoinHostPort("127.0.0.1", originPort)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.Close()
				p.handleTransparentHTTPS(conn, originalDest, nil)
			}()
		}
	}()
	return ln.Addr().String()
}

func newTestMITM(t *testing.T) *MITMProxy {
	t.Helper()
	setTempLeashDir(t)
	ca, err := NewCertificateAuthority()
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	p := &MITMProxy{
		ca:             ca,
		certCache:      make(map[string]*tls.Certificate),
		headerRewriter: NewHeaderRewriter(),
	}
	p.SetPolicyChecker(stubPolicyChecker{allowConnect: true})
	return p
}

// h2PreferringClient is an HTTP client that offers h2 + http/1.1 via ALPN (as
// curl, browsers and most SDKs do) and always connects to the proxy.
func h2PreferringClient(t *testing.T, proxyAddr string) *http.Client {
	tr := &http.Transport{
		ForceAttemptHTTP2: true,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test against the leash CA
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, proxyAddr)
		},
	}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}
}

func entriesWith(capture *capturingBroadcaster, substr string) []string {
	var out []string
	for _, e := range capture.all() {
		if strings.Contains(e, substr) {
			out = append(out, e)
		}
	}
	return out
}

func TestALPNDowngradeModeH2ForRewriteHost(t *testing.T) {
	origin := newH2TestOrigin(t, true, nil)
	p := newTestMITM(t)
	p.h2Mode = h2ModeDowngrade
	logger, _, capture := newMCPTestLogger(t)
	p.sharedLogger = logger
	p.headerRewriter.SetSharedLogger(logger)
	p.headerRewriter.SetRules([]HeaderRewriteRule{{Host: "example.com", Header: "X-Injected", Value: "rewritten"}})
	proxyAddr := startTestMITM(t, p, origin)

	resp, err := h2PreferringClient(t, proxyAddr).Get("https://example.com/rewrite")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.Proto != "HTTP/1.1" {
		t.Fatalf("client negotiated %s, want HTTP/1.1 (downgrade)", resp.Proto)
	}
	recs := origin.records()
	if len(recs) != 1 || recs[0].injected != "rewritten" {
		t.Fatalf("origin did not see the rewritten header: %+v", recs)
	}
	alpnLogs := entriesWith(capture, "event=http.alpn")
	if len(alpnLogs) != 1 || !strings.Contains(alpnLogs[0], "alpn_mode=downgrade") ||
		!strings.Contains(alpnLogs[0], `reasons="header_rewrite"`) || !strings.Contains(alpnLogs[0], `alpn_negotiated="http/1.1"`) {
		t.Fatalf("unexpected alpn log: %v", alpnLogs)
	}
	if len(entriesWith(capture, "event=http.rewrite")) != 1 {
		t.Fatalf("expected one rewrite event, got %v", capture.all())
	}
}

func TestALPNKeepsH2TunnelWithoutRequestFeatures(t *testing.T) {
	origin := newH2TestOrigin(t, true, nil)
	p := newTestMITM(t)
	logger, _, capture := newMCPTestLogger(t)
	p.sharedLogger = logger
	// A rule for some other host must not affect example.com.
	p.headerRewriter.SetRules([]HeaderRewriteRule{{Host: "other.example.net", Header: "X-Injected", Value: "rewritten"}})
	proxyAddr := startTestMITM(t, p, origin)

	resp, err := h2PreferringClient(t, proxyAddr).Get("https://example.com/tunnel")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.Proto != "HTTP/2.0" {
		t.Fatalf("client negotiated %s, want HTTP/2.0", resp.Proto)
	}
	recs := origin.records()
	if len(recs) != 1 || recs[0].proto != "HTTP/2.0" || recs[0].injected != "" {
		t.Fatalf("origin should see an untouched h2 request through the tunnel: %+v", recs)
	}
	alpnLogs := entriesWith(capture, "event=http.alpn")
	if len(alpnLogs) != 1 || !strings.Contains(alpnLogs[0], "alpn_mode=tunnel") || !strings.Contains(alpnLogs[0], `alpn_negotiated="h2"`) {
		t.Fatalf("unexpected alpn log: %v", alpnLogs)
	}
}

func TestALPNDowngradeModeEnforcesMCPDenyForH2Client(t *testing.T) {
	origin := newH2TestOrigin(t, true, nil)
	p := newTestMITM(t)
	p.h2Mode = h2ModeDowngrade
	p.mcpObserver = newMCPObserver(MCPConfig{Mode: MCPModeBasic}, nil)
	p.SetPolicyChecker(stubPolicyChecker{allowConnect: true, mcp: true, allowMCP: false})
	proxyAddr := startTestMITM(t, p, origin)

	body := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"shell"}}`
	resp, err := h2PreferringClient(t, proxyAddr).Post("https://example.com/mcp", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	out, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.Proto != "HTTP/1.1" || resp.StatusCode != http.StatusForbidden || !strings.Contains(string(out), "denied by policy") {
		t.Fatalf("want HTTP/1.1 403 MCP denial, got %s %d %q", resp.Proto, resp.StatusCode, out)
	}
	if n := len(origin.records()); n != 0 {
		t.Fatalf("denied tools/call reached the origin (%d requests)", n)
	}
}

func TestALPNDowngradeModeRefusesH2OnlyClient(t *testing.T) {
	origin := newH2TestOrigin(t, true, nil)
	p := newTestMITM(t)
	p.h2Mode = h2ModeDowngrade
	logger, _, capture := newMCPTestLogger(t)
	p.sharedLogger = logger
	p.headerRewriter.SetRules([]HeaderRewriteRule{{Host: "example.com", Header: "X-Injected", Value: "rewritten"}})
	proxyAddr := startTestMITM(t, p, origin)

	conn, err := tls.Dial("tcp", proxyAddr, &tls.Config{ServerName: "example.com", NextProtos: []string{"h2"}, InsecureSkipVerify: true}) //nolint:gosec
	if err == nil {
		conn.Close()
		t.Fatal("h2-only handshake succeeded; the rewrite would have been bypassed")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && len(entriesWith(capture, "alpn_mode=refuse")) == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if got := entriesWith(capture, "alpn_mode=refuse"); len(got) != 1 || !strings.Contains(got[0], "decision=denied") {
		t.Fatalf("expected one refuse log, got %v", capture.all())
	}
}
