package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const injectedSecret = "Bearer synthetic-injected-credential-0123456789"

func rewriterFor(host string) *HeaderRewriter {
	hr := NewHeaderRewriter()
	hr.SetRules([]HeaderRewriteRule{{Host: host, Header: "Authorization", Value: injectedSecret}})
	return hr
}

func staticLookup(ips ...string) func(context.Context, string) ([]net.IP, error) {
	return func(context.Context, string) ([]net.IP, error) {
		out := make([]net.IP, 0, len(ips))
		for _, s := range ips {
			out = append(out, net.ParseIP(s))
		}
		return out, nil
	}
}

func TestVerifyRequestAuthority(t *testing.T) {
	p := &MITMProxy{lookupIP: func(_ context.Context, host string) ([]net.IP, error) {
		switch host {
		case "a.example":
			return []net.IP{net.ParseIP("192.0.2.10"), net.ParseIP("2001:db8::10")}, nil
		case "other.example":
			return []net.IP{net.ParseIP("192.0.2.99")}, nil
		}
		return nil, fmt.Errorf("no such host")
	}}
	sni := newConnAuthority("api.example.com", "443", "api.example.com")
	sniOddPort := newConnAuthority("api.example.com", "8443", "api.example.com")
	ip4 := newConnAuthority("192.0.2.10", "80", "")
	ip6 := newConnAuthority("2001:db8::10", "80", "")

	cases := []struct {
		name string
		a    connAuthority
		host string
		want string // "" means rejected
	}{
		{"exact", sni, "api.example.com", "api.example.com"},
		{"default port", sni, "api.example.com:443", "api.example.com"},
		{"case", sni, "API.Example.COM", "api.example.com"},
		{"trailing dot", sni, "api.example.com.", "api.example.com"},
		{"trailing dot and port", sni, "Api.Example.Com.:443", "api.example.com"},
		{"no host binds to connection", sni, "", "api.example.com"},
		{"other host", sni, "evil.example", ""},
		{"suffix lookalike", sni, "api.example.com.evil.example", ""},
		{"wrong port", sni, "api.example.com:8443", ""},
		{"non-default port matches", sniOddPort, "api.example.com:8443", "api.example.com"},
		{"portless on non-default port", sniOddPort, "api.example.com", "api.example.com"},
		{"bad port", sni, "api.example.com:x", ""},
		{"out of range port", sni, "api.example.com:70000", ""},
		{"ip literal on sni conn", sni, "192.0.2.10", ""},
		{"malformed bracket", sni, "[api.example.com", ""},
		{"ip host equal", ip4, "192.0.2.10", "192.0.2.10"},
		{"ip host with port", ip4, "192.0.2.10:80", "192.0.2.10"},
		{"ip host different", ip4, "192.0.2.11", ""},
		{"name resolving to dest", ip4, "A.Example.", "a.example"},
		{"name resolving elsewhere", ip4, "other.example", ""},
		{"name not resolving", ip4, "missing.example", ""},
		{"ipv6 bracketed", ip6, "[2001:db8::10]:80", "2001:db8::10"},
		{"ipv6 non-canonical", ip6, "[2001:0db8:0:0::10]", "2001:db8::10"},
		{"ipv6 name", ip6, "a.example", "a.example"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := &http.Request{Host: tc.host}
			got, err := p.verifyRequestAuthority(req, tc.a)
			if tc.want == "" {
				if err == nil {
					t.Fatalf("expected rejection for Host %q, got %q", tc.host, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected rejection for Host %q: %v", tc.host, err)
			}
			if got != tc.want {
				t.Fatalf("verified host = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestApplyRulesForHostNormalizes(t *testing.T) {
	hr := rewriterFor("API.Example.com")
	for _, host := range []string{"api.example.com", "api.example.com:443", "API.EXAMPLE.COM.", "api.example.com.:8443"} {
		req, _ := http.NewRequest("GET", "https://x/", nil)
		hr.ApplyRulesForHost(req, host)
		if req.Header.Get("Authorization") != injectedSecret {
			t.Fatalf("rule not applied for %q", host)
		}
	}
	for _, host := range []string{"", "evil.example", "api.example.com.evil.example"} {
		req, _ := http.NewRequest("GET", "https://x/", nil)
		hr.ApplyRulesForHost(req, host)
		if req.Header.Get("Authorization") != "" {
			t.Fatalf("rule applied for %q", host)
		}
	}
}

// httpsHarness runs handleTransparentHTTPS against a pipe-backed origin and
// records every request the origin receives.
type httpsHarness struct {
	t      *testing.T
	proxy  *MITMProxy
	dials  atomic.Int32
	mu     sync.Mutex
	origin []*http.Request
	// dialed records the (addr, serverName) of every upstream dial.
	dialed [][2]string
	logs   *capturingBroadcaster
}

func newHTTPSHarness(t *testing.T, rewriteHost string) *httpsHarness {
	t.Helper()
	setTempLeashDir(t)
	ca, err := NewCertificateAuthority()
	if err != nil {
		t.Fatalf("failed to create CA: %v", err)
	}
	proxy, _, capture := newCapturingProxyLogger(t)
	proxy.ca = ca
	proxy.certCache = make(map[string]*tls.Certificate)
	proxy.headerRewriter = rewriterFor(rewriteHost)
	proxy.SetPolicyChecker(stubPolicyChecker{allowConnect: true})
	h := &httpsHarness{t: t, proxy: proxy, logs: capture}
	originCert := generateTestCertificate(t, "origin.test")
	proxy.tlsDialer = func(addr, serverName string) (*tls.Conn, error) {
		h.dials.Add(1)
		h.mu.Lock()
		h.dialed = append(h.dialed, [2]string{addr, serverName})
		h.mu.Unlock()
		c, s := net.Pipe()
		go func() {
			srv := tls.Server(s, &tls.Config{Certificates: []tls.Certificate{originCert}})
			defer srv.Close()
			req, err := http.ReadRequest(bufio.NewReader(srv))
			if err != nil {
				return
			}
			_, _ = io.Copy(io.Discard, req.Body)
			h.mu.Lock()
			h.origin = append(h.origin, req)
			h.mu.Unlock()
			_, _ = srv.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"))
		}()
		return tls.Client(c, &tls.Config{InsecureSkipVerify: true}), nil
	}
	return h
}

// do sends one raw request on a fresh TLS connection with the given SNI and
// returns the response status.
func (h *httpsHarness) do(originalDest, sni, raw string) int {
	h.t.Helper()
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer serverConn.Close()
		h.proxy.handleTransparentHTTPS(serverConn, originalDest, nil)
	}()
	clientTLS := tls.Client(clientConn, &tls.Config{InsecureSkipVerify: true, ServerName: sni})
	_ = clientTLS.SetDeadline(time.Now().Add(5 * time.Second))
	if err := clientTLS.Handshake(); err != nil {
		h.t.Fatalf("client handshake failed: %v", err)
	}
	if _, err := clientTLS.Write([]byte(raw)); err != nil {
		h.t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(clientTLS), nil)
	if err != nil {
		h.t.Fatalf("read response: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	_ = clientTLS.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		h.t.Fatal("proxy handler did not finish")
	}
	return resp.StatusCode
}

func (h *httpsHarness) originRequests() []*http.Request {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]*http.Request(nil), h.origin...)
}

func (h *httpsHarness) assertMisdirectedLogged() {
	h.t.Helper()
	for _, e := range h.logs.all() {
		if strings.Contains(e, "event=http.misdirected") && strings.Contains(e, "decision=denied") && strings.Contains(e, "status=421") {
			if strings.Contains(e, injectedSecret) {
				h.t.Fatalf("misdirected log leaked the injected credential: %s", e)
			}
			return
		}
	}
	h.t.Fatalf("no event=http.misdirected entry in %q", h.logs.all())
}

func TestHTTPSHostSNIMismatchRejectedWithoutInjection(t *testing.T) {
	// Rewrite rules exist for api.a.example; the connection is opened (and
	// connect-checked) for b.example; the request claims Host: api.a.example.
	h := newHTTPSHarness(t, "api.a.example")
	status := h.do("b.example:443", "b.example", "GET /steal HTTP/1.1\r\nHost: api.a.example\r\n\r\n")
	if status != http.StatusMisdirectedRequest {
		t.Fatalf("status = %d, want 421", status)
	}
	if n := h.dials.Load(); n != 0 {
		t.Fatalf("origin was dialed %d times for a misdirected request", n)
	}
	if got := h.originRequests(); len(got) != 0 {
		t.Fatalf("origin received %d requests", len(got))
	}
	h.assertMisdirectedLogged()
}

func TestHTTPSAbsoluteFormAuthorityMismatchRejected(t *testing.T) {
	// The absolute-form request-URI is the request's authority (RFC 9112
	// 3.2.2) even when the Host header matches the SNI.
	h := newHTTPSHarness(t, "api.a.example")
	status := h.do("b.example:443", "b.example", "GET https://api.a.example/steal HTTP/1.1\r\nHost: b.example\r\n\r\n")
	if status != http.StatusMisdirectedRequest {
		t.Fatalf("status = %d, want 421", status)
	}
	if n := h.dials.Load(); n != 0 {
		t.Fatalf("origin was dialed %d times", n)
	}
	h.assertMisdirectedLogged()
}

func TestHTTPSMismatchAfterValidRequestStopsConnection(t *testing.T) {
	// A keep-alive connection cannot switch authority mid-stream.
	h := newHTTPSHarness(t, "api.a.example")
	status := h.do("b.example:443", "b.example",
		"GET /ok HTTP/1.1\r\nHost: b.example\r\n\r\nGET /steal HTTP/1.1\r\nHost: api.a.example\r\n\r\n")
	if status != http.StatusOK {
		t.Fatalf("first status = %d, want 200", status)
	}
	// do() waited for the handler to exit, so the second request was read.
	h.assertMisdirectedLogged()
	for _, r := range h.originRequests() {
		if r.Header.Get("Authorization") != "" {
			t.Fatalf("origin saw an injected Authorization header on %s", r.URL.Path)
		}
		if r.URL.Path == "/steal" {
			t.Fatal("misdirected request reached the origin")
		}
	}
}

func TestHTTPSHostMatchingSNIStillRewritten(t *testing.T) {
	cases := []struct {
		name, sni, host, rule string
	}{
		{"exact", "api.a.example", "api.a.example", "api.a.example"},
		{"default port", "api.a.example", "api.a.example:443", "api.a.example"},
		{"case", "api.a.example", "API.A.Example", "api.a.example"},
		{"trailing dot", "api.a.example", "api.a.example.", "api.a.example"},
		{"sni case and trailing dot", "API.A.EXAMPLE.", "api.a.example", "api.a.example"},
		{"rule case", "api.a.example", "api.a.example", "Api.A.Example"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHTTPSHarness(t, tc.rule)
			status := h.do("192.0.2.10:443", tc.sni, "GET /v1 HTTP/1.1\r\nHost: "+tc.host+"\r\n\r\n")
			if status != http.StatusOK {
				t.Fatalf("status = %d, want 200", status)
			}
			reqs := h.originRequests()
			if len(reqs) != 1 {
				t.Fatalf("origin received %d requests, want 1", len(reqs))
			}
			if got := reqs[0].Header.Get("Authorization"); got != injectedSecret {
				t.Fatalf("origin Authorization = %q, want injected value", got)
			}
		})
	}
}

func TestHTTPSAbsoluteFormMatchingSNIRewritten(t *testing.T) {
	h := newHTTPSHarness(t, "api.a.example")
	status := h.do("192.0.2.10:443", "api.a.example", "GET https://api.a.example/v1 HTTP/1.1\r\nHost: api.a.example\r\n\r\n")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	reqs := h.originRequests()
	if len(reqs) != 1 || reqs[0].Header.Get("Authorization") != injectedSecret {
		t.Fatalf("expected one rewritten origin request, got %d", len(reqs))
	}
	if reqs[0].RequestURI != "/v1" {
		t.Fatalf("origin request-URI = %q, want origin-form /v1", reqs[0].RequestURI)
	}
}

func TestHTTPSWithoutSNIRequiresHostToResolveToDestination(t *testing.T) {
	// No SNI: the connection is forwarded to the original IP, so a Host name
	// is accepted only if it resolves to that IP.
	h := newHTTPSHarness(t, "api.a.example")
	h.proxy.lookupIP = staticLookup("192.0.2.99")
	status := h.do("192.0.2.10:443", "", "GET / HTTP/1.1\r\nHost: api.a.example\r\n\r\n")
	if status != http.StatusMisdirectedRequest {
		t.Fatalf("status = %d, want 421", status)
	}
	if n := h.dials.Load(); n != 0 {
		t.Fatalf("origin dialed %d times", n)
	}

	h2 := newHTTPSHarness(t, "api.a.example")
	h2.proxy.lookupIP = staticLookup("192.0.2.10")
	if status := h2.do("192.0.2.10:443", "", "GET / HTTP/1.1\r\nHost: api.a.example\r\n\r\n"); status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	reqs := h2.originRequests()
	if len(reqs) != 1 || reqs[0].Header.Get("Authorization") != injectedSecret {
		t.Fatal("expected the verified request to be rewritten")
	}
}

// doPlainHTTP runs one request through handleTransparentHTTP and returns the
// response status and the request handed to the upstream transport (nil if
// none was forwarded).
func doPlainHTTP(t *testing.T, proxy *MITMProxy, originalDest, raw string) (int, *http.Request) {
	t.Helper()
	var forwarded *http.Request
	var mu sync.Mutex
	proxy.httpClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		mu.Lock()
		forwarded = req
		mu.Unlock()
		return &http.Response{
			StatusCode: 200, Status: "200 OK", Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
			Body: io.NopCloser(strings.NewReader("OK")), ContentLength: 2,
			Header: http.Header{"Content-Length": []string{"2"}}, Request: req,
		}, nil
	})}
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer serverConn.Close()
		// serveTransparent hands over the first bytes it peeked.
		proxy.handleTransparentHTTP(serverConn, originalDest, []byte(raw[:4]))
	}()
	_ = clientConn.SetDeadline(time.Now().Add(5 * time.Second))
	go func() { _, _ = clientConn.Write([]byte(raw[4:])) }()
	resp, err := http.ReadResponse(bufio.NewReader(clientConn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("proxy handler did not finish")
	}
	mu.Lock()
	defer mu.Unlock()
	return resp.StatusCode, forwarded
}

func newPlainHTTPProxy(t *testing.T, rewriteHost string, lookup func(context.Context, string) ([]net.IP, error)) (*MITMProxy, *capturingBroadcaster) {
	t.Helper()
	proxy, _, capture := newCapturingProxyLogger(t)
	proxy.certCache = make(map[string]*tls.Certificate)
	proxy.headerRewriter = rewriterFor(rewriteHost)
	proxy.lookupIP = lookup
	proxy.SetPolicyChecker(stubPolicyChecker{allowConnect: true})
	return proxy, capture
}

func TestPlainHTTPHostNotMatchingDestinationRejected(t *testing.T) {
	proxy, capture := newPlainHTTPProxy(t, "api.a.example", staticLookup("192.0.2.99"))
	status, forwarded := doPlainHTTP(t, proxy, "192.0.2.10:80", "GET /steal HTTP/1.1\r\nHost: api.a.example\r\n\r\n")
	if status != http.StatusMisdirectedRequest {
		t.Fatalf("status = %d, want 421", status)
	}
	if forwarded != nil {
		t.Fatal("misdirected plain HTTP request was forwarded")
	}
	found := false
	for _, e := range capture.all() {
		if strings.Contains(e, "event=http.misdirected") && strings.Contains(e, "protocol=http ") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no event=http.misdirected entry in %q", capture.all())
	}
}

func TestPlainHTTPAbsoluteFormMismatchRejected(t *testing.T) {
	proxy, _ := newPlainHTTPProxy(t, "api.a.example", staticLookup("192.0.2.99"))
	status, forwarded := doPlainHTTP(t, proxy, "192.0.2.10:80", "GET http://api.a.example/steal HTTP/1.1\r\nHost: 192.0.2.10\r\n\r\n")
	if status != http.StatusMisdirectedRequest {
		t.Fatalf("status = %d, want 421", status)
	}
	if forwarded != nil {
		t.Fatal("misdirected request was forwarded")
	}
}

func TestPlainHTTPHostWrongPortRejected(t *testing.T) {
	proxy, _ := newPlainHTTPProxy(t, "api.a.example", staticLookup("192.0.2.10"))
	status, forwarded := doPlainHTTP(t, proxy, "192.0.2.10:80", "GET / HTTP/1.1\r\nHost: api.a.example:8080\r\n\r\n")
	if status != http.StatusMisdirectedRequest || forwarded != nil {
		t.Fatalf("status = %d forwarded = %v, want 421 and no forward", status, forwarded != nil)
	}
}

func TestPlainHTTPHostResolvingToDestinationRewritten(t *testing.T) {
	for _, host := range []string{"api.a.example", "API.A.Example.", "api.a.example:80"} {
		proxy, _ := newPlainHTTPProxy(t, "api.a.example", staticLookup("192.0.2.10"))
		status, forwarded := doPlainHTTP(t, proxy, "192.0.2.10:80", "GET /v1 HTTP/1.1\r\nHost: "+host+"\r\n\r\n")
		if status != http.StatusOK || forwarded == nil {
			t.Fatalf("Host %q: status = %d forwarded = %v", host, status, forwarded != nil)
		}
		if forwarded.Header.Get("Authorization") != injectedSecret {
			t.Fatalf("Host %q: rule not applied for verified host", host)
		}
		if forwarded.URL.Host != "192.0.2.10:80" {
			t.Fatalf("Host %q: forwarded to %q, want original destination", host, forwarded.URL.Host)
		}
	}
}

func TestPlainHTTPIPLiteralHostNoRewriteForOtherHost(t *testing.T) {
	// Host equal to the destination IP is fine, and only rules for that IP
	// can apply.
	proxy, _ := newPlainHTTPProxy(t, "api.a.example", nil)
	status, forwarded := doPlainHTTP(t, proxy, "192.0.2.10:80", "GET / HTTP/1.1\r\nHost: 192.0.2.10\r\n\r\n")
	if status != http.StatusOK || forwarded == nil {
		t.Fatalf("status = %d forwarded = %v", status, forwarded != nil)
	}
	if forwarded.Header.Get("Authorization") != "" {
		t.Fatal("rule for another host applied to an IP-literal request")
	}
}

func TestPlainHTTPNamedDestinationComparesNames(t *testing.T) {
	// PROXY-protocol ingestion can carry a hostname destination; the proxy
	// dials it by name, so Host must name the same host (no DNS involved).
	lookupCalled := false
	lookup := func(context.Context, string) ([]net.IP, error) {
		lookupCalled = true
		return nil, fmt.Errorf("unexpected lookup")
	}
	proxy, _ := newPlainHTTPProxy(t, "api.a.example", lookup)
	status, forwarded := doPlainHTTP(t, proxy, "b.example:80", "GET / HTTP/1.1\r\nHost: api.a.example\r\n\r\n")
	if status != http.StatusMisdirectedRequest || forwarded != nil {
		t.Fatalf("status = %d forwarded = %v, want 421", status, forwarded != nil)
	}
	if lookupCalled {
		t.Fatal("named destination should not need DNS")
	}

	proxy2, _ := newPlainHTTPProxy(t, "api.a.example", lookup)
	status, forwarded = doPlainHTTP(t, proxy2, "api.a.example:80", "GET / HTTP/1.1\r\nHost: Api.A.Example\r\n\r\n")
	if status != http.StatusOK || forwarded == nil || forwarded.Header.Get("Authorization") != injectedSecret {
		t.Fatalf("matching named destination: status = %d, rewritten = %v", status, forwarded != nil && forwarded.Header.Get("Authorization") == injectedSecret)
	}
}
