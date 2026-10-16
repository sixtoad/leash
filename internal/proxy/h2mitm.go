package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"sync"
	"time"
)

// HTTP/2 MITM (issue #57).
//
// For hosts with a request-level feature (see requestInspectionReasons) the
// proxy accepts h2 from the client, serves each stream through the same
// per-request steps as the HTTP/1.1 path (MCP sniff + tools/call enforcement,
// header rewrite, request and MCP logging) and forwards it with an h2-capable
// transport that falls back to HTTP/1.1 when the origin does not negotiate h2.
//
// The h2 framing, HPACK, flow control, stream limits and trailers are handled
// by net/http's bundled HTTP/2 server and client, so no new dependency is
// needed; bodies are streamed in both directions (httputil.ReverseProxy), and
// only the MCP sniffer reads ahead, exactly as on the HTTP/1.1 path (a JSON
// request body up to the sniff limit; a JSON response body up to the limit;
// SSE is sniffed while it streams).

// LEASH_PROXY_H2 values.
const (
	h2ModeInspect   = "inspect"   // default: MITM h2 for inspected hosts
	h2ModeDowngrade = "downgrade" // escape hatch: offer only http/1.1 to inspected hosts
)

// h2ModeEnv selects how h2 clients of inspected hosts are handled.
const h2ModeEnv = "LEASH_PROXY_H2"

const (
	// h2IdleTimeout closes a client h2 connection (GOAWAY) after it has had no
	// open streams for this long; a long-lived stream (SSE, gRPC) is not idle.
	h2IdleTimeout = 2 * time.Minute
	// upstream transport tuning; no overall request timeout so streaming
	// responses are never cut off — cancellation follows the client stream.
	upstreamTLSHandshakeTimeout = 10 * time.Second
	upstreamIdleConnTimeout     = 90 * time.Second
	upstreamMaxIdleConnsPerHost = 16
)

// loadH2Mode parses LEASH_PROXY_H2. Unknown values fall back to inspect.
func loadH2Mode() string {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv(h2ModeEnv)))
	switch raw {
	case "", h2ModeInspect:
		return h2ModeInspect
	case h2ModeDowngrade:
		return h2ModeDowngrade
	default:
		log.Printf("%s=%q not recognised (want %s|%s); using %s", h2ModeEnv, raw, h2ModeInspect, h2ModeDowngrade, h2ModeInspect)
		return h2ModeInspect
	}
}

// h2InspectEnabled reports whether h2 clients of inspected hosts are served by
// the h2 MITM (true) or downgraded to HTTP/1.1 (false). A zero-value proxy
// (constructed in tests without NewMITMProxy) inspects.
func (p *MITMProxy) h2InspectEnabled() bool {
	return p.h2Mode != h2ModeDowngrade
}

// newUpstreamTransport returns the h2-capable transport that forwards the
// streams of one client connection. Every upstream connection it opens dials
// upstream.addr — the destination selectTLSUpstream chose from what the
// connect policy permitted (issue #154) — through dialUpstream (SO_MARK on
// Linux, as for the HTTP/1.1 path), and handshakes with upstream.serverName as
// SNI and verification name. The transport is per client connection because
// its pool is keyed by URL host only: sharing it would let a connection whose
// SNI was permitted only via its destination IP reuse an upstream dialed by
// name for another connection (or the reverse).
func (p *MITMProxy) newUpstreamTransport(upstream tlsUpstream) *http.Transport {
	serverName := strings.Trim(upstream.serverName, "[]")
	return &http.Transport{
		Proxy: nil, // never chain through HTTP(S)_PROXY from the daemon env
		DialTLSContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			raw, err := p.dialUpstream(ctx, network, upstream.addr)
			if err != nil {
				return nil, err
			}
			tc := tls.Client(raw, &tls.Config{
				ServerName: serverName,
				RootCAs:    p.upstreamRootCAs,
				NextProtos: []string{"h2", "http/1.1"}, // use whatever the origin picks
			})
			hsCtx, cancel := context.WithTimeout(ctx, upstreamTLSHandshakeTimeout)
			defer cancel()
			if err := tc.HandshakeContext(hsCtx); err != nil {
				_ = raw.Close()
				return nil, err
			}
			return tc, nil
		},
		ForceAttemptHTTP2:   true, // use h2 when the origin negotiates it
		IdleConnTimeout:     upstreamIdleConnTimeout,
		MaxIdleConnsPerHost: upstreamMaxIdleConnsPerHost,
		// Pass bodies through as the client and origin sent them; never let
		// the transport add Accept-Encoding and transparently decompress.
		DisableCompression:    true,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

// serveH2 runs an HTTP/2 server on the client's TLS connection (ALPN h2) and
// returns once the connection is closed. upstream is where every stream is
// forwarded, authority the connection's verified host, and targetHost the URL
// host (authority host:port) sent upstream.
func (p *MITMProxy) serveH2(tlsConn *tls.Conn, upstream tlsUpstream, authority connAuthority, targetHost string) {
	transport := p.newUpstreamTransport(upstream)
	defer transport.CloseIdleConnections()
	ln := newSingleConnListener(tlsConn)
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p.handleH2Request(w, r, transport, authority, targetHost)
		}),
		IdleTimeout: h2IdleTimeout,
		ConnState: func(c net.Conn, state http.ConnState) {
			if state == http.StateClosed || state == http.StateHijacked {
				ln.connDone()
			}
		},
	}
	log.Printf("h2 mitm: %s <-> %s (dial %s)", tlsConn.RemoteAddr(), targetHost, upstream.addr)
	if err := srv.Serve(ln); err != nil && !errors.Is(err, net.ErrClosed) {
		log.Printf("h2 mitm: serve %s: %v", targetHost, err)
	}
}

// handleH2Request handles one h2 stream: the per-request pipeline of the
// HTTP/1.1 HTTPS path, then a streamed forward to the origin.
func (p *MITMProxy) handleH2Request(w http.ResponseWriter, r *http.Request, transport http.RoundTripper, authority connAuthority, targetHost string) {
	host, port, err := net.SplitHostPort(targetHost)
	if err != nil {
		host = targetHost
		port = "443"
	}
	path := r.URL.Path
	if path == "" {
		path = "/"
	}
	query := r.URL.RawQuery
	authPresent := headerValuePresent(r.Header, "Authorization")

	// The stream's :authority must name the connection's verified host, as on
	// the HTTP/1.1 path (issue #149). h2 additionally lets a client reuse a
	// connection for any authority the certificate covers (the leash leaf has a
	// wildcard SAN), so this also stops coalesced streams. rejectMisdirected
	// writes an HTTP/1.1 421 and logs event=http.misdirected; capture it and
	// replay it on this stream only. No rewrite has been applied yet.
	verifiedHost, authErr := p.verifyRequestAuthority(r, authority)
	if authErr != nil {
		capture := &responseCaptureConn{}
		p.rejectMisdirected(capture, "https", authority, r, authErr)
		capture.replay(w, r)
		return
	}

	out := r.Clone(r.Context())
	out.URL.Scheme = "https"
	out.URL.Host = targetHost
	out.RequestURI = ""

	var mcpCtx *mcpRequestContext
	if p.mcpObserver != nil {
		if ctx, sniffErr := p.mcpObserver.inspectHTTPRequest(out, verifiedHost); sniffErr == nil {
			mcpCtx = ctx
		} else {
			log.Printf("mcp sniff (h2) error: %v", sniffErr)
		}
	}
	// enforceMCPCall renders its denial as an HTTP/1.1 response on a conn and
	// does its own logging; capture that response and replay it on this stream.
	capture := &responseCaptureConn{}
	if p.enforceMCPCall(capture, mcpCtx, verifiedHost, host, port, path, query, authPresent, "https") {
		capture.replay(w, out)
		return
	}

	// Rewrite rules for the verified host only, never the raw :authority.
	p.headerRewriter.ApplyRulesForHost(out, verifiedHost)

	rec := &statusRecorder{ResponseWriter: w}
	var (
		sessionHeader string
		forwardErr    error
	)
	finish := func(err error) {
		status := rec.status
		if mcpCtx != nil {
			p.mcpObserver.logHTTPRequest(mcpCtx, status, classifyOutcome(status, err), sessionHeader, err)
		}
		p.logRequest("https", host, port, path, query, authPresent, status, err)
	}
	defer func() {
		// ReverseProxy aborts the stream with http.ErrAbortHandler when copying
		// the response body fails (client reset, origin error mid-body). Log the
		// request, then let the server reset the stream.
		if v := recover(); v != nil {
			if v == http.ErrAbortHandler {
				finish(fmt.Errorf("stream aborted"))
			}
			panic(v)
		}
	}()

	rp := &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "https"
			pr.Out.URL.Host = targetHost
			pr.Out.Host = pr.In.Host
			// Rewrite mode strips Forwarded/X-Forwarded-*; the HTTP/1.1 path
			// forwards client headers verbatim, so restore them.
			for _, k := range []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto"} {
				if v, ok := pr.In.Header[k]; ok {
					pr.Out.Header[k] = v
				}
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			sessionHeader = resp.Header.Get("Mcp-Session-Id")
			transport := transportFromHeader(resp.Header.Get("Content-Type"))
			if mcpCtx != nil && mcpCtx.sampled {
				mcpCtx.transport = transport
				if transport == "sse" {
					resp.Body = p.mcpObserver.wrapSSEBody(mcpCtx, resp.Body)
				} else {
					p.mcpObserver.inspectHTTPResponse(mcpCtx, resp)
				}
				p.mcpObserver.registerSession(sessionHeader, mcpCtx)
			} else if p.mcpObserver != nil && transport == "sse" {
				protoHeader := strings.TrimSpace(out.Header.Get("MCP-Protocol-Version"))
				resp.Body = p.mcpObserver.wrapSessionSSE(sessionHeader, host, protoHeader, resp.Body)
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, req *http.Request, err error) {
			forwardErr = err
			log.Printf("h2 mitm: forwarding to %s: %v", targetHost, err)
			w.WriteHeader(http.StatusBadGateway)
		},
		ErrorLog: log.Default(),
	}
	rp.ServeHTTP(rec, out)
	finish(forwardErr)
}

// statusRecorder captures the final status code written to an h2 stream. It
// unwraps to the underlying writer so http.ResponseController (used by
// ReverseProxy to flush streaming responses) reaches the h2 server's Flush.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.status == 0 && code >= 200 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// responseCaptureConn is a write-only net.Conn that records what a responder
// written for a raw connection (enforceMCPCall) sends, so it can be replayed
// as an h2 response.
type responseCaptureConn struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *responseCaptureConn) Read([]byte) (int, error) { return 0, io.EOF }
func (c *responseCaptureConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(b)
}
func (c *responseCaptureConn) Close() error                     { return nil }
func (c *responseCaptureConn) LocalAddr() net.Addr              { return captureAddr{} }
func (c *responseCaptureConn) RemoteAddr() net.Addr             { return captureAddr{} }
func (c *responseCaptureConn) SetDeadline(time.Time) error      { return nil }
func (c *responseCaptureConn) SetReadDeadline(time.Time) error  { return nil }
func (c *responseCaptureConn) SetWriteDeadline(time.Time) error { return nil }

// replay writes the captured HTTP/1.1 response to w. Connection-level headers
// are dropped (meaningless, and invalid, in h2).
func (c *responseCaptureConn) replay(w http.ResponseWriter, req *http.Request) {
	c.mu.Lock()
	raw := append([]byte(nil), c.buf.Bytes()...)
	c.mu.Unlock()
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(raw)), req)
	if err != nil {
		log.Printf("h2 mitm: unreadable denial response: %v", err)
		w.WriteHeader(http.StatusForbidden)
		return
	}
	defer resp.Body.Close()
	for k, vv := range resp.Header {
		if strings.EqualFold(k, "Connection") {
			continue
		}
		w.Header()[k] = vv
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

type captureAddr struct{}

func (captureAddr) Network() string { return "capture" }
func (captureAddr) String() string  { return "capture" }

// singleConnListener hands one already-handshaken *tls.Conn to http.Server.
// The conn must reach the server unwrapped: net/http selects its h2 server by
// type-asserting *tls.Conn and reading NegotiatedProtocol. Accept blocks after
// the first call until the server reports the conn closed, so Serve returns
// only when the connection is finished.
type singleConnListener struct {
	conn     *tls.Conn
	accepted bool
	mu       sync.Mutex
	done     chan struct{}
	doneOnce sync.Once
}

func newSingleConnListener(conn *tls.Conn) *singleConnListener {
	return &singleConnListener{conn: conn, done: make(chan struct{})}
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if !l.accepted {
		l.accepted = true
		l.mu.Unlock()
		return l.conn, nil
	}
	l.mu.Unlock()
	<-l.done
	return nil, net.ErrClosed
}

func (l *singleConnListener) connDone() { l.doneOnce.Do(func() { close(l.done) }) }

func (l *singleConnListener) Close() error {
	l.connDone()
	return nil
}

func (l *singleConnListener) Addr() net.Addr { return l.conn.LocalAddr() }
