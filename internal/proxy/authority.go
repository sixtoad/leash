package proxy

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// authorityLookupTimeout bounds the DNS lookup used to tie a plain-HTTP (or
// SNI-less TLS) Host name to the connection's original destination IP.
const authorityLookupTimeout = 3 * time.Second

// connAuthority is the host a proxied connection is actually bound to: the
// name the proxy dials (and the connect policy checked), or the original
// destination IP when there is no such name. Every request-level decision
// (connect policy, header rewrite, MCP policy, logging) must be made for this
// host, never for the client-supplied Host header on its own (issue #149).
type connAuthority struct {
	// host is the normalized authoritative host (lowercase, no brackets, no
	// trailing dot).
	host string
	// port is the destination port of the connection.
	port string
	// ip is set when host is an IP literal (plain HTTP to SO_ORIGINAL_DST,
	// SNI-less TLS); a Host name is then accepted only if it resolves to ip.
	ip net.IP
	// sni is the raw TLS server name, for logging only.
	sni string
}

// newConnAuthority builds the authority for a connection whose upstream is
// dialHost (SNI name, or the original destination host) on port.
func newConnAuthority(dialHost, port, sni string) connAuthority {
	h := normalizeAuthorityHost(dialHost)
	a := connAuthority{host: h, port: port, sni: sni}
	if ip := net.ParseIP(h); ip != nil {
		a.ip = ip
	}
	return a
}

// normalizeAuthorityHost canonicalizes a bare host for comparison: brackets
// around IPv6 literals and a trailing root dot are removed, names are
// lowercased and IP literals are rendered in canonical form.
func normalizeAuthorityHost(h string) string {
	h = strings.TrimSpace(h)
	h = strings.TrimPrefix(h, "[")
	h = strings.TrimSuffix(h, "]")
	h = strings.TrimSuffix(h, ".")
	if ip := net.ParseIP(h); ip != nil {
		return ip.String()
	}
	return strings.ToLower(h)
}

// splitRequestAuthority splits a Host header / absolute-form authority into a
// normalized host and an optional port.
func splitRequestAuthority(authority string) (host, port string, err error) {
	authority = strings.TrimSpace(authority)
	if authority == "" {
		return "", "", fmt.Errorf("empty authority")
	}
	host = authority
	if h, p, splitErr := net.SplitHostPort(authority); splitErr == nil {
		host, port = h, p
	} else if strings.HasPrefix(authority, "[") {
		// "[v6]" without a port.
		if !strings.HasSuffix(authority, "]") {
			return "", "", fmt.Errorf("malformed authority")
		}
	} else if strings.Contains(authority, ":") && net.ParseIP(authority) == nil {
		// An unbracketed IPv6 literal is tolerated; any other colon form that
		// SplitHostPort rejects is malformed.
		return "", "", fmt.Errorf("malformed authority")
	}
	if port != "" {
		if n, convErr := strconv.Atoi(port); convErr != nil || n < 1 || n > 65535 {
			return "", "", fmt.Errorf("invalid port")
		}
	}
	host = normalizeAuthorityHost(host)
	if host == "" {
		return "", "", fmt.Errorf("empty host")
	}
	return host, port, nil
}

// resolveAuthorityIPs resolves a Host name for consistency checks against the
// original destination IP. Tests replace it via MITMProxy.lookupIP.
func (p *MITMProxy) resolveAuthorityIPs(ctx context.Context, host string) ([]net.IP, error) {
	if p.lookupIP != nil {
		return p.lookupIP(ctx, host)
	}
	return net.DefaultResolver.LookupIP(ctx, "ip", host)
}

// verifyRequestAuthority checks that the request's authority (req.Host, which
// http.ReadRequest fills from an absolute-form request-URI ahead of the Host
// header) names the connection's authoritative host, and returns the host all
// decisions for this request must use. A request with no authority (HTTP/1.0)
// is bound to the connection host.
//
// Accepted:
//   - same host after normalization (case, trailing dot, brackets, IP form);
//   - a port only if it equals the connection's destination port (a Host
//     without a port is accepted for any port);
//   - when the connection is bound to an IP (plain HTTP via SO_ORIGINAL_DST,
//     SNI-less TLS), a Host name that resolves to that IP.
func (p *MITMProxy) verifyRequestAuthority(req *http.Request, a connAuthority) (string, error) {
	if strings.TrimSpace(req.Host) == "" {
		return a.host, nil
	}
	host, port, err := splitRequestAuthority(req.Host)
	if err != nil {
		return "", err
	}
	if port != "" && a.port != "" && port != a.port {
		return "", fmt.Errorf("authority port %s does not match connection port %s", port, a.port)
	}
	if host == a.host {
		return host, nil
	}
	if a.ip == nil || net.ParseIP(host) != nil {
		return "", fmt.Errorf("authority host does not match connection host")
	}
	ctx, cancel := context.WithTimeout(req.Context(), authorityLookupTimeout)
	defer cancel()
	ips, err := p.resolveAuthorityIPs(ctx, host)
	if err != nil {
		return "", fmt.Errorf("authority host could not be resolved: %v", err)
	}
	for _, ip := range ips {
		if ip.Equal(a.ip) {
			return host, nil
		}
	}
	return "", fmt.Errorf("authority host does not resolve to connection destination")
}

// rejectMisdirected answers a request whose authority does not match the
// connection with 421 Misdirected Request, closes the connection and logs
// event=http.misdirected. No rewrite rule has been applied at this point and
// nothing is forwarded upstream.
func (p *MITMProxy) rejectMisdirected(conn net.Conn, scheme string, a connAuthority, req *http.Request, reason error) {
	status := http.StatusMisdirectedRequest
	body := "misdirected request: authority does not match the connection destination\n"
	response := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		status, http.StatusText(status), len(body), body)
	if _, err := conn.Write([]byte(response)); err != nil {
		log.Printf("failed to write misdirected response: %v", err)
	}
	if closer, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = closer.CloseWrite()
	}
	_ = conn.Close()

	dest := a.host
	if a.port != "" && a.port != "80" && a.port != "443" {
		dest = net.JoinHostPort(a.host, a.port)
	}
	path := "/"
	if req != nil && req.URL != nil && req.URL.Path != "" {
		path = req.URL.Path
	}
	reqHost := ""
	if req != nil {
		reqHost = req.Host
	}
	reasonStr := ""
	if reason != nil {
		reasonStr = reason.Error()
	}
	log.Printf("proxy: misdirected %s request rejected: host=%q dest=%s: %s", scheme, sanitizeAuthorityLog(reqHost), dest, reasonStr)
	if p.sharedLogger != nil {
		entry := fmt.Sprintf("time=%s event=http.misdirected protocol=%s addr=\"%s\" host=\"%s\"",
			time.Now().Format(time.RFC3339), scheme, sanitizeAuthorityLog(dest), sanitizeAuthorityLog(reqHost))
		if a.sni != "" {
			entry += fmt.Sprintf(" sni=\"%s\"", sanitizeAuthorityLog(a.sni))
		}
		entry += fmt.Sprintf(" path=\"%s\" decision=denied status=%d", sanitizeAuthorityLog(path), status)
		if reasonStr != "" {
			entry += fmt.Sprintf(" error=\"%s\"", sanitizeAuthorityLog(reasonStr))
		}
		_ = p.sharedLogger.Write(entry)
	}
}

// sanitizeAuthorityLog makes a client-controlled value safe to embed in a
// quoted logfmt field: quotes, backslashes and control bytes are replaced and
// the value is capped.
func sanitizeAuthorityLog(s string) string {
	const max = 256
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= max {
			b.WriteString("...")
			break
		}
		switch {
		case r == '"':
			b.WriteByte('\'')
		case r == '\\':
			b.WriteByte('/')
		case r < 0x20 || r == 0x7f:
			b.WriteByte('?')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
