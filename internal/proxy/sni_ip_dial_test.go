package proxy

import (
	"encoding/binary"
	"net"
	"net/http"
	"testing"

	"github.com/strongdm/leash/internal/lsm"
)

// Issue #154: the upstream dial of an intercepted TLS connection must go to a
// destination the connect policy actually permitted. An IP-only permit must
// not let a client-chosen SNI steer the dial to another host.

func connectHostRule(action int32, host string, port uint16) lsm.ConnectPolicyRule {
	r := lsm.ConnectPolicyRule{Action: action, Operation: 4, DestPort: port}
	copy(r.Hostname[:], host)
	r.HostnameLen = int32(len(host))
	if len(host) > 2 && host[:2] == "*." {
		r.IsWildcard = 1
	}
	return r
}

func connectIPRule(action int32, ip string, port uint16) lsm.ConnectPolicyRule {
	return lsm.ConnectPolicyRule{
		Action:    action,
		Operation: 4,
		DestIP:    binary.BigEndian.Uint32(net.ParseIP(ip).To4()),
		DestPort:  port,
	}
}

// denyByDefault builds the real proxy-side checker with the given rules and a
// default-deny policy.
func denyByDefault(rules ...lsm.ConnectPolicyRule) PolicyChecker {
	return lsm.NewSimplePolicyChecker(rules, false, nil)
}

func (h *httpsHarness) dialedTargets() [][2]string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([][2]string(nil), h.dialed...)
}

func (h *httpsHarness) assertSingleDial(wantAddr, wantServerName string) {
	h.t.Helper()
	got := h.dialedTargets()
	if len(got) != 1 {
		h.t.Fatalf("dials = %v, want exactly one", got)
	}
	if got[0][0] != wantAddr || got[0][1] != wantServerName {
		h.t.Fatalf("dialed addr=%q serverName=%q, want addr=%q serverName=%q", got[0][0], got[0][1], wantAddr, wantServerName)
	}
}

func TestTLSIPOnlyPermitMismatchedSNIDialsOriginalIP(t *testing.T) {
	h := newHTTPSHarness(t, "unused.example")
	h.proxy.SetPolicyChecker(denyByDefault(connectIPRule(lsm.PolicyAllow, "203.0.113.10", 443)))

	status := h.do("203.0.113.10:443", "evil.example", "GET / HTTP/1.1\r\nHost: evil.example\r\n\r\n")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	// The dial goes to the permitted IP, never to the SNI name; the SNI is
	// kept for the upstream handshake so the origin certificate is still
	// verified against it.
	h.assertSingleDial("203.0.113.10:443", "evil.example")
	reqs := h.originRequests()
	if len(reqs) != 1 || reqs[0].Host != "evil.example" {
		t.Fatalf("origin requests = %v, want one with Host evil.example", reqs)
	}
}

func TestTLSIPOnlyPermitNonDefaultPortDialsOriginalIP(t *testing.T) {
	h := newHTTPSHarness(t, "unused.example")
	h.proxy.SetPolicyChecker(denyByDefault(connectIPRule(lsm.PolicyAllow, "203.0.113.10", 8443)))

	if status := h.do("203.0.113.10:8443", "evil.example", "GET / HTTP/1.1\r\nHost: evil.example:8443\r\n\r\n"); status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	h.assertSingleDial("203.0.113.10:8443", "evil.example")
}

func TestTLSNamePermitStillDialsName(t *testing.T) {
	h := newHTTPSHarness(t, "api.example")
	h.proxy.SetPolicyChecker(denyByDefault(connectHostRule(lsm.PolicyAllow, "api.example", 0)))

	if status := h.do("198.51.100.7:443", "api.example", "GET / HTTP/1.1\r\nHost: api.example\r\n\r\n"); status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	h.assertSingleDial("api.example:443", "api.example")
	reqs := h.originRequests()
	if len(reqs) != 1 || reqs[0].Header.Get("Authorization") != injectedSecret {
		t.Fatalf("name-permitted request was not rewritten as before: %v", reqs)
	}
}

func TestTLSWildcardNamePermitStillDialsName(t *testing.T) {
	h := newHTTPSHarness(t, "unused.example")
	h.proxy.SetPolicyChecker(denyByDefault(connectHostRule(lsm.PolicyAllow, "*.example.com", 443)))

	if status := h.do("198.51.100.7:443", "api.example.com", "GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n"); status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	h.assertSingleDial("api.example.com:443", "api.example.com")
}

func TestTLSBothNameAndIPPermittedDialsName(t *testing.T) {
	h := newHTTPSHarness(t, "unused.example")
	h.proxy.SetPolicyChecker(denyByDefault(
		connectIPRule(lsm.PolicyAllow, "203.0.113.10", 443),
		connectHostRule(lsm.PolicyAllow, "api.example", 443),
	))

	if status := h.do("203.0.113.10:443", "api.example", "GET / HTTP/1.1\r\nHost: api.example\r\n\r\n"); status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	h.assertSingleDial("api.example:443", "api.example")
}

func TestTLSAllowAllPolicyDialsName(t *testing.T) {
	// No checker / allow-all: unchanged, the SNI name is dialed.
	h := newHTTPSHarness(t, "unused.example")
	if status := h.do("203.0.113.10:443", "api.example", "GET / HTTP/1.1\r\nHost: api.example\r\n\r\n"); status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	h.assertSingleDial("api.example:443", "api.example")
}

func TestSelectTLSUpstream(t *testing.T) {
	ipOnly := denyByDefault(connectIPRule(lsm.PolicyAllow, "203.0.113.10", 0))
	named := denyByDefault(connectHostRule(lsm.PolicyAllow, "api.example", 0))
	// A hostname rule bound to an IP is IP-scoped: it must not make the name
	// dialable on its own.
	nameAtIP := connectHostRule(lsm.PolicyAllow, "api.example", 0)
	nameAtIP.DestIP = binary.BigEndian.Uint32(net.ParseIP("203.0.113.10").To4())
	boundName := denyByDefault(nameAtIP)

	tests := []struct {
		name       string
		checker    PolicyChecker
		sni        string
		dest       string
		wantAddr   string
		wantServer string
		wantByName bool
	}{
		{"no SNI", ipOnly, "", "203.0.113.10:443", "203.0.113.10:443", "203.0.113.10", false},
		{"IP literal SNI is not dialed", ipOnly, "192.0.2.1", "203.0.113.10:443", "203.0.113.10:443", "203.0.113.10", false},
		{"IPv6 destination without SNI", nil, "", "[2001:db8::1]:443", "[2001:db8::1]:443", "2001:db8::1", false},
		{"IP-only permit keeps SNI, dials IP", ipOnly, "evil.example", "203.0.113.10:443", "203.0.113.10:443", "evil.example", false},
		{"name permit dials name", named, "api.example", "198.51.100.7:443", "api.example:443", "api.example", true},
		{"IP-bound name rule dials IP", boundName, "api.example", "203.0.113.10:443", "203.0.113.10:443", "api.example", false},
		{"no checker dials name", nil, "api.example", "203.0.113.10:443", "api.example:443", "api.example", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := &MITMProxy{}
			if tc.checker != nil {
				p.SetPolicyChecker(tc.checker)
			}
			host, port, err := net.SplitHostPort(tc.dest)
			if err != nil {
				t.Fatal(err)
			}
			got := p.selectTLSUpstream(tc.sni, tc.dest, host, port, 443)
			if got.addr != tc.wantAddr || got.serverName != tc.wantServer || got.byName != tc.wantByName {
				t.Fatalf("got %+v, want addr=%q serverName=%q byName=%v", got, tc.wantAddr, tc.wantServer, tc.wantByName)
			}
		})
	}
}
