package lsm

import (
	"net"
	"strings"
	"testing"
)

// IPv6 egress (#182): the kernel connect tables carry IPv6 rules, an
// IPv4-mapped IPv6 destination is decided by the IPv4 rules, and the connect
// default applies to IPv6 like IPv4.

func ip6Bytes(s string) [16]byte {
	var b [16]byte
	copy(b[:], net.ParseIP(s).To16())
	return b
}

func TestParseRuleStringIPv6Targets(t *testing.T) {
	for _, tc := range []struct {
		line string
		v4   uint32
		v6   string
		port uint16
	}{
		{line: "allow net.send [2001:db8::1]:443", v6: "2001:db8::1", port: 443},
		{line: "deny net.send 2001:db8::1", v6: "2001:db8::1"},
		{line: "allow net.send [2001:DB8:0::1]", v6: "2001:db8::1"},
		{line: "allow net.send [::ffff:192.168.1.1]:443", v4: asymmetricIPv4, port: 443},
		{line: "allow net.send ::ffff:192.168.1.1", v4: asymmetricIPv4},
	} {
		rule, err := ParseRuleString(tc.line)
		if err != nil {
			t.Fatalf("%q: %v", tc.line, err)
		}
		var wantV6 [16]byte
		if tc.v6 != "" {
			wantV6 = ip6Bytes(tc.v6)
		}
		if rule.DestIP != tc.v4 || rule.DestIP6 != wantV6 || rule.DestPort != tc.port || rule.HostnameLen != 0 {
			t.Fatalf("%q: got ip=%#x ip6=%v port=%d hostlen=%d", tc.line, rule.DestIP, net.IP(rule.DestIP6[:]), rule.DestPort, rule.HostnameLen)
		}
	}
	for _, bad := range []string{
		"allow net.send [2001:db8::1",       // unterminated
		"allow net.send [2001:db8::1]443",   // no colon before the port
		"allow net.send [2001:db8::1]:0",    // port out of range
		"allow net.send [192.168.1.1]:443",  // brackets around IPv4
		"allow net.send [example.com]:443",  // brackets around a name
		"allow net.send ::",                 // unspecified address
		"allow net.send example.com:443:80", // not an IPv6 literal
	} {
		if _, err := ParseRuleString(bad); err == nil {
			t.Errorf("%q parsed; want an error", bad)
		}
	}
}

func TestConnectRuleStringRendersIPv6(t *testing.T) {
	rule, err := ParseRuleString("allow net.send [2001:db8::1]:443")
	if err != nil {
		t.Fatal(err)
	}
	if got := rule.String(); got != "allow net.send [2001:db8::1]:443" {
		t.Fatalf("String() = %q", got)
	}
	cr := ConvertToConnectRules([]PolicyRule{*rule})[0]
	if got := cr.String(); !strings.Contains(got, "dest_ip=2001:db8::1") {
		t.Fatalf("ConnectPolicyRule.String() = %q", got)
	}
}

// anyPort8443 is the kernel form of Host::"*:8443" (connectRuleFor): an
// address-less rule with a port.
const anyPort8443 = "any:8443"

func loadConnectForTest(t *testing.T, defaultAllow bool, lines ...string) *ConnectLsm {
	t.Helper()
	var rules []PolicyRule
	for _, line := range lines {
		if line == anyPort8443 {
			rules = append(rules, PolicyRule{Action: PolicyAllow, Operation: OpConnect, DestPort: 8443})
			continue
		}
		r, err := ParseRuleString(line)
		if err != nil {
			t.Fatalf("%q: %v", line, err)
		}
		rules = append(rules, *r)
	}
	l := &ConnectLsm{}
	if err := l.LoadPolicies(ConvertToConnectRules(rules), &defaultAllow); err != nil {
		t.Fatal(err)
	}
	return l
}

func kernelConnectForTest(l *ConnectLsm, ip string, port uint16) bool {
	return connectBPFDecisionDest(l.policyRules, l.defaultPolicyResult, connectDestOf(net.ParseIP(ip), port)) == PolicyAllow
}

func TestConnectKernelEnforcesIPv6Rules(t *testing.T) {
	l := loadConnectForTest(t, false,
		"allow net.send [2001:db8::1]:443",
		"deny net.send 2001:db8::2",
		"allow net.send 192.168.1.1:443",
		anyPort8443,
	)
	for _, r := range l.policyRules {
		if r.DestIP6 != ([16]byte{}) && r.Family != afInet6 {
			t.Fatalf("IPv6 rule loaded with family %d: %+v", r.Family, r)
		}
		if r.DestIP != 0 && r.Family != afInet {
			t.Fatalf("IPv4 rule loaded with family %d: %+v", r.Family, r)
		}
	}
	for _, tc := range []struct {
		ip   string
		port uint16
		want bool
	}{
		{"2001:db8::1", 443, true},
		{"2001:db8::1", 80, false},        // wrong port
		{"2001:db8::3", 443, false},       // default deny applies to IPv6
		{"2001:db8::2", 8443, false},      // forbid beats the any-address permit
		{"2001:db8::9", 8443, true},       // an any-address rule covers IPv6
		{"192.168.1.1", 443, true},        // IPv4 unchanged
		{"::ffff:192.168.1.1", 443, true}, // IPv4-mapped: the IPv4 rule decides
		{"::ffff:192.168.1.1", 80, false}, // ... and the IPv4 default
		{"::ffff:192.168.1.2", 443, false},
		{"::192.168.1.1", 443, false}, // IPv4-compatible (deprecated) is IPv6, not mapped
	} {
		if got := kernelConnectForTest(l, tc.ip, tc.port); got != tc.want {
			t.Errorf("connect [%s]:%d = %v, want %v (rules %v)", tc.ip, tc.port, got, tc.want, l.policyRules)
		}
	}
}

func TestConnectKernelIPv6DefaultAllow(t *testing.T) {
	l := loadConnectForTest(t, true, "deny net.send [2001:db8::1]:22")
	if kernelConnectForTest(l, "2001:db8::1", 22) {
		t.Fatal("IPv6 deny rule did not apply under default allow")
	}
	if !kernelConnectForTest(l, "2001:db8::1", 443) || !kernelConnectForTest(l, "2001:db8::5", 22) {
		t.Fatal("default allow did not apply to IPv6")
	}
}

func TestConnectHostnameRuleResolvesAAndAAAA(t *testing.T) {
	orig := lookupConnectHost
	t.Cleanup(func() { lookupConnectHost = orig })
	lookupConnectHost = func(host string) ([]net.IP, error) {
		if host != "dual.example" {
			t.Fatalf("unexpected lookup %q", host)
		}
		return []net.IP{net.ParseIP("192.168.1.1"), net.ParseIP("2001:db8::10"), net.ParseIP("::")}, nil
	}
	l := loadConnectForTest(t, false, "allow net.send dual.example:443")
	if len(l.policyRules) != 2 {
		t.Fatalf("rules = %d, want 2 (A + AAAA; the unspecified address is skipped): %+v", len(l.policyRules), l.policyRules)
	}
	for _, tc := range []struct {
		ip   string
		port uint16
		want bool
	}{
		{"192.168.1.1", 443, true},
		{"2001:db8::10", 443, true},
		{"::ffff:192.168.1.1", 443, true},
		{"2001:db8::10", 80, false},
		{"2001:db8::11", 443, false},
		{"::", 443, false},
	} {
		if got := kernelConnectForTest(l, tc.ip, tc.port); got != tc.want {
			t.Errorf("connect [%s]:%d = %v, want %v", tc.ip, tc.port, got, tc.want)
		}
	}
}

func TestSplitConnectTarget(t *testing.T) {
	for _, tc := range []struct {
		in, host string
		port     uint16
	}{
		{"example.com", "example.com", 0},
		{"example.com:443", "example.com", 443},
		{"10.0.0.1:22", "10.0.0.1", 22},
		{"2001:db8::1", "2001:db8::1", 0},
		{"[2001:db8::1]", "2001:db8::1", 0},
		{"[2001:db8::1]:443", "2001:db8::1", 443},
	} {
		host, port, err := SplitConnectTarget(tc.in)
		if err != nil || host != tc.host || port != tc.port {
			t.Errorf("SplitConnectTarget(%q) = %q, %d, %v; want %q, %d", tc.in, host, port, err, tc.host, tc.port)
		}
	}
	if got := JoinConnectTarget("2001:db8::1", 443); got != "[2001:db8::1]:443" {
		t.Errorf("JoinConnectTarget = %q", got)
	}
	if got := JoinConnectTarget("10.0.0.1", 0); got != "10.0.0.1" {
		t.Errorf("JoinConnectTarget = %q", got)
	}
}
