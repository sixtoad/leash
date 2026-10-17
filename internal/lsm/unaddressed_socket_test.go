package lsm

import (
	"net"
	"testing"
)

// #188: packet, raw IP, XDP and SCTP sockets are decided once, at creation
// (lsm_socket_create), because no address rule can see where their traffic
// goes. They are allowed only when the policy restricts no destination.
func TestUnaddressedSocketsDecision(t *testing.T) {
	orig := lookupConnectHost
	t.Cleanup(func() { lookupConnectHost = orig })
	lookupConnectHost = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("192.0.2.7")}, nil }

	allowAll := func(rules ...PolicyRule) *PolicySet {
		return &PolicySet{ConnectDefaultExplicit: true, ConnectDefaultAllow: true, Connect: rules}
	}
	cases := []struct {
		name  string
		ps    *PolicySet
		allow bool
	}{
		{"no network policy (default deny)", &PolicySet{}, false},
		{"explicit default deny", &PolicySet{ConnectDefaultExplicit: true}, false},
		{"default deny with permits", &PolicySet{Connect: []PolicyRule{mustConnectRule(t, "allow net.send 10.0.0.1:443")}}, false},
		{"explicit default allow, no rules", allowAll(), true},
		{"default allow with permits only", allowAll(mustConnectRule(t, "allow net.send 10.0.0.1")), true},
		{"implicit default allow (allow net.send *)", &PolicySet{Connect: []PolicyRule{mustConnectRule(t, "allow net.send *")}}, true},
		{"default allow with an address forbid", allowAll(mustConnectRule(t, "deny net.send 169.254.169.254")), false},
		{"default allow with a port forbid", allowAll(mustConnectRule(t, "deny net.send *:25")), false},
		{"default allow with a hostname forbid", allowAll(mustConnectRule(t, "deny net.send evil.example.com")), false},
		{"default allow with a wildcard forbid (proxy only)", allowAll(mustConnectRule(t, "deny net.send *.example.com")), false},
		{"default allow with an MCP forbid", &PolicySet{ConnectDefaultExplicit: true, ConnectDefaultAllow: true,
			MCP: []MCPPolicyRule{{Action: PolicyDeny, Server: "mcp.example.com"}}}, false},
		{"default allow with an MCP permit only", &PolicySet{ConnectDefaultExplicit: true, ConnectDefaultAllow: true,
			MCP: []MCPPolicyRule{{Action: PolicyAllow, Server: "mcp.example.com"}}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, err := NewConnectLsm("/sys/fs/cgroup/leash-test", nil)
			if err != nil {
				t.Fatal(err)
			}
			l.proxyRestricted = proxyRestricts(tc.ps)
			if err := l.LoadPolicies(ConvertToConnectRules(tc.ps.Connect), connectDefaultOverride(tc.ps)); err != nil {
				t.Fatal(err)
			}
			maps := &fakeConnectMaps{rules: map[uint32]ConnectPolicyRuleBPF{}, unaddressed: 7}
			if err := l.writePolicyMaps(maps.lookup); err != nil {
				t.Fatal(err)
			}
			want := uint32(0)
			if tc.allow {
				want = 1
			}
			if maps.unaddressed != want {
				t.Fatalf("connect_unaddressed_policy = %d, want %d", maps.unaddressed, want)
			}
		})
	}
}

// A reload that adds a forbid retires a previous allow (the map is always
// rewritten, like the rule count).
func TestUnaddressedSocketsReload(t *testing.T) {
	l, err := NewConnectLsm("/sys/fs/cgroup/leash-test", nil)
	if err != nil {
		t.Fatal(err)
	}
	maps := &fakeConnectMaps{rules: map[uint32]ConnectPolicyRuleBPF{}}
	allowAll := &PolicySet{ConnectDefaultExplicit: true, ConnectDefaultAllow: true}
	if err := l.LoadPolicies(nil, connectDefaultOverride(allowAll)); err != nil {
		t.Fatal(err)
	}
	if err := l.writePolicyMaps(maps.lookup); err != nil || maps.unaddressed != 1 {
		t.Fatalf("setup: allow-all must allow unaddressed sockets (map=%d, err=%v)", maps.unaddressed, err)
	}
	withForbid := &PolicySet{ConnectDefaultExplicit: true, ConnectDefaultAllow: true, Connect: []PolicyRule{mustConnectRule(t, "deny net.send 10.0.0.9")}}
	if err := l.LoadPolicies(ConvertToConnectRules(withForbid.Connect), connectDefaultOverride(withForbid)); err != nil {
		t.Fatal(err)
	}
	if err := l.writePolicyMaps(maps.lookup); err != nil || maps.unaddressed != 0 {
		t.Fatalf("a reload adding a forbid must deny unaddressed sockets (map=%d, err=%v)", maps.unaddressed, err)
	}
}
