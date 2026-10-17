package lsm

import (
	"bytes"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
)

// legacyModel states the legacy (#138) decision semantics of a PolicySet in
// plain Go, as one userspace function per rule kind. It is a test oracle
// only (no production code decides with it, #142):
//
//   - the parity tests below pin it to the kernel loaders' compiled state
//     (OpenLsm/ExecLsm/ConnectLsm.LoadPolicies and the BPF lookup models),
//     so it is the kernel's semantics for the IR;
//   - the equivalence test (legacy_equivalence_test.go) checks that strict
//     Cedar, cedar.Authorize over transpiler.RewriteLegacy's output, decides
//     exactly like it.
//
// Connect hostnames compare case-insensitively and wildcards need a label
// boundary (*.example.com does not match evilexample.com): the
// fix/proxy-wildcard-label-boundary fix of the proxy checker.
type legacyModel struct {
	open        []OpenPolicyRule
	openDefault bool

	exec        []ExecPolicyRule
	execDefault bool

	connect        []ConnectPolicyRule
	connectDefault bool

	mcp []MCPPolicyRule
}

func newLegacyModel(policies *PolicySet) *legacyModel {
	m := &legacyModel{}
	if policies == nil {
		return m
	}
	m.open = ConvertToFileOpenRules(policies.Open)
	sortOpenRulesByPrecedence(m.open)
	m.openDefault = rootPathPolicy(m.open)

	m.exec = ConvertToExecRules(policies.Exec)
	sortExecRulesByPrecedence(m.exec)
	m.execDefault = legacyExecRootPathPolicy(m.exec)

	m.connect = connectRulesByPrecedence(ConvertToConnectRules(policies.Connect))
	m.connectDefault = policies.ConnectDefaultAllow

	m.mcp = normalizeMCPRules(policies.MCP)
	return m
}

// newLegacyChecker is the legacy model of the proxy checker (connect and
// MCP), the matcher SimplePolicyChecker implemented before #142.
func newLegacyChecker(rules []ConnectPolicyRule, defaultAllow bool, mcp []MCPPolicyRule) *legacyModel {
	return &legacyModel{connect: connectRulesByPrecedence(rules), connectDefault: defaultAllow, mcp: normalizeMCPRules(mcp)}
}

func (m *legacyModel) CheckConnect(hostname, ip string, port uint16) bool {
	return m.connectAllowed(hostname, ip, port)
}

func (m *legacyModel) CheckMCPCall(server, tool string) bool { return m.mcpAllowed(server, tool) }

// openAllowed: first match in precedence order (longest path, deny first at
// equal length); a rule matches every path its bytes prefix, a directory
// rule also the directory itself.
func (m *legacyModel) openAllowed(path string, operation uint32) bool {
	for i := range m.open {
		rule := &m.open[i]
		if rule.Operation != OpOpen && rule.Operation != operation {
			continue
		}
		if legacyOpenRuleMatches(rule, path) {
			return rule.Action == PolicyAllow
		}
	}
	return m.openDefault
}

func legacyOpenRuleMatches(rule *OpenPolicyRule, path string) bool {
	length := int(rule.PathLen)
	if length <= 0 {
		return false
	}
	rulePath := rule.Path[:length]
	if len(path) >= length && path[:length] == string(rulePath) {
		return true
	}
	return rule.IsDirectory != 0 && length > 1 && rulePath[length-1] == '/' &&
		len(path) == length-1 && path == string(rulePath[:length-1])
}

// execAllowed: check_exec_policy. A deny rule with arguments denies only
// when one of its arguments is present; an allow rule with arguments never
// matches.
func (m *legacyModel) execAllowed(path string, args []string) bool {
	for i := range m.exec {
		rule := &m.exec[i]
		if rule.PathLen <= 0 || !strings.HasPrefix(path, string(rule.Path[:rule.PathLen])) {
			continue
		}
		if rule.ArgCount == 0 {
			return rule.Action == PolicyAllow
		}
		if rule.Action != PolicyDeny {
			continue
		}
		for p := int32(0); p < rule.ArgCount && p < int32(len(rule.Args)); p++ {
			want := string(rule.Args[p][:rule.ArgLens[p]])
			for _, a := range args {
				if a == want {
					return false
				}
			}
		}
	}
	return m.execDefault
}

func legacyExecRootPathPolicy(rules []ExecPolicyRule) bool {
	for i := range rules {
		if rules[i].Action == PolicyAllow && rules[i].PathLen == 1 && rules[i].Path[0] == '/' {
			return true
		}
	}
	return false
}

// connectAllowed: every deny before every allow, first match, else the
// connect default.
func (m *legacyModel) connectAllowed(hostname, ip string, port uint16) bool {
	var ipNum uint32
	var ip6 [16]byte
	if addr := net.ParseIP(ip); addr != nil {
		var ok bool
		if ipNum, ok = canonicalIPv4(addr); !ok {
			copy(ip6[:], addr.To16())
		}
	}
	host := strings.ToLower(strings.TrimSuffix(hostname, "."))
	for i := range m.connect {
		rule := &m.connect[i]
		if rule.DestIP6 != ([16]byte{}) {
			if rule.DestIP6 != ip6 {
				continue
			}
		} else if rule.DestIP != 0 && rule.DestIP != ipNum {
			continue
		}
		if rule.DestPort != 0 && rule.DestPort != port {
			continue
		}
		if rule.HostnameLen > 0 && !legacyHostMatches(rule, host) {
			continue
		}
		return rule.Action == PolicyAllow
	}
	return m.connectDefault
}

func legacyHostMatches(rule *ConnectPolicyRule, host string) bool {
	ruleHost := strings.ToLower(string(bytes.TrimRight(rule.Hostname[:rule.HostnameLen], "\x00")))
	if ruleHost == "*" {
		return true
	}
	if rule.IsWildcard == 1 && strings.HasPrefix(ruleHost, "*.") {
		suffix := ruleHost[1:]
		return len(host) > len(suffix) && strings.HasSuffix(host, suffix)
	}
	return host == ruleHost
}

// mcpAllowed: denies first, first match, default allow.
func (m *legacyModel) mcpAllowed(server, tool string) bool {
	host := normalizeServer(server)
	toolName := strings.ToLower(strings.TrimSpace(tool))
	for _, rule := range m.mcp {
		if rule.Server != "" && host != rule.Server {
			continue
		}
		if rule.Tool != "" && toolName != rule.Tool {
			continue
		}
		return rule.Action == PolicyAllow
	}
	return true
}

// The legacy proxy checker's rule normalization and precedence, kept with
// the model (production decides with the engine, #142).

// connectRulesByPrecedence returns a copy of userspace connect rules with
// every deny before every allow, keeping the given order otherwise. The
// Host::"*" default rule is dropped; the caller passes the default separately.
func connectRulesByPrecedence(rules []ConnectPolicyRule) []ConnectPolicyRule {
	out := make([]ConnectPolicyRule, 0, len(rules))
	for _, r := range rules {
		if !isConnectDefault(r.DestIP, r.DestPort, r.Hostname[:], r.HostnameLen) {
			out = append(out, r)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		less, _ := denyFirst(uint32(out[i].Action), uint32(out[j].Action))
		return less
	})
	return out
}

// mcpRulesByPrecedence orders MCP rules in place with every deny before every
// allow, keeping the given order otherwise.
func mcpRulesByPrecedence(rules []MCPPolicyRule) {
	sort.SliceStable(rules, func(i, j int) bool {
		less, _ := denyFirst(uint32(rules[i].Action), uint32(rules[j].Action))
		return less
	})
}

func normalizeMCPRules(rules []MCPPolicyRule) []MCPPolicyRule {
	if len(rules) == 0 {
		return nil
	}
	out := make([]MCPPolicyRule, 0, len(rules))
	seen := make(map[string]struct{})
	for _, rule := range rules {
		server := normalizeServer(rule.Server)
		tool := strings.ToLower(strings.TrimSpace(rule.Tool))
		key := fmt.Sprintf("%d|%s|%s", rule.Action, server, tool)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, MCPPolicyRule{
			Action: rule.Action,
			Server: server,
			Tool:   tool,
		})
	}
	// CheckMCPCall takes the first match; denies first (#135).
	mcpRulesByPrecedence(out)
	return out
}

func normalizeServer(server string) string {
	s := strings.TrimSpace(server)
	if s == "" {
		return ""
	}
	s = strings.ToLower(s)
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil {
			if host := u.Hostname(); host != "" {
				s = host
			}
		}
	}
	if strings.Contains(s, "/") {
		s = strings.SplitN(s, "/", 2)[0]
	}
	if host, _, err := net.SplitHostPort(s); err == nil && host != "" {
		s = host
	}
	return strings.TrimSpace(s)
}
