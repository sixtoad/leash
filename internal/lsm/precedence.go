package lsm

import (
	"bytes"
	"sort"
)

// Rule precedence (#135).
//
// Every matcher in this package (the BPF scans, the compiled file-open index
// and the userspace proxy checker) takes the first matching rule. The front
// ends do not guarantee an order (the Cedar parser used to iterate a Go map),
// so the order is fixed here, and the matchers follow it whatever order they
// were given:
//
//   - file open and exec: longest path first; for equal length a deny comes
//     before an allow, so forbid overrides permit at equal specificity. Two
//     rules of equal length can only match the same path if their path bytes
//     are identical.
//   - connect and MCP: there is no specificity order, so every deny comes
//     before every allow: any matching forbid wins, as in Cedar.
//
// Ties left after that are broken on the remaining fields so that the same
// set of rules always produces the same order, and so the same kernel state.

func denyFirst(a, b uint32) (less, decided bool) {
	if a == b {
		return false, false
	}
	return a == PolicyDeny, true
}

// sortOpenRulesByPrecedence orders file-open rules in place.
func sortOpenRulesByPrecedence(rules []OpenPolicyRule) {
	sort.SliceStable(rules, func(i, j int) bool {
		a, b := &rules[i], &rules[j]
		if a.PathLen != b.PathLen {
			return a.PathLen > b.PathLen
		}
		if less, ok := denyFirst(a.Action, b.Action); ok {
			return less
		}
		if c := bytes.Compare(a.Path[:a.PathLen], b.Path[:b.PathLen]); c != 0 {
			return c < 0
		}
		if a.Operation != b.Operation {
			return a.Operation < b.Operation
		}
		return a.IsDirectory < b.IsDirectory
	})
}

// sortExecRulesByPrecedence orders exec rules in place. A deny rule with
// arguments only denies when an argument matches and otherwise falls through,
// so placing it before an allow of the same path keeps it reachable.
func sortExecRulesByPrecedence(rules []ExecPolicyRule) {
	sort.SliceStable(rules, func(i, j int) bool {
		a, b := &rules[i], &rules[j]
		if a.PathLen != b.PathLen {
			return a.PathLen > b.PathLen
		}
		if less, ok := denyFirst(uint32(a.Action), uint32(b.Action)); ok {
			return less
		}
		if c := bytes.Compare(a.Path[:], b.Path[:]); c != 0 {
			return c < 0
		}
		if a.ArgCount != b.ArgCount {
			return a.ArgCount < b.ArgCount
		}
		for k := range a.Args {
			if c := bytes.Compare(a.Args[k][:], b.Args[k][:]); c != 0 {
				return c < 0
			}
		}
		if a.HasWildcard != b.HasWildcard {
			return a.HasWildcard < b.HasWildcard
		}
		return a.IsDirectory < b.IsDirectory
	})
}

// sortConnectBPFRulesByPrecedence orders kernel connect rules in place: denies
// first, then by port and IP.
func sortConnectBPFRulesByPrecedence(rules []ConnectPolicyRuleBPF) {
	sort.SliceStable(rules, func(i, j int) bool {
		a, b := &rules[i], &rules[j]
		if less, ok := denyFirst(a.Action, b.Action); ok {
			return less
		}
		if a.DestPort != b.DestPort {
			return a.DestPort < b.DestPort
		}
		if a.DestIP != b.DestIP {
			return a.DestIP < b.DestIP
		}
		return a.Operation < b.Operation
	})
}

// IsConnectDefaultRule reports whether rule is the bare Host::"*" connect rule
// (no IP, no port). Leash writes the connect default as
// `permit|forbid ... resource == Host::"*"` and applyConnectDefaults turns it
// into PolicySet.ConnectDefaultAllow/Explicit; the rule itself stays in
// PolicySet.Connect. It is the default, not a matching rule: ordered first, a
// default-deny would otherwise shadow every permit (#135).
func IsConnectDefaultRule(rule PolicyRule) bool {
	return isConnectDefault(rule.DestIP, rule.DestPort, rule.Hostname[:], rule.HostnameLen)
}

func isConnectDefault(ip uint32, port uint16, hostname []byte, hostnameLen int32) bool {
	return ip == 0 && port == 0 && hostnameLen == 1 && hostname[0] == '*'
}

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
