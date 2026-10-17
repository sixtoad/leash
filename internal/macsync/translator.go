package macsync

import (
	"bytes"
	"sort"
	"strings"

	"github.com/google/uuid"

	"github.com/strongdm/leash/internal/lsm"
	"github.com/strongdm/leash/internal/messages"
)

// ConvertPolicyToMacRules converts the Linux-oriented policy set into the macOS
// policy structures understood by the Endpoint Security and Network Extension shims.
func ConvertPolicyToMacRules(policy *lsm.PolicySet) ([]messages.MacPolicyRule, []messages.MacNetworkRule) {
	if policy == nil {
		return nil, nil
	}

	var macRules []messages.MacPolicyRule
	var networkRules []messages.MacNetworkRule

	for _, rule := range policy.Exec {
		action := actionString(rule.Action)
		if action == "" {
			continue
		}
		path := pathString(&rule)
		if path == "" {
			continue
		}
		// A directory-scoped exec rule (e.g. Cedar Dir::"/") must match by executable
		// path PREFIX, not exact path — otherwise "allow /" matches nothing and, under
		// default-deny, every exec is killed. Carry it as Directory (with a wildcard
		// executable) exactly like the file-open rules do; a File:: rule stays exact.
		macRule := messages.MacPolicyRule{
			ID:     uuid.NewString(),
			Kind:   "processExec",
			Action: action,
		}
		if rule.IsDirectory == 1 {
			macRule.ExecutablePath = "*"
			macRule.Directory = path
		} else {
			macRule.ExecutablePath = path
		}
		macRules = append(macRules, macRule)
	}

	for _, rule := range policy.Open {
		if rule.Operation == lsm.OpMutation {
			continue // the Linux directory-mutation table; ES derives creates from the open rules
		}
		action := actionString(rule.Action)
		if action == "" {
			continue
		}
		path := pathString(&rule)
		// `pathString` returns rule path; ensure not empty
		if path == "" {
			continue
		}
		coversCreates := rule.Operation == lsm.OpOpenRW
		macRule := messages.MacPolicyRule{
			ID:             uuid.NewString(),
			Kind:           "fileAccess",
			Action:         action,
			ExecutablePath: "*",
			CoversCreates:  coversCreates,
		}
		if rule.IsDirectory == 1 {
			macRule.Directory = path
		} else {
			macRule.FilePath = path
		}
		macRules = append(macRules, macRule)
	}

	for _, rule := range policy.Connect {
		// Host::"*" is the connect default (PolicySet.ConnectDefaultAllow),
		// not a rule; deny-first ordering must not turn it into one (#135).
		if lsm.IsConnectDefaultRule(rule) {
			continue
		}
		action := actionString(rule.Action)
		if action == "" {
			continue
		}
		targetType, targetValue := networkTarget(&rule)
		if targetType == "" || targetValue == "" {
			continue
		}
		networkRules = append(networkRules, messages.MacNetworkRule{
			ID:          uuid.NewString(),
			TargetType:  targetType,
			TargetValue: targetValue,
			Action:      action,
			Enabled:     true,
		})
	}

	macRules = append(macRules, firmlinkVariants(macRules)...)

	// The Network Extension filter returns the first matching rule, so every
	// deny goes first: a matching forbid always wins, whatever the input order
	// (#135). File/exec rules are re-sorted by the ES extension
	// (ruleSortComparator), which already ranks deny before allow.
	sort.SliceStable(networkRules, func(i, j int) bool {
		return networkRules[i].Action == "deny" && networkRules[j].Action != "deny"
	})

	return macRules, networkRules
}

// macOS presents firmlinked system directories to Endpoint Security by their
// canonical /private path (/etc -> /private/etc, /tmp -> /private/tmp,
// /var -> /private/var), but Cedar policies are written with the short form.
// For every file/exec rule whose Directory or FilePath is under a firmlink, emit
// an equivalent rule with the /private prefix so it matches the path ES reports.
func firmlinkVariants(rules []messages.MacPolicyRule) []messages.MacPolicyRule {
	var extra []messages.MacPolicyRule
	for _, r := range rules {
		if pv, ok := privatePath(r.Directory); ok {
			v := r
			v.ID = uuid.NewString()
			v.Directory = pv
			extra = append(extra, v)
		}
		if pv, ok := privatePath(r.FilePath); ok {
			v := r
			v.ID = uuid.NewString()
			v.FilePath = pv
			extra = append(extra, v)
		}
	}
	return extra
}

// privatePath returns the /private-prefixed form of a path that lives under a
// macOS firmlink (/etc, /tmp, /var), and false otherwise.
func privatePath(path string) (string, bool) {
	if path == "" {
		return "", false
	}
	for _, fl := range []string{"/etc", "/tmp", "/var"} {
		if path == fl || strings.HasPrefix(path, fl+"/") {
			return "/private" + path, true
		}
	}
	return "", false
}

func actionString(action int32) string {
	switch action {
	case lsm.PolicyAllow:
		return "allow"
	case lsm.PolicyDeny:
		return "deny"
	default:
		return ""
	}
}

func pathString(rule *lsm.PolicyRule) string {
	if rule == nil || rule.PathLen <= 0 {
		return ""
	}
	path := bytes.TrimRight(rule.Path[:rule.PathLen], "\x00")
	return string(path)
}

func networkTarget(rule *lsm.PolicyRule) (string, string) {
	if rule == nil {
		return "", ""
	}
	if rule.HostnameLen > 0 {
		host := bytes.TrimRight(rule.Hostname[:rule.HostnameLen], "\x00")
		value := strings.TrimSpace(string(host))
		if value == "" {
			return "", ""
		}
		if strings.Contains(value, "/") {
			return "ipRange", value
		}
		return "domain", value
	}
	if ip := lsm.ConnectRuleAddr(rule.DestIP, rule.DestIP6); ip != "" {
		return "ipAddress", ip
	}
	return "", ""
}
