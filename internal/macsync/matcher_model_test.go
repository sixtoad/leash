package macsync

import (
	"net"
	"strings"
)

// This file is a line-for-line Go model of the Swift matcher in
// mac-leash/Shared/PolicyCore/PolicyMatcher.swift. It is test-only on
// purpose: production decisions are Cedar's (internal/engine) and the
// kernel's/extensions' table lookups, never a second Go evaluator. The parity
// test drives this model with random strict policies and compares it with
// cedar.Authorize; the Swift unit tests replay the same vectors
// (testdata/parity-vectors.json) against the real Swift code.

func modelProtected(t *MacPolicyTables, path string) bool {
	for _, p := range t.Protected.Paths {
		if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}

func modelOpen(t *MacPolicyTables, rawPath string, write bool) bool {
	path := canonicalMacPath(rawPath)
	if modelProtected(t, path) {
		return false
	}
	op := "read"
	if write {
		op = "write"
	}
	var prefix, exact *MacFileEntry
	for i := range t.File.Prefix {
		e := &t.File.Prefix[i]
		if e.Op == op && strings.HasPrefix(path, e.Path) && (prefix == nil || len(e.Path) > len(prefix.Path)) {
			prefix = e
		}
	}
	for i := range t.File.Exact {
		e := &t.File.Exact[i]
		if e.Op == op && e.Path == path {
			exact = e
			break
		}
	}
	switch {
	case exact != nil && prefix == nil:
		return exact.Allow
	case exact != nil && exact.Specificity > prefix.Specificity:
		return exact.Allow
	case exact != nil && prefix.Specificity > exact.Specificity:
		return prefix.Allow
	case exact != nil && exact.Order <= prefix.Order:
		return exact.Allow
	case prefix != nil:
		return prefix.Allow
	}
	return t.File.DefaultAllow
}

func modelMutation(t *MacPolicyTables, rawPath string) bool {
	path := canonicalMacPath(rawPath)
	if modelProtected(t, path) {
		return false
	}
	for _, p := range t.Mutation.ExactDeny {
		if p == path {
			return false
		}
	}
	longest := func(ps []MacMutationPrefix) (uint32, bool) {
		best, spec, found := -1, uint32(0), false
		for _, p := range ps {
			if strings.HasPrefix(path, p.Path) && len(p.Path) > best {
				best, spec, found = len(p.Path), p.Specificity, true
			}
		}
		return spec, found
	}
	deny, _ := longest(t.Mutation.Deny)
	allow, ok := longest(t.Mutation.Allow)
	return ok && allow > deny
}

// modelLink is the hard-link guard: the source must be readable.
func modelLink(t *MacPolicyTables, source string) bool { return modelOpen(t, source, false) }

func modelExec(t *MacPolicyTables, rawPath string, args []string) bool {
	path := canonicalMacPath(rawPath)
	if modelProtected(t, path) {
		return false
	}
	for _, r := range t.Exec.Rules {
		match := strings.HasPrefix(path, r.Path)
		if r.Exact {
			match = path == r.Path
		}
		if !match {
			continue
		}
		if len(r.Args) == 0 {
			return r.Allow
		}
		for _, want := range r.Args {
			for _, a := range args {
				if a == want {
					return false
				}
			}
		}
	}
	return t.Exec.DefaultAllow
}

func modelConnect(t *MacPolicyTables, ipText string, port uint16) bool {
	ip := net.ParseIP(ipText)
	if ip == nil {
		return false
	}
	family := 6
	if v4 := ip.To4(); v4 != nil {
		family, ip = 4, v4
	}
	for _, p := range t.Protected.Ports {
		if p == port && (ip.IsLoopback() || ip.IsUnspecified()) {
			return false
		}
	}
	for _, r := range t.Network.Rules {
		if r.Family != 0 {
			if r.Family != family || !net.ParseIP(r.IP).Equal(ip) {
				continue
			}
		}
		if r.Port != 0 && r.Port != port {
			continue
		}
		return r.Allow
	}
	return t.Network.DefaultAllow
}

// modelConnectAnyAddress mirrors LeashPolicyMatcher.allowsConnectToAnyAddress.
func modelConnectAnyAddress(t *MacPolicyTables, port uint16) bool {
	for _, p := range t.Protected.Ports {
		if p == port {
			return false
		}
	}
	for _, r := range t.Network.Rules {
		if r.Port != 0 && r.Port != port {
			continue
		}
		if r.Family == 0 {
			return r.Allow
		}
		if !r.Allow {
			return false
		}
	}
	return t.Network.DefaultAllow
}
