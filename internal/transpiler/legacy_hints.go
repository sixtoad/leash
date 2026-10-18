package transpiler

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/strongdm/leash/internal/engine"
)

// LintLegacySemantics is the lint code for an unmarked file that looks like
// it was written for the legacy dialect: strict Cedar is the default, so the
// file now decides differently than its author probably meant.
const LintLegacySemantics = "legacy_semantics_suspected"

const legacyHintSuggestion = "Unmarked files are strict Cedar. If this file was written for the legacy Leash dialect, run `leash policy migrate <file>` (same decisions, in strict Cedar) or mark it @leash_semantics(\"legacy\"). If it is meant as strict Cedar, mark it @leash_semantics(\"cedar\") to silence this warning."

var (
	hintPathRe = regexp.MustCompile(`\b(?:File|Dir|FilePrefix|Fs::Directory|Fs::File)::"([^"]*)"`)
	hintHostRe = regexp.MustCompile(`\b(?:Host|Net::Hostname|Net::DnsZone|Net::Endpoint)::"([^"]*)"`)
)

// legacyRelianceIssues warns when an unmarked file (strict Cedar by default)
// decides differently than the legacy dialect would read it: the signs of a
// file written before strict became the default (File:: used as a path
// prefix, a longer permit that beat a shorter forbid, `unless` read as
// `when`, MCP forbids that relied on the MCP default allow). It compares the
// two readings on requests built from the file's own entities and reports
// one example per kind of request. A file the legacy dialect cannot load is
// not a legacy file; only its `unless` clauses are reported.
func legacyRelianceIssues(text string, ps *CedarPolicySet) []LintIssue {
	if writtenForStrict(text, ps) {
		return nil
	}
	var issues []LintIssue
	hasMCPForbid, hasMCPPermit := false, false
	for _, p := range ps.Policies {
		if p.NativePolicy != nil {
			if sc, err := engine.ClassifyActions(p.NativePolicy); err == nil && len(sc.Namespaces) > 0 {
				continue // plugin policies always had Cedar semantics
			}
		}
		if containsActionID(p.Action, "McpCall") {
			if p.Effect == Permit {
				hasMCPPermit = true
			} else {
				hasMCPForbid = true
			}
		}
		for _, c := range p.Conditions {
			if c.Kind == "unless" {
				issues = append(issues, LintIssue{
					PolicyID: p.ID, Severity: LintWarning, Code: LintLegacySemantics,
					Message:    "`unless` is enforced as written in strict Cedar (an exception); the legacy dialect read it as `when`.",
					Suggestion: legacyHintSuggestion,
				})
				break
			}
		}
	}
	if hasMCPForbid && !hasMCPPermit {
		issues = append(issues, LintIssue{
			Severity: LintWarning, Code: LintLegacySemantics,
			Message:    "the file forbids some MCP calls but permits none: strict Cedar denies every MCP call no policy permits, while the legacy dialect allowed MCP by default.",
			Suggestion: legacyHintSuggestion,
		})
	}

	strictEng, err := engine.New(ps.NativePolicySet)
	if err != nil {
		return issues
	}
	rw, err := RewriteLegacy(RewriteOptions{}, LegacyLayer{Name: "policies", Policies: ps})
	if err != nil {
		return issues
	}
	legacyEng, err := engine.New(rw.Policies)
	if err != nil {
		return issues
	}
	verdict := func(allow bool) string {
		if allow {
			return "allow"
		}
		return "deny"
	}
	report := func(what string, legacy, strict bool) {
		issues = append(issues, LintIssue{
			Severity: LintWarning, Code: LintLegacySemantics,
			Message:    fmt.Sprintf("this unmarked file is read as strict Cedar and decides differently than the legacy dialect, e.g. %s: legacy %s, strict %s.", what, verdict(legacy), verdict(strict)),
			Suggestion: legacyHintSuggestion,
		})
	}

	paths := hintPaths(text)
	reported := map[string]bool{}
	for _, path := range paths {
		for _, action := range []string{engine.ActionFileOpenReadOnly, engine.ActionFileOpenReadWrite} {
			if reported["open"] {
				break
			}
			l, s := legacyEng.DecideOpen(path, action).Allow, strictEng.DecideOpen(path, action).Allow
			if l != s {
				reported["open"] = true
				report(fmt.Sprintf("%s %q", action, path), l, s)
			}
		}
		if !reported["exec"] {
			l, s := legacyEng.DecideExec(path).Allow, strictEng.DecideExec(path).Allow
			if l != s {
				reported["exec"] = true
				report(fmt.Sprintf("ProcessExec %q", path), l, s)
			}
		}
	}
	for _, h := range hintHosts(text) {
		if reported["connect"] {
			break
		}
		l, s := legacyEng.DecideConnect(h.name, h.ip, h.port).Allow, strictEng.DecideConnect(h.name, h.ip, h.port).Allow
		if l != s {
			reported["connect"] = true
			target := h.name
			if target == "" {
				target = h.ip
			}
			report(fmt.Sprintf("NetworkConnect %s:%d", target, h.port), l, s)
		}
	}
	return issues
}

// writtenForStrict reports a file whose author evidently wrote strict Cedar,
// so its legacy reading means nothing: `leash policy migrate` output, a
// strict-only entity type (FilePrefix), a legacy-rewrite annotation, or a
// condition the legacy dialect cannot read (`resource in E` without
// brackets, which the legacy parser sees as an empty resource list).
func writtenForStrict(text string, ps *CedarPolicySet) bool {
	if strings.HasPrefix(strings.TrimSpace(text), MigratedHeader) ||
		strings.Contains(text, "FilePrefix::") || strings.Contains(text, "@"+annotationRewrite) {
		return true
	}
	for _, p := range ps.Policies {
		for _, c := range p.Conditions {
			if c.Type == ConditionResourceIn && len(c.ResourceSet) == 0 {
				return true
			}
		}
	}
	return false
}

// hintPaths returns probe paths around every path literal: the path, its
// byte and directory extensions, the path without a trailing slash, and an
// unrelated path.
func hintPaths(text string) []string {
	set := map[string]bool{"/": true, "/leash-lint-unlisted": true}
	for _, m := range hintPathRe.FindAllStringSubmatch(text, -1) {
		p := m[1]
		if !strings.HasPrefix(p, "/") {
			continue
		}
		set[p] = true
		set[p+"x"] = true
		set[strings.TrimSuffix(p, "/")+"/x"] = true
		if t := strings.TrimSuffix(p, "/"); t != "" {
			set[t] = true
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

type hintHost struct {
	name, ip string
	port     uint16
}

// hintHosts returns probe connections for every host literal: the host (or
// a name inside a wildcard zone, and the zone apex), on the literal's port
// and on 443, plus an unrelated host.
func hintHosts(text string) []hintHost {
	type key = hintHost
	set := map[key]bool{{name: "leash-lint-unlisted.example", ip: "203.0.113.9", port: 443}: true}
	add := func(name string, port uint16) {
		if ip := net.ParseIP(strings.Trim(name, "[]")); ip != nil {
			set[key{ip: ip.String(), port: port}] = true
			return
		}
		set[key{name: name, ip: "203.0.113.9", port: port}] = true
	}
	for _, m := range hintHostRe.FindAllStringSubmatch(text, -1) {
		host, port := splitHostPortLoose(m[1])
		ports := []uint16{443}
		if n, err := strconv.ParseUint(port, 10, 16); err == nil && n != 0 {
			ports = append(ports, uint16(n))
		}
		var names []string
		switch {
		case host == "*" || host == "":
			names = []string{"leash-lint-unlisted.example"}
		case strings.HasPrefix(host, "*."):
			zone := strings.TrimPrefix(host, "*.")
			names = []string{"a." + zone, zone}
		default:
			names = []string{host, "a." + host}
		}
		for _, n := range names {
			for _, p := range ports {
				add(n, p)
			}
		}
	}
	out := make([]hintHost, 0, len(set))
	for h := range set {
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].name != out[j].name {
			return out[i].name < out[j].name
		}
		if out[i].ip != out[j].ip {
			return out[i].ip < out[j].ip
		}
		return out[i].port < out[j].port
	})
	return out
}
