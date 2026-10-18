package lsm_test

import (
	"net"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	cedarlib "github.com/cedar-policy/cedar-go"

	"github.com/strongdm/leash/internal/engine"
	"github.com/strongdm/leash/internal/lsm"
	"github.com/strongdm/leash/internal/policy"
	"github.com/strongdm/leash/internal/transpiler"
)

// Strict Cedar is the default dialect: every policy Leash ships (the
// bootstrap policy, the release-gate Walk policy, the documented example)
// was migrated from the legacy dialect with `leash policy migrate`. Each
// pair below is the legacy original (kept as an explicit
// @leash_semantics("legacy") fixture) and the shipped strict text; the
// equivalence harness's legacy model over the original must decide exactly
// like cedar.Authorize over the strict text, on requests built from both
// files' entities.
func TestMigratedBuiltInPoliciesKeepTheirDecisions(t *testing.T) {
	read := func(path string) string {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	cases := []struct {
		name, legacy, strict string
		// migrated: the strict text is migrate's own output (comments
		// aside), not a hand-written equivalent.
		migrated bool
	}{
		{"default", read("testdata/default.legacy.cedar"), policy.DefaultCedarPolicy, true},
		{"walk33", read("testdata/walk33-combined.legacy.cedar"), read("../../e2e/testdata/walk33-combined.cedar"), true},
		{"cedar-md-example", read("testdata/cedar-md-example.legacy.cedar"), read("testdata/cedar-md-example.cedar"), false},
	}
	// The document shows the checked strict example verbatim.
	if doc := read("../../docs/design/CEDAR.md"); !strings.Contains(doc, cases[2].strict) {
		t.Fatal("docs/design/CEDAR.md must show testdata/cedar-md-example.cedar verbatim")
	}
	tr := transpiler.NewCedarToLeashTranspiler()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.migrated {
				out, _, already, err := transpiler.MigrateText(tc.name+".cedar", tc.legacy)
				if err != nil || already {
					t.Fatalf("migrate: %v already=%v", err, already)
				}
				if policiesOnly(out) != policiesOnly(tc.strict) {
					t.Fatalf("the shipped strict text is not migrate's output:\n%s\nwant:\n%s", tc.strict, out)
				}
			}
			strictSet, err := cedarlib.NewPolicySetFromBytes(tc.name+".cedar", []byte(tc.strict))
			if err != nil {
				t.Fatal(err)
			}
			if sem, err := transpiler.DetectSemantics(strictSet); err != nil || sem != transpiler.SemanticsCedar {
				t.Fatalf("the shipped text must be strict: %v %v", sem, err)
			}
			eng, err := engine.New(strictSet)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := transpiler.CompileKernel(strictSet, eng); err != nil {
				t.Fatalf("the kernel must enforce the shipped text: %v", err)
			}
			legacyIR, _, err := tr.TranspileFromString(tc.legacy)
			if err != nil {
				t.Fatal(err)
			}
			legacy := lsm.NewLegacyModelForTest(legacyIR)
			text := tc.legacy + "\n" + tc.strict
			decisions := 0
			for _, path := range builtinProbePaths(text) {
				for _, m := range []struct {
					op     uint32
					action string
				}{{lsm.OpOpenRO, engine.ActionFileOpenReadOnly}, {lsm.OpOpenRW, engine.ActionFileOpenReadWrite}} {
					decisions++
					if want, got := legacy.Open(path, m.op), eng.DecideOpen(path, m.action); got.Allow != want {
						t.Errorf("open %s %q: legacy %v, strict %+v", m.action, path, want, got)
					}
				}
				decisions++
				if want, got := legacy.Exec(path), eng.DecideExec(path); got.Allow != want {
					t.Errorf("exec %q: legacy %v, strict %+v", path, want, got)
				}
			}
			hosts, ips := builtinProbeHosts(text)
			for _, h := range hosts {
				for _, ip := range ips {
					for _, port := range []uint16{0, 22, 443, 5432} {
						if h == "" && ip == "" {
							continue
						}
						decisions++
						if want, got := legacy.Connect(h, ip, port), eng.DecideConnect(h, ip, port); got.Allow != want {
							t.Errorf("connect %q %q %d: legacy %v, strict %+v", h, ip, port, want, got)
						}
					}
				}
			}
			for _, server := range append(builtinProbeLiterals(text, `MCP::Server::"([^"]*)"`), "other.example", "") {
				for _, tool := range append(builtinProbeLiterals(text, `MCP::Tool::"([^"]*)"`), "search", "") {
					decisions++
					if want, got := legacy.MCP(server, tool), eng.DecideMCP(server, tool); got.Allow != want {
						t.Errorf("mcp %q %q: legacy %v, strict %+v", server, tool, want, got)
					}
				}
			}
			t.Logf("%d decisions: legacy == strict", decisions)
		})
	}
}

// policiesOnly drops comment lines and blank lines.
func policiesOnly(text string) string {
	var out []string
	for _, l := range strings.Split(text, "\n") {
		if t := strings.TrimSpace(l); t == "" || strings.HasPrefix(t, "//") {
			continue
		}
		out = append(out, strings.TrimRight(l, " "))
	}
	return strings.Join(out, "\n")
}

func builtinProbeLiterals(text, re string) []string {
	set := map[string]bool{}
	for _, m := range regexp.MustCompile(re).FindAllStringSubmatch(text, -1) {
		set[m[1]] = true
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// builtinProbePaths: every path literal, its byte and directory extensions,
// the path without its trailing slash and its parent, plus unrelated paths.
func builtinProbePaths(text string) []string {
	set := map[string]bool{"/": true, "/unlisted": true, "/unlisted/x": true}
	for _, p := range builtinProbeLiterals(text, `(?:File|Dir|FilePrefix)::"([^"]*)"`) {
		if !strings.HasPrefix(p, "/") {
			continue
		}
		t := strings.TrimSuffix(p, "/")
		for _, q := range []string{p, p + "x", t + "/x", t + "/x/y", t} {
			if q != "" {
				set[q] = true
			}
		}
		if i := strings.LastIndex(t, "/"); i > 0 {
			set[t[:i]] = true
			set[t[:i]+"/"] = true
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// builtinProbeHosts: every host name literal without its port, a name inside
// each wildcard zone and the zone apex, a lookalike, and an unrelated name;
// and every address literal plus unrelated addresses (an IP literal is an
// address, never a host name: AUTHZ-SERVICE.md 4.3 #21).
func builtinProbeHosts(text string) (hosts, ips []string) {
	set := map[string]bool{"": true, "unlisted.example": true}
	ipSet := map[string]bool{"": true, "203.0.113.9": true, "2001:db8::1": true}
	for _, h := range builtinProbeLiterals(text, `(?:Host|MCP::Server)::"([^"]*)"`) {
		if i := strings.LastIndex(h, ":"); i > 0 && !strings.Contains(h[:i], ":") {
			h = h[:i]
		}
		switch {
		case net.ParseIP(strings.Trim(h, "[]")) != nil:
			ipSet[net.ParseIP(strings.Trim(h, "[]")).String()] = true
		case h == "*":
		case strings.HasPrefix(h, "*."):
			zone := strings.TrimPrefix(h, "*.")
			set["a."+zone] = true
			set[zone] = true
			set["evil"+zone] = true
		default:
			set[h] = true
			set["a."+h] = true
		}
	}
	for h := range set {
		hosts = append(hosts, h)
	}
	for ip := range ipSet {
		ips = append(ips, ip)
	}
	sort.Strings(hosts)
	sort.Strings(ips)
	return hosts, ips
}
