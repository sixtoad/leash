package lsm_test

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/strongdm/leash/internal/engine"
	"github.com/strongdm/leash/internal/lsm"
	"github.com/strongdm/leash/internal/transpiler"
)

// Equivalence of the legacy rewrite (#142): for random legacy policy files
// and random requests, the legacy decision (the #138 transpiled-rule
// semantics, legacyModel over the legacy transpiler's IR) must equal
// cedar.Authorize over transpiler.RewriteLegacy's strict output, through the
// engine's entity hierarchy.

var (
	eqPathPool = []string{"/", "/a", "/a/", "/ab", "/a/b", "/a/b/", "/a/bc", "/a/b/c", "/a/b/c/", "/a/b/c/d", "/a/b/c/d/", "/x", "/x/", "/x/y/", "/etc/", "/etc/passwd", "/bin/rm", "/bin/rmdir", "/bin/", "relative"}
	eqHostPool = []string{`Host::"a.example.com"`, `Host::"*.example.com"`, `Host::"example.com"`, `Host::"*"`, `Host::"10.0.0.1"`, `Host::"10.0.0.2"`, `Host::"10.0.0.1:22"`, `Host::"*.com"`, `Host::"b.a.example.com:443"`, `Host::"*:443"`, `Host::"A.Example.com"`, `Net::DnsZone::"example.com"`, `Net::Hostname::"x.example.com"`, `Host::"0.0.0.0:22"`, `Host::"*.example.com:443"`, `Host::"example.com."`, `Host::"*."`, `Host::"a b.example.com"`, `Host::"x.example.com:0"`}
	eqServers  = []string{"mcp.example.com", "other.example.com", "mcp.example.com:8443"}
	eqTools    = []string{"search", "Execute-Shell", "delete"}
)

func pick[T any](rng *rand.Rand, xs []T) T { return xs[rng.Intn(len(xs))] }

func randomFileEntity(rng *rand.Rand) string {
	p := pick(rng, eqPathPool)
	if rng.Intn(2) == 0 {
		if rng.Intn(4) == 0 {
			p = strings.TrimSuffix(p, "/")
			if p == "" {
				p = "/"
			}
		}
		return fmt.Sprintf("Dir::%q", p)
	}
	return fmt.Sprintf("File::%q", p)
}

func resourceClause(rng *rand.Rand, entities []string) (head string, conds []string) {
	switch {
	case len(entities) == 1 && rng.Intn(3) == 0:
		return "resource == " + entities[0], nil
	case rng.Intn(6) == 0:
		// Legacy reads `unless { resource in [...] }` as `when`.
		return "resource", []string{"unless { resource in [" + strings.Join(entities, ", ") + "] }"}
	}
	return "resource", []string{"when { resource in [" + strings.Join(entities, ", ") + "] }"}
}

func randomLegacyPolicy(rng *rand.Rand) string {
	effect := pick(rng, []string{"permit", "forbid"})
	principal := "principal"
	if rng.Intn(8) == 0 {
		principal = `principal == User::"alice"`
	}
	var action string
	var entities []string
	switch kind := rng.Intn(10); {
	case kind < 5:
		acts := []string{}
		for _, a := range []string{"FileOpen", "FileOpenReadOnly", "FileOpenReadWrite"} {
			if rng.Intn(2) == 0 {
				acts = append(acts, fmt.Sprintf("Action::%q", a))
			}
		}
		if len(acts) == 0 {
			acts = []string{`Action::"FileOpen"`}
		}
		if len(acts) == 1 {
			action = "action == " + acts[0]
		} else {
			action = "action in [" + strings.Join(acts, ", ") + "]"
		}
		for n := rng.Intn(3) + 1; n > 0; n-- {
			entities = append(entities, randomFileEntity(rng))
		}
	case kind < 7:
		action = `action == Action::"ProcessExec"`
		for n := rng.Intn(2) + 1; n > 0; n-- {
			entities = append(entities, randomFileEntity(rng))
		}
	case kind < 9:
		action = `action == Action::"NetworkConnect"`
		for n := rng.Intn(3) + 1; n > 0; n-- {
			entities = append(entities, pick(rng, eqHostPool))
		}
	default:
		action = `action == Action::"McpCall"`
		head := "resource"
		var conds []string
		if rng.Intn(2) == 0 {
			head = fmt.Sprintf("resource == MCP::Tool::%q", pick(rng, eqTools))
		}
		if rng.Intn(3) > 0 {
			conds = append(conds, fmt.Sprintf("when { resource in [MCP::Server::%q] }", pick(rng, eqServers)))
		}
		return fmt.Sprintf("%s (%s, %s, %s) %s;", effect, principal, action, head, strings.Join(conds, " "))
	}
	head, conds := resourceClause(rng, entities)
	if rng.Intn(10) == 0 {
		conds = append(conds, "when { context.ignored == 1 }")
	}
	return fmt.Sprintf("%s (%s, %s, %s) %s;", effect, principal, action, head, strings.Join(conds, " "))
}

// randomProbePath returns an absolute path: requests always are (the engine
// rejects a relative one), so relative rule paths never match.
func randomProbePath(rng *rand.Rand) string {
	p := pick(rng, eqPathPool)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	switch rng.Intn(4) {
	case 0:
		p += pick(rng, []string{"z", "/z", "b", "c/d", "/"})
	case 1:
		if len(p) > 1 {
			p = strings.TrimSuffix(p, "/")
		}
	}
	return p
}

type eqCounter struct{ policies, decisions int }

// checkEquivalent compares legacy and strict decisions on random probes.
func checkEquivalent(t *testing.T, rng *rand.Rand, legacyIR *lsm.PolicySet, eng *engine.Engine, text, strict string, probes int, c *eqCounter) {
	t.Helper()
	legacy := lsm.NewLegacyModelForTest(legacyIR)
	fail := func(what string, want, got bool, dec engine.Decision) {
		t.Fatalf("%s: legacy=%v strict=%v (%+v)\nlegacy policy:\n%s\nstrict policy:\n%s", what, want, got, dec, text, strict)
	}
	for i := 0; i < probes; i++ {
		c.decisions++
		switch rng.Intn(4) {
		case 0:
			path := randomProbePath(rng)
			op, action := uint32(lsm.OpOpenRO), engine.ActionFileOpenReadOnly
			if rng.Intn(2) == 0 {
				op, action = lsm.OpOpenRW, engine.ActionFileOpenReadWrite
			}
			want := legacy.Open(path, op)
			if got := eng.DecideOpen(path, action); got.Allow != want {
				fail(fmt.Sprintf("open %s %q", action, path), want, got.Allow, got)
			}
		case 1:
			path := randomProbePath(rng)
			want := legacy.Exec(path)
			if got := eng.DecideExec(path); got.Allow != want {
				fail(fmt.Sprintf("exec %q", path), want, got.Allow, got)
			}
		case 2:
			host := pick(rng, []string{"", "a.example.com", "b.a.example.com", "example.com", "evilexample.com", "x.example.com", "A.EXAMPLE.COM", "a.example.com.", "other.org", "mcp.example.com"})
			ip := pick(rng, []string{"", "10.0.0.1", "10.0.0.2", "10.0.0.3"})
			if host == "" && ip == "" {
				ip = "10.0.0.1"
			}
			port := pick(rng, []uint16{0, 22, 80, 443})
			want := legacy.Connect(host, ip, port)
			if got := eng.DecideConnect(host, ip, port); got.Allow != want {
				fail(fmt.Sprintf("connect %q %q %d", host, ip, port), want, got.Allow, got)
			}
		default:
			server := pick(rng, []string{"mcp.example.com", "https://MCP.example.com/mcp", "other.example.com", "", "mcp.example.com:8443"})
			tool := pick(rng, []string{"search", "execute-shell", " EXECUTE-SHELL ", "delete", ""})
			want := legacy.MCP(server, tool)
			if got := eng.DecideMCP(server, tool); got.Allow != want {
				fail(fmt.Sprintf("mcp %q %q", server, tool), want, got.Allow, got)
			}
		}
	}
}

func rewriteAndBuild(t *testing.T, layers ...transpiler.LegacyLayer) (*transpiler.Rewrite, *engine.Engine) {
	t.Helper()
	rw, err := transpiler.RewriteLegacy(transpiler.RewriteOptions{}, layers...)
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	eng, err := engine.New(rw.Policies)
	if err != nil {
		t.Fatalf("engine: %v\n%s", err, rw.Text)
	}
	return rw, eng
}

func TestLegacyRewriteIsEquivalentToLegacySemantics(t *testing.T) {
	sets, probes := 3000, 200
	if testing.Short() {
		sets = 300
	}
	rng := rand.New(rand.NewSource(142))
	var c eqCounter
	tr := transpiler.NewCedarToLeashTranspiler()
	for i := 0; i < sets; i++ {
		var lines []string
		for n := rng.Intn(8) + 1; n > 0; n-- {
			lines = append(lines, randomLegacyPolicy(rng))
		}
		text := strings.Join(lines, "\n")
		legacyIR, _, err := tr.TranspileFromString(text)
		if err != nil {
			t.Fatalf("legacy transpile: %v\n%s", err, text)
		}
		parsed, err := transpiler.NewCedarParser().ParseFromNamedString("leash.cedar", text)
		if err != nil {
			t.Fatal(err)
		}
		rw, eng := rewriteAndBuild(t, transpiler.LegacyLayer{Name: "leash.cedar", Policies: parsed})
		c.policies++
		checkEquivalent(t, rng, legacyIR, eng, text, rw.Text, probes, &c)
	}
	t.Logf("%d random legacy policy sets, %d decisions: legacy == strict Cedar", c.policies, c.decisions)
}

// TestLegacyRewriteNestingProperty: random nested chains of alternating
// forbid/permit (forbid /a, permit /a/b, forbid /a/b/c, ...), with random
// open modes and resource kinds, decide the same.
func TestLegacyRewriteNestingProperty(t *testing.T) {
	rng := rand.New(rand.NewSource(1420))
	var c eqCounter
	tr := transpiler.NewCedarToLeashTranspiler()
	segs := []string{"a", "b", "c", "d", "e", "f"}
	for i := 0; i < 2000; i++ {
		depth := rng.Intn(6) + 1
		path := ""
		var lines []string
		effect := pick(rng, []string{"forbid", "permit"})
		for d := 0; d < depth; d++ {
			path += "/" + segs[d]
			ent := fmt.Sprintf("Dir::%q", path+"/")
			if rng.Intn(3) == 0 {
				ent = fmt.Sprintf("File::%q", path)
			}
			action := pick(rng, []string{`Action::"FileOpen"`, `Action::"FileOpenReadOnly"`, `Action::"FileOpenReadWrite"`, `Action::"ProcessExec"`})
			lines = append(lines, fmt.Sprintf("%s (principal, action == %s, resource) when { resource in [%s] };", effect, action, ent))
			if rng.Intn(4) > 0 {
				effect = map[string]string{"forbid": "permit", "permit": "forbid"}[effect]
			}
		}
		// Shuffle: source order must not matter.
		rng.Shuffle(len(lines), func(a, b int) { lines[a], lines[b] = lines[b], lines[a] })
		text := strings.Join(lines, "\n")
		legacyIR, _, err := tr.TranspileFromString(text)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := transpiler.NewCedarParser().ParseFromNamedString("leash.cedar", text)
		if err != nil {
			t.Fatal(err)
		}
		rw, eng := rewriteAndBuild(t, transpiler.LegacyLayer{Name: "leash.cedar", Policies: parsed})
		legacy := lsm.NewLegacyModelForTest(legacyIR)
		for probe := 0; probe < 60; probe++ {
			c.decisions++
			p := ""
			for d := rng.Intn(depth + 2); d > 0; d-- {
				p += "/" + segs[rng.Intn(len(segs))]
			}
			if p == "" {
				p = "/"
			}
			if rng.Intn(3) == 0 {
				p += "/x"
			}
			if got, want := eng.DecideOpen(p, engine.ActionFileOpenReadOnly).Allow, legacy.Open(p, lsm.OpOpenRO); got != want {
				t.Fatalf("open ro %q: legacy=%v strict=%v\n%s\n---\n%s", p, want, got, text, rw.Text)
			}
			if got, want := eng.DecideOpen(p, engine.ActionFileOpenReadWrite).Allow, legacy.Open(p, lsm.OpOpenRW); got != want {
				t.Fatalf("open rw %q: legacy=%v strict=%v\n%s\n---\n%s", p, want, got, text, rw.Text)
			}
			if got, want := eng.DecideExec(p).Allow, legacy.Exec(p); got != want {
				t.Fatalf("exec %q: legacy=%v strict=%v\n%s\n---\n%s", p, want, got, text, rw.Text)
			}
		}
		c.policies++
	}
	t.Logf("%d nested chains, %d probes x 3 decisions: legacy == strict Cedar", c.policies, c.decisions)
}

// legacyMerge is policy.Manager's legacy layer merge (GetActiveRules before
// #142): union of the rules; a runtime explicit connect default overrides
// the file's; otherwise any allow-any makes the default allow.
func legacyMerge(file, runtime *lsm.PolicySet) *lsm.PolicySet {
	merged := runtime.Clone()
	merged.ConnectDefaultAllow = file.ConnectDefaultAllow
	merged.ConnectDefaultExplicit = file.ConnectDefaultExplicit
	merged.Open = append(merged.Open, file.Open...)
	merged.Exec = append(merged.Exec, file.Exec...)
	merged.Connect = append(merged.Connect, file.Connect...)
	merged.MCP = append(merged.MCP, file.MCP...)
	if runtime.ConnectDefaultExplicit {
		merged.ConnectDefaultAllow = runtime.ConnectDefaultAllow
		merged.ConnectDefaultExplicit = true
	} else if !merged.ConnectDefaultExplicit && runtime.ConnectDefaultAllow {
		merged.ConnectDefaultAllow = true
	}
	return merged
}

// TestLegacyRewriteAcrossLayers: a file layer and a runtime layer are
// rewritten together, so specificity crosses layers as the legacy merge did.
func TestLegacyRewriteAcrossLayers(t *testing.T) {
	rng := rand.New(rand.NewSource(1421))
	var c eqCounter
	tr := transpiler.NewCedarToLeashTranspiler()
	for i := 0; i < 1000; i++ {
		var texts [2]string
		var irs [2]*lsm.PolicySet
		var layers []transpiler.LegacyLayer
		for l := 0; l < 2; l++ {
			var lines []string
			for n := rng.Intn(5) + 1; n > 0; n-- {
				lines = append(lines, randomLegacyPolicy(rng))
			}
			texts[l] = strings.Join(lines, "\n")
			ir, _, err := tr.TranspileFromString(texts[l])
			if err != nil {
				t.Fatal(err)
			}
			irs[l] = ir
			parsed, err := transpiler.NewCedarParser().ParseFromNamedString(fmt.Sprintf("layer%d.cedar", l), texts[l])
			if err != nil {
				t.Fatal(err)
			}
			layers = append(layers, transpiler.LegacyLayer{Name: fmt.Sprintf("layer%d", l), Policies: parsed})
		}
		rw, eng := rewriteAndBuild(t, layers...)
		c.policies++
		checkEquivalent(t, rng, legacyMerge(irs[0], irs[1]), eng, texts[0]+"\n// --- runtime layer\n"+texts[1], rw.Text, 150, &c)
	}
	t.Logf("%d random layer pairs, %d decisions: legacy merge == strict Cedar", c.policies, c.decisions)
}

// TestLegacyRewriteOfRawIRLayers: IR-only layers (rules built in code) are
// legacy by definition and rewrite the same way.
func TestLegacyRewriteOfRawIRLayers(t *testing.T) {
	rng := rand.New(rand.NewSource(1422))
	var c eqCounter
	tr := transpiler.NewCedarToLeashTranspiler()
	for i := 0; i < 500; i++ {
		var lines []string
		for n := rng.Intn(8) + 1; n > 0; n-- {
			lines = append(lines, randomLegacyPolicy(rng))
		}
		text := strings.Join(lines, "\n")
		ir, _, err := tr.TranspileFromString(text)
		if err != nil {
			t.Fatal(err)
		}
		rw, eng := rewriteAndBuild(t, transpiler.LegacyLayer{Name: "ir", IR: ir})
		c.policies++
		checkEquivalent(t, rng, ir, eng, text, rw.Text, 150, &c)
	}
	t.Logf("%d IR layers, %d decisions: legacy == strict Cedar", c.policies, c.decisions)
}
