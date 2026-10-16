package lsm_test

import (
	"fmt"
	"math/rand"
	"regexp"
	"strings"
	"testing"

	cedar "github.com/cedar-policy/cedar-go"

	"github.com/strongdm/leash/internal/engine"
	"github.com/strongdm/leash/internal/lsm"
	"github.com/strongdm/leash/internal/transpiler"
)

// Kernel parity (#142): the kernel tables transpiler.CompileKernel builds
// from a strict policy set, loaded through the real kernel loaders and
// decided by the userspace models of the BPF lookups, must decide exactly
// like cedar.Authorize (the engine) over the same set.

var kpPaths = []string{"/", "/a", "/a/", "/ab", "/a/b", "/a/b/", "/a/b/c/", "/x", "/x/", "/x/y"}

func kpEntity(rng *rand.Rand) string {
	p := pick(rng, kpPaths)
	switch rng.Intn(3) {
	case 0:
		if rng.Intn(4) == 0 && len(p) > 1 {
			p = strings.TrimSuffix(p, "/")
		}
		return fmt.Sprintf("Dir::%q", p)
	case 1:
		return fmt.Sprintf("FilePrefix::%q", p)
	}
	return fmt.Sprintf("File::%q", p) // exact
}

func kpExactFile(rng *rand.Rand) string {
	return fmt.Sprintf("File::%q", pick(rng, kpPaths))
}

var kpActions = []string{
	"action",
	`action in Action::"FileOpen"`,
	`action == Action::"FileOpenReadOnly"`,
	`action == Action::"FileOpenReadWrite"`,
	`action == Action::"ProcessExec"`,
	`action in [Action::"FileOpenReadOnly", Action::"ProcessExec"]`,
}

func kpAtom(rng *rand.Rand) string {
	switch rng.Intn(6) {
	case 0:
		return pick(rng, []string{`action == Action::"FileOpenReadOnly"`, `action in Action::"FileOpen"`, `action != Action::"ProcessExec"`})
	case 1:
		return "resource in [" + kpEntity(rng) + ", " + kpEntity(rng) + "]"
	case 2:
		return pick(rng, []string{"true", "false", "resource is File"})
	case 3:
		return "resource == " + kpExactFile(rng)
	}
	return "resource in " + kpEntity(rng)
}

func kpExpr(rng *rand.Rand, depth int) string {
	if depth == 0 || rng.Intn(3) == 0 {
		return kpAtom(rng)
	}
	switch rng.Intn(3) {
	case 0:
		return "(" + kpExpr(rng, depth-1) + " && " + kpExpr(rng, depth-1) + ")"
	case 1:
		return "(" + kpExpr(rng, depth-1) + " || " + kpExpr(rng, depth-1) + ")"
	}
	return "!(" + kpExpr(rng, depth-1) + ")"
}

func randomStrictFilePolicy(rng *rand.Rand) string {
	effect := pick(rng, []string{"permit", "forbid"})
	scope := "resource"
	switch rng.Intn(5) {
	case 0:
		scope = "resource in " + kpEntity(rng)
	case 1:
		scope = "resource is File in " + kpEntity(rng)
	case 2:
		scope = "resource == " + kpExactFile(rng)
	}
	var conds []string
	for n := rng.Intn(3); n > 0; n-- {
		kind := pick(rng, []string{"when", "when", "unless"})
		conds = append(conds, fmt.Sprintf("%s { %s }", kind, kpExpr(rng, 2)))
	}
	return fmt.Sprintf("@leash_semantics(\"cedar\")\n%s (principal, %s, %s) %s;", effect, pick(rng, kpActions), scope, strings.Join(conds, " "))
}

func compileStrict(t *testing.T, text string) (*engine.Engine, *lsm.PolicySet, error) {
	t.Helper()
	ps, err := cedar.NewPolicySetFromBytes("strict.cedar", []byte(text))
	if err != nil {
		t.Fatalf("parse: %v\n%s", err, text)
	}
	eng, err := engine.New(ps)
	if err != nil {
		t.Fatalf("engine: %v\n%s", err, text)
	}
	ir, err := transpiler.CompileKernel(ps, eng)
	return eng, ir, err
}

func kernelProbePath(rng *rand.Rand) string {
	p := pick(rng, kpPaths)
	switch rng.Intn(4) {
	case 0:
		p += pick(rng, []string{"z", "/z", "b", "/c/d"})
	case 1:
		if len(p) > 1 {
			p = strings.TrimSuffix(p, "/")
		}
	}
	return p
}

func checkKernelParity(t *testing.T, rng *rand.Rand, text string, eng *engine.Engine, ir *lsm.PolicySet, probes int) int {
	t.Helper()
	k, err := lsm.NewKernelForTest(ir)
	if err != nil {
		t.Fatalf("kernel load: %v\n%s", err, text)
	}
	n := 0
	for i := 0; i < probes; i++ {
		path := kernelProbePath(rng)
		for _, op := range []struct {
			action string
			op     uint32
		}{{engine.ActionFileOpenReadOnly, lsm.OpOpenRO}, {engine.ActionFileOpenReadWrite, lsm.OpOpenRW}} {
			n++
			if got, want := k.Open(path, op.op), eng.DecideOpen(path, op.action).Allow; got != want {
				t.Fatalf("open %s %q: kernel=%v cedar=%v\npolicy:\n%s\nrules: %v", op.action, path, got, want, text, ruleStrings(ir.Open))
			}
		}
		n++
		if got, want := k.Link(path), eng.DecideOpen(path, engine.ActionFileOpenReadOnly).Allow; got != want {
			t.Fatalf("link source %q: kernel=%v cedar=%v\npolicy:\n%s\nrules: %v", path, got, want, text, ruleStrings(ir.Open))
		}
		// mkdir/unlink/rmdir/rename: the mutation table vs the two Cedar
		// decisions it stands for. Below a loose FilePrefix the kernel may be
		// stricter (documented), never looser.
		for _, m := range []string{path, path + "/n", path + "n"} {
			n++
			got, want := k.Mutation(m), eng.DecideMutation(m).Allow
			if got != want && !(want && !got && belowLooseFilePrefix(text, m)) {
				t.Fatalf("mutation %q: kernel=%v cedar=%v\npolicy:\n%s\nrules: %v", m, got, want, text, ruleStrings(ir.Open))
			}
		}
		n++
		if got, want := k.Exec(path), eng.DecideExec(path).Allow; got != want {
			t.Fatalf("exec %q: kernel=%v cedar=%v\npolicy:\n%s\nrules: %v", path, got, want, text, ruleStrings(ir.Exec))
		}
		ip := pick(rng, []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"})
		port := pick(rng, []uint16{22, 80, 443})
		n++
		if got, want := k.Connect(ip, port), eng.DecideConnect("", ip, port).Allow; got != want {
			t.Fatalf("connect %s:%d: kernel=%v cedar=%v\npolicy:\n%s\nrules: %v default=%v", ip, port, got, want, text, ruleStrings(ir.Connect), ir.ConnectDefaultAllow)
		}
	}
	return n
}

var filePrefixLiteral = regexp.MustCompile(`FilePrefix::"([^"]*)"`)

// belowLooseFilePrefix reports whether path has a "/" after a FilePrefix of
// the policy that does not end in "/": the documented zone where the
// kernel's mutation table may deny what Cedar allows.
func belowLooseFilePrefix(text, path string) bool {
	for _, m := range filePrefixLiteral.FindAllStringSubmatch(text, -1) {
		x := m[1]
		if !strings.HasSuffix(x, "/") && strings.HasPrefix(path, x) && strings.Contains(path[len(x):], "/") {
			return true
		}
	}
	return false
}

func ruleStrings(rules []lsm.PolicyRule) []string {
	out := make([]string, len(rules))
	for i := range rules {
		out[i] = rules[i].String()
	}
	return out
}

func TestKernelCompileMatchesCedarForStrictPolicies(t *testing.T) {
	rng := rand.New(rand.NewSource(1430))
	sets, decisions, rejected := 0, 0, 0
	for i := 0; i < 3000; i++ {
		var lines []string
		for n := rng.Intn(6) + 1; n > 0; n-- {
			lines = append(lines, randomStrictFilePolicy(rng))
		}
		text := strings.Join(lines, "\n")
		eng, ir, err := compileStrict(t, text)
		if err != nil {
			if !strings.Contains(err.Error(), "not enforceable by the kernel") {
				t.Fatalf("unexpected compile error: %v\n%s", err, text)
			}
			if rejected == 0 {
				t.Logf("example rejection: %v", err)
			}
			rejected++
			continue
		}
		sets++
		decisions += checkKernelParity(t, rng, text, eng, ir, 40)
	}
	t.Logf("%d random strict policy sets (%d rejected as not kernel-enforceable), %d decisions: kernel == cedar.Authorize", sets, rejected, decisions)
}

var kpHosts = []string{`Host::"10.0.0.1"`, `Host::"10.0.0.2"`, `Host::"10.0.0.1:22"`, `Host::"10.0.0.2:443"`, `Host::"*:443"`, `Host::"*"`, `Host::"api.example.com"`, `Host::"*.example.com"`}

func randomStrictConnectPolicy(rng *rand.Rand) string {
	effect := pick(rng, []string{"permit", "forbid"})
	action := pick(rng, []string{`action == Action::"NetworkConnect"`, "action", `action in [Action::"NetworkConnect", Action::"ProcessExec"]`})
	scope, cond := "resource", ""
	switch rng.Intn(5) {
	case 0:
		scope = "resource in " + pick(rng, kpHosts)
	case 1:
		scope = "resource is Host"
	case 2:
		hosts := []string{pick(rng, kpHosts)}
		for n := rng.Intn(3); n > 0; n-- {
			hosts = append(hosts, pick(rng, kpHosts))
		}
		cond = "when { resource in [" + strings.Join(hosts, ", ") + "] }"
	case 3:
		cond = fmt.Sprintf("when { resource in %s || resource in %s }", pick(rng, kpHosts), pick(rng, kpHosts))
	}
	if rng.Intn(5) == 0 {
		cond += ` when { action == Action::"NetworkConnect" }`
	}
	return fmt.Sprintf("@leash_semantics(\"cedar\")\n%s (principal, %s, %s) %s;", effect, action, scope, cond)
}

func TestKernelCompileMatchesCedarForConnect(t *testing.T) {
	rng := rand.New(rand.NewSource(1431))
	sets, decisions := 0, 0
	for i := 0; i < 3000; i++ {
		var lines []string
		for n := rng.Intn(5) + 1; n > 0; n-- {
			lines = append(lines, randomStrictConnectPolicy(rng))
		}
		text := strings.Join(lines, "\n")
		eng, ir, err := compileStrict(t, text)
		if err != nil {
			t.Fatalf("compile: %v\n%s", err, text)
		}
		sets++
		decisions += checkKernelParity(t, rng, text, eng, ir, 30)
	}
	t.Logf("%d random strict connect sets, %d decisions: kernel == cedar.Authorize (IP rules; hostnames reach the kernel via DNS)", sets, decisions)
}

// TestKernelCompileOfRewrittenLegacyPolicies closes the chain: legacy policy
// -> RewriteLegacy -> CompileKernel -> kernel loaders == cedar.Authorize.
func TestKernelCompileOfRewrittenLegacyPolicies(t *testing.T) {
	rng := rand.New(rand.NewSource(1432))
	sets, decisions, rejected := 0, 0, 0
	for i := 0; i < 2000; i++ {
		var lines []string
		for n := rng.Intn(8) + 1; n > 0; n-- {
			lines = append(lines, randomLegacyPolicy(rng))
		}
		text := strings.Join(lines, "\n")
		parsed, err := transpiler.NewCedarParser().ParseFromNamedString("leash.cedar", text)
		if err != nil {
			t.Fatal(err)
		}
		rw, err := transpiler.RewriteLegacy(transpiler.RewriteOptions{}, transpiler.LegacyLayer{Name: "leash.cedar", Policies: parsed})
		if err != nil {
			t.Fatal(err)
		}
		eng, err := engine.New(rw.Policies)
		if err != nil {
			t.Fatal(err)
		}
		ir, err := transpiler.CompileKernel(rw.Policies, eng)
		if err != nil {
			// The only rewritten-legacy shape the kernel cannot enforce: a
			// mutation permit nested in a forbid nested in a permit.
			if !strings.Contains(err.Error(), "directory mutations") {
				t.Fatalf("a rewritten legacy policy must compile for the kernel: %v\nlegacy:\n%s\nstrict:\n%s", err, text, rw.Text)
			}
			rejected++
			continue
		}
		sets++
		decisions += checkKernelParity(t, rng, rw.Text, eng, ir, 40)
	}
	t.Logf("%d rewritten legacy sets (%d rejected: mutation permit nested in forbid nested in permit), %d decisions: kernel == cedar.Authorize", sets, rejected, decisions)
}
