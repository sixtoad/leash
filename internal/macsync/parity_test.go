package macsync

import (
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	cedar "github.com/cedar-policy/cedar-go"

	"github.com/strongdm/leash/internal/engine"
	"github.com/strongdm/leash/internal/lsm"
	"github.com/strongdm/leash/internal/transpiler"
)

// macOS parity (#142 follow-up): random strict Cedar policies, compiled by
// transpiler.CompileKernel, turned into the macOS tables by CompileTables,
// sent through JSON and decided by the model of the Swift matcher, must decide
// exactly like cedar.Authorize. The only exceptions are the kernel's own
// documented mutation over-denials (never the reverse). The same random sets
// are written to testdata/parity-vectors.json, which the Swift unit tests
// replay against the real matcher (mac-leash/Tests).

var updateVectors = flag.Bool("update-vectors", false, "rewrite testdata/parity-vectors.json")

func pick[T any](rng *rand.Rand, xs []T) T { return xs[rng.Intn(len(xs))] }

var ppPaths = []string{"/", "/a", "/a/", "/ab", "/a/b", "/a/b/", "/a/b/c/", "/x", "/x/", "/x/y", "/tmp/", "/tmp/w"}

func ppEntity(rng *rand.Rand) string {
	p := pick(rng, ppPaths)
	switch rng.Intn(3) {
	case 0:
		if rng.Intn(4) == 0 && len(p) > 1 {
			p = strings.TrimSuffix(p, "/")
		}
		return fmt.Sprintf("Dir::%q", p)
	case 1:
		return fmt.Sprintf("FilePrefix::%q", p)
	}
	return fmt.Sprintf("File::%q", p)
}

var ppActions = []string{
	"action",
	`action in Action::"FileOpen"`,
	`action == Action::"FileOpenReadOnly"`,
	`action == Action::"FileOpenReadWrite"`,
	`action == Action::"ProcessExec"`,
	`action in [Action::"FileOpenReadOnly", Action::"ProcessExec"]`,
}

func ppAtom(rng *rand.Rand) string {
	switch rng.Intn(6) {
	case 0:
		return pick(rng, []string{`action == Action::"FileOpenReadOnly"`, `action in Action::"FileOpen"`, `action != Action::"ProcessExec"`})
	case 1:
		return "resource in [" + ppEntity(rng) + ", " + ppEntity(rng) + "]"
	case 2:
		return pick(rng, []string{"true", "false", "resource is File"})
	case 3:
		return fmt.Sprintf("resource == File::%q", pick(rng, ppPaths))
	}
	return "resource in " + ppEntity(rng)
}

func ppExpr(rng *rand.Rand, depth int) string {
	if depth == 0 || rng.Intn(3) == 0 {
		return ppAtom(rng)
	}
	switch rng.Intn(3) {
	case 0:
		return "(" + ppExpr(rng, depth-1) + " && " + ppExpr(rng, depth-1) + ")"
	case 1:
		return "(" + ppExpr(rng, depth-1) + " || " + ppExpr(rng, depth-1) + ")"
	}
	return "!(" + ppExpr(rng, depth-1) + ")"
}

func randomFilePolicy(rng *rand.Rand) string {
	effect := pick(rng, []string{"permit", "forbid"})
	scope := "resource"
	switch rng.Intn(5) {
	case 0:
		scope = "resource in " + ppEntity(rng)
	case 1:
		scope = "resource is File in " + ppEntity(rng)
	case 2:
		scope = fmt.Sprintf("resource == File::%q", pick(rng, ppPaths))
	}
	var conds []string
	for n := rng.Intn(3); n > 0; n-- {
		conds = append(conds, fmt.Sprintf("%s { %s }", pick(rng, []string{"when", "when", "unless"}), ppExpr(rng, 2)))
	}
	return fmt.Sprintf("@leash_semantics(\"cedar\")\n%s (principal, %s, %s) %s;", effect, pick(rng, ppActions), scope, strings.Join(conds, " "))
}

var ppHosts = []string{`Host::"10.0.0.1"`, `Host::"10.0.0.2"`, `Host::"10.0.0.1:22"`, `Host::"10.0.0.2:443"`, `Host::"*:443"`, `Host::"*"`,
	`Host::"2001:db8::1"`, `Host::"2001:db8::2"`, `Host::"[2001:db8::1]:22"`, `Host::"[2001:db8::2]:443"`, `Host::"127.0.0.1"`}

func randomConnectPolicy(rng *rand.Rand) string {
	effect := pick(rng, []string{"permit", "forbid"})
	action := pick(rng, []string{`action == Action::"NetworkConnect"`, "action", `action in [Action::"NetworkConnect", Action::"ProcessExec"]`})
	scope, cond := "resource", ""
	switch rng.Intn(5) {
	case 0:
		scope = "resource in " + pick(rng, ppHosts)
	case 1:
		scope = "resource is Host"
	case 2:
		hosts := []string{pick(rng, ppHosts)}
		for n := rng.Intn(3); n > 0; n-- {
			hosts = append(hosts, pick(rng, ppHosts))
		}
		cond = "when { resource in [" + strings.Join(hosts, ", ") + "] }"
	case 3:
		cond = fmt.Sprintf("when { resource in %s || resource in %s }", pick(rng, ppHosts), pick(rng, ppHosts))
	}
	return fmt.Sprintf("@leash_semantics(\"cedar\")\n%s (principal, %s, %s) %s;", effect, action, scope, cond)
}

func compileForMac(t *testing.T, text string, protection Protection) (*engine.Engine, *MacPolicyTables, map[string]bool, error) {
	t.Helper()
	ps, err := cedar.NewPolicySetFromBytes("strict.cedar", []byte(text))
	if err != nil {
		t.Fatalf("parse: %v\n%s", err, text)
	}
	eng, err := engine.New(ps)
	if err != nil {
		t.Fatalf("engine: %v\n%s", err, text)
	}
	ir, warnings, err := transpiler.CompileKernelReport(ps, eng)
	if err != nil {
		return eng, nil, nil, err
	}
	warned := map[string]bool{}
	for _, w := range warnings {
		warned[w.Path] = true
	}
	tables, err := CompileTables(ir, protection)
	if err != nil {
		t.Fatalf("CompileTables: %v\n%s", err, text)
	}
	// What the extensions get is the JSON, not the Go value.
	data, err := json.Marshal(tables)
	if err != nil {
		t.Fatal(err)
	}
	var wire MacPolicyTables
	if err := json.Unmarshal(data, &wire); err != nil {
		t.Fatal(err)
	}
	return eng, &wire, warned, nil
}

var filePrefixLiteral = regexp.MustCompile(`FilePrefix::"([^"]*)"`)

// belowLooseFilePrefix: the documented zone where the kernel's mutation
// table may deny what Cedar allows (see AUTHZ-SERVICE.md).
func belowLooseFilePrefix(text, path string) bool {
	for _, m := range filePrefixLiteral.FindAllStringSubmatch(text, -1) {
		x := m[1]
		if !strings.HasSuffix(x, "/") && strings.HasPrefix(path, x) && strings.Contains(path[len(x):], "/") {
			return true
		}
	}
	return false
}

// Probe is one decision of a parity vector, as the Swift tests replay it.
type Probe struct {
	Kind  string `json:"kind"` // open_read, open_write, mutation, link, exec, connect
	Path  string `json:"path,omitempty"`
	IP    string `json:"ip,omitempty"`
	Port  uint16 `json:"port,omitempty"`
	Allow bool   `json:"allow"`
}

// Vector is one policy's tables and the decisions Cedar makes for it.
type Vector struct {
	Policy string          `json:"policy"`
	Tables MacPolicyTables `json:"tables"`
	Probes []Probe         `json:"probes"`
}

func probePath(rng *rand.Rand) string {
	p := pick(rng, ppPaths)
	switch rng.Intn(5) {
	case 0:
		p += pick(rng, []string{"z", "/z", "b", "/c/d"})
	case 1:
		if len(p) > 1 {
			p = strings.TrimSuffix(p, "/")
		}
	case 2:
		// The form Endpoint Security reports for /tmp.
		if strings.HasPrefix(p, "/tmp") {
			p = "/private" + p
		}
	}
	return p
}

// checkMacParity probes tables against Cedar and returns the probes (with
// Cedar's answers, or the kernel-documented answer where they may differ).
func checkMacParity(t *testing.T, rng *rand.Rand, text string, eng *engine.Engine, tables *MacPolicyTables, warned map[string]bool, probes int) []Probe {
	t.Helper()
	var out []Probe
	fail := func(what string, got, want bool) {
		data, _ := json.MarshalIndent(tables, "", " ")
		t.Fatalf("%s: mac=%v cedar=%v\npolicy:\n%s\ntables:\n%s", what, got, want, text, data)
	}
	for i := 0; i < probes; i++ {
		path := probePath(rng)
		cedarPath := canonicalMacPath(path) // the file macOS reports as path
		for _, op := range []struct {
			kind   string
			write  bool
			action string
		}{{"open_read", false, engine.ActionFileOpenReadOnly}, {"open_write", true, engine.ActionFileOpenReadWrite}} {
			got, want := modelOpen(tables, path, op.write), eng.DecideOpen(cedarPath, op.action).Allow
			if got != want {
				fail(fmt.Sprintf("%s %q", op.kind, path), got, want)
			}
			out = append(out, Probe{Kind: op.kind, Path: path, Allow: want})
		}
		if got, want := modelLink(tables, path), eng.DecideOpen(cedarPath, engine.ActionFileOpenReadOnly).Allow; got != want {
			fail(fmt.Sprintf("link source %q", path), got, want)
		} else {
			out = append(out, Probe{Kind: "link", Path: path, Allow: want})
		}
		for _, m := range []string{path, path + "/n", path + "n"} {
			cm := canonicalMacPath(m)
			got, want := modelMutation(tables, m), eng.DecideMutation(cm).Allow
			if got != want && !(want && !got && (warned[cm] || belowLooseFilePrefix(text, cm))) {
				fail(fmt.Sprintf("mutation %q", m), got, want)
			}
			out = append(out, Probe{Kind: "mutation", Path: m, Allow: got})
		}
		if got, want := modelExec(tables, path, nil), eng.DecideExec(cedarPath).Allow; got != want {
			fail(fmt.Sprintf("exec %q", path), got, want)
		} else {
			out = append(out, Probe{Kind: "exec", Path: path, Allow: want})
		}
		ip := pick(rng, []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "::ffff:10.0.0.1", "::ffff:10.0.0.2", "2001:db8::1", "2001:db8::2", "2001:db8::3", "127.0.0.1"})
		port := pick(rng, []uint16{22, 80, 443})
		if got, want := modelConnect(tables, ip, port), eng.DecideConnect("", ip, port).Allow; got != want {
			fail(fmt.Sprintf("connect %s:%d", ip, port), got, want)
		} else {
			out = append(out, Probe{Kind: "connect", IP: ip, Port: port, Allow: want})
		}
	}
	// A flow that names its destination but not its address is allowed only
	// where Cedar allows every address: never looser.
	for _, port := range []uint16{22, 80, 443} {
		any := modelConnectAnyAddress(tables, port)
		if any {
			for _, ip := range kpAnyAddressProbes {
				if !eng.DecideConnect("", ip, port).Allow {
					fail(fmt.Sprintf("connect to an unknown address on %d allowed, but cedar denies %s", port, ip), true, false)
				}
			}
		}
		out = append(out, Probe{Kind: "connect_any", Port: port, Allow: any})
	}
	return out
}

var kpAnyAddressProbes = []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "192.0.2.1", "::ffff:10.0.0.1", "2001:db8::1", "2001:db8::2", "2001:db8::9", "127.0.0.1"}

func TestMacTablesMatchCedarForStrictPolicies(t *testing.T) {
	rng := rand.New(rand.NewSource(4242))
	var vectors []Vector
	sets, decisions, rejected := 0, 0, 0
	for i := 0; i < 2500; i++ {
		var lines []string
		for n := rng.Intn(6) + 1; n > 0; n-- {
			if rng.Intn(3) == 0 {
				lines = append(lines, randomConnectPolicy(rng))
			} else {
				lines = append(lines, randomFilePolicy(rng))
			}
		}
		text := strings.Join(lines, "\n")
		eng, tables, warned, err := compileForMac(t, text, Protection{})
		if err != nil {
			if !strings.Contains(err.Error(), "not enforceable by the kernel") {
				t.Fatalf("unexpected compile error: %v\n%s", err, text)
			}
			rejected++
			continue
		}
		sets++
		probes := checkMacParity(t, rng, text, eng, tables, warned, 40)
		decisions += len(probes)
		if len(vectors) < 120 {
			kept := probes[:min(len(probes), 40)]
			kept = append(kept, probes[len(probes)-3:]...) // the connect_any probes
			vectors = append(vectors, Vector{Policy: text, Tables: *tables, Probes: kept})
		}
	}
	t.Logf("%d random strict policy sets (%d rejected as not kernel-enforceable), %d decisions: macOS tables == cedar.Authorize", sets, rejected, decisions)
	vectors = append(vectors, protectionVectors(t)...)
	checkVectorsFile(t, vectors)
}

// Leash's own state is denied whatever the policy permits.
func protectionVectors(t *testing.T) []Vector {
	t.Helper()
	const permitAll = "@leash_semantics(\"cedar\")\npermit (principal, action, resource);"
	protection := Protection{Paths: []string{"/Users/u/Library/Application Support/leash", "/private/var/folders/x/T/leash/private/"}, Ports: []uint16{18080, 18000}}
	_, tables, _, err := compileForMac(t, permitAll, protection)
	if err != nil {
		t.Fatal(err)
	}
	want := []Probe{
		{Kind: "open_read", Path: "/Users/u/Library/Application Support/leash/policy.cedar", Allow: false},
		{Kind: "open_write", Path: "/Users/u/Library/Application Support/leash", Allow: false},
		{Kind: "mutation", Path: "/Users/u/Library/Application Support/leash/policy.cedar", Allow: false},
		{Kind: "exec", Path: "/Users/u/Library/Application Support/leash/x", Allow: false},
		{Kind: "link", Path: "/var/folders/x/T/leash/private/ca-key.pem", Allow: false},
		{Kind: "open_read", Path: "/private/var/folders/x/T/leash/private/ca-key.pem", Allow: false},
		{Kind: "open_read", Path: "/private/var/folders/x/T/leash/ca-cert.pem", Allow: true},
		{Kind: "open_read", Path: "/Users/u/Library/Application Support/leashx", Allow: true},
		{Kind: "connect", IP: "127.0.0.1", Port: 18080, Allow: false},
		{Kind: "connect", IP: "::1", Port: 18000, Allow: false},
		{Kind: "connect", IP: "::ffff:127.0.0.1", Port: 18080, Allow: false},
		{Kind: "connect", IP: "0.0.0.0", Port: 18080, Allow: false},
		{Kind: "connect", IP: "127.0.0.1", Port: 8080, Allow: true},
		{Kind: "connect", IP: "10.0.0.1", Port: 18080, Allow: true},
	}
	for _, p := range want {
		if got := decideProbe(tables, p); got != p.Allow {
			t.Fatalf("protected probe %+v: got %v", p, got)
		}
	}
	return []Vector{{Policy: permitAll, Tables: *tables, Probes: want}}
}

func decideProbe(tables *MacPolicyTables, p Probe) bool {
	switch p.Kind {
	case "open_read":
		return modelOpen(tables, p.Path, false)
	case "open_write":
		return modelOpen(tables, p.Path, true)
	case "mutation":
		return modelMutation(tables, p.Path)
	case "link":
		return modelLink(tables, p.Path)
	case "exec":
		return modelExec(tables, p.Path, nil)
	case "connect":
		return modelConnect(tables, p.IP, p.Port)
	case "connect_any":
		return modelConnectAnyAddress(tables, p.Port)
	}
	panic("unknown probe kind " + p.Kind)
}

// The vectors are generated from a fixed seed, so the committed file must be
// exactly what this test produces: a change to the compiler, the tables or
// the model that alters a decision shows up here and in the Swift tests.
func checkVectorsFile(t *testing.T, vectors []Vector) {
	t.Helper()
	// One compact vector per line: small enough to commit, still diffable.
	var b strings.Builder
	b.WriteString("[\n")
	for i, v := range vectors {
		line, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(line)
		if i < len(vectors)-1 {
			b.WriteString(",")
		}
		b.WriteString("\n")
	}
	b.WriteString("]\n")
	data := []byte(b.String())
	path := filepath.Join("..", "..", "mac-leash", "Tests", "LeashPolicyCoreTests", "Resources", "parity-vectors.json")
	if *updateVectors {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	committed, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s (regenerate with go test ./internal/macsync -run TestMacTablesMatchCedar -update-vectors): %v", path, err)
	}
	if string(committed) != string(data) {
		t.Fatalf("%s is stale; regenerate with go test ./internal/macsync -run TestMacTablesMatchCedar -update-vectors", path)
	}
	// Every committed decision must still be what the model says.
	var replay []Vector
	if err := json.Unmarshal(committed, &replay); err != nil || len(replay) < 100 {
		t.Fatal(err)
	}
	for _, v := range replay {
		for _, p := range v.Probes {
			if got := decideProbe(&v.Tables, p); got != p.Allow {
				t.Fatalf("vector probe %+v: model=%v\n%s", p, got, v.Policy)
			}
		}
	}
}

// The firmlinked form a policy cannot be enforced as written is refused,
// rather than silently never matching.
func TestCompileTablesRefusesPrivateFirmlinkPaths(t *testing.T) {
	for _, text := range []string{
		`forbid (principal, action, resource in Dir::"/private/tmp/");`,
		`forbid (principal, action, resource in FilePrefix::"/priv");`,
		`forbid (principal, action == Action::"ProcessExec", resource == File::"/private/var/x");`,
	} {
		full := "@leash_semantics(\"cedar\")\npermit (principal, action, resource);\n@leash_semantics(\"cedar\")\n" + text
		ps, err := cedar.NewPolicySetFromBytes("p.cedar", []byte(full))
		if err != nil {
			t.Fatal(err)
		}
		eng, err := engine.New(ps)
		if err != nil {
			t.Fatal(err)
		}
		ir, _, err := transpiler.CompileKernelReport(ps, eng)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := CompileTables(ir, Protection{}); err == nil || !strings.Contains(err.Error(), "/private") {
			t.Fatalf("%s: want a refusal naming /private, got %v", text, err)
		}
	}
	// /private itself (not under a firmlink) and the short forms are fine.
	for _, text := range []string{
		`forbid (principal, action, resource == File::"/private");`,
		`forbid (principal, action, resource in Dir::"/tmp/");`,
	} {
		full := "@leash_semantics(\"cedar\")\npermit (principal, action, resource);\n@leash_semantics(\"cedar\")\n" + text
		ps, _ := cedar.NewPolicySetFromBytes("p.cedar", []byte(full))
		eng, _ := engine.New(ps)
		ir, _, err := transpiler.CompileKernelReport(ps, eng)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := CompileTables(ir, Protection{}); err != nil {
			t.Fatalf("%s: refused: %v", text, err)
		}
	}
}

// Hostname rules are resolved to addresses at load, as the Linux loader does.
func TestCompileTablesResolvesHostnames(t *testing.T) {
	lsm.SetHostResolver(func(host string) ([]net.IP, error) {
		if host == "api.example.com" {
			return []net.IP{net.ParseIP("192.0.2.10"), net.ParseIP("2001:db8::10")}, nil
		}
		return nil, fmt.Errorf("no such host")
	})
	t.Cleanup(func() { lsm.SetHostResolver(nil) })
	_, tables, _, err := compileForMac(t, "@leash_semantics(\"cedar\")\npermit (principal, action == Action::\"NetworkConnect\", resource in Host::\"api.example.com:443\");", Protection{})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		ip    string
		port  uint16
		allow bool
	}{{"192.0.2.10", 443, true}, {"2001:db8::10", 443, true}, {"::ffff:192.0.2.10", 443, true}, {"192.0.2.10", 80, false}, {"192.0.2.11", 443, false}} {
		if got := modelConnect(tables, c.ip, c.port); got != c.allow {
			t.Fatalf("connect %s:%d = %v, want %v (rules %+v default %v)", c.ip, c.port, got, c.allow, tables.Network.Rules, tables.Network.DefaultAllow)
		}
	}
}

// The tables and their version are a pure function of the policy.
func TestCompileTablesIsDeterministic(t *testing.T) {
	text := "@leash_semantics(\"cedar\")\npermit (principal, action, resource in Dir::\"/\");\n@leash_semantics(\"cedar\")\nforbid (principal, action == Action::\"FileOpenReadWrite\", resource in Dir::\"/etc/\");"
	_, a, _, err := compileForMac(t, text, Protection{Paths: []string{"/p"}, Ports: []uint16{1}})
	if err != nil {
		t.Fatal(err)
	}
	_, b, _, _ := compileForMac(t, text, Protection{Paths: []string{"/p"}, Ports: []uint16{1}})
	if a.Version == "" || a.Version != b.Version {
		t.Fatalf("versions %q %q", a.Version, b.Version)
	}
	_, c, _, _ := compileForMac(t, text, Protection{Paths: []string{"/q"}, Ports: []uint16{1}})
	if c.Version == a.Version {
		t.Fatal("different tables, same version")
	}
	if a.Semantics != TablesSemantics {
		t.Fatalf("semantics %q", a.Semantics)
	}
}
