package transpiler

import (
	"strings"
	"testing"

	cedarlib "github.com/cedar-policy/cedar-go"

	"github.com/strongdm/leash/internal/engine"
	"github.com/strongdm/leash/internal/lsm"
)

func compileKernelText(t *testing.T, text string) (*lsm.PolicySet, error) {
	t.Helper()
	ps, err := cedarlib.NewPolicySetFromBytes("strict.cedar", []byte(text))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	eng, err := engine.New(ps)
	if err != nil {
		return nil, err
	}
	return CompileKernel(ps, eng)
}

func TestCompileKernelRejectsWhatTheKernelCannotEnforce(t *testing.T) {
	cases := map[string]string{
		`permit (principal == User::"a", action == Action::"FileOpenReadOnly", resource in Dir::"/x/");`:                              "principal cannot be constrained",
		`permit (principal == User::"a", action == Action::"McpCall", resource);`:                                                     "principal cannot be constrained",
		`permit (principal, action == Action::"FileOpenReadOnly", resource) when { context.tty == true };`:                            "context",
		`permit (principal, action == Action::"ProcessExec", resource == Dir::"/bin/");`:                                              "never matches",
		`permit (principal, action == Action::"ProcessExec", resource == FilePrefix::"/bin/");`:                                       "never matches",
		`@expires("2030-01-01T00:00:00Z") permit (principal, action == Action::"NetworkConnect", resource);`:                          "@expires",
		`permit (principal, action == Action::"NetworkConnect", resource in Net::Hostname::"x.com");`:                                 "unknown resource type",
		`permit (principal, action == Action::"NetworkConnect", resource in Host::"API.example.com");`:                                "lowercase",
		`permit (principal, action == Action::"NetworkConnect", resource in Host::"x.com:http");`:                                     "port",
		`permit (principal, action == Action::"NetworkConnect", resource == Host::"x.com:443");`:                                      "never matches",
		`permit (principal, action == Action::"FileOpen", resource in Dir::"/x/");`:                                                   "matches no request",
		`permit (principal, action == Action::"Teleport", resource);`:                                                                 "unknown Leash action",
		`permit (principal, action == Action::"NetworkConnect", resource in Host::"a.com") when { resource in Host::"*:443" };`:       "not both",
		`forbid (principal, action == Action::"NetworkConnect", resource in Host::"*.a.com") unless { resource in Host::"b.a.com" };`: "unless",
		`permit (principal, action, resource) when { resource.owner == "x" };`:                                                        "attributes",
		`permit (principal, action == Action::"FileOpenReadOnly", resource in File::"relative");`:                                     "absolute",
		`permit (principal, action == Action::"NetworkConnect", resource in Host::"2001:DB8::1");`:                                    "canonical form (2001:db8::1)",
		`permit (principal, action == Action::"NetworkConnect", resource in Host::"::ffff:10.0.0.1");`:                                "canonical form (10.0.0.1)",
		`permit (principal, action == Action::"NetworkConnect", resource in Host::"[2001:db8::1]");`:                                  "brackets are only for an IPv6 address with a port",
		`permit (principal, action == Action::"NetworkConnect", resource in Host::"[10.0.0.1]:443");`:                                 "brackets enclose only an IPv6 address",
		`permit (principal, action == Action::"NetworkConnect", resource in Host::"[2001:db8::1]:0");`:                                "port",
		`permit (principal, action == Action::"NetworkConnect", resource in Host::"::");`:                                             "unspecified address",
		`permit (principal, action == Action::"NetworkConnect", resource in Host::"0.0.0.0");`:                                        "unspecified address",
		`permit (principal, action == Action::"NetworkConnect", resource in Host::"a:b:c");`:                                          "[address]:port",
	}
	for text, want := range cases {
		_, err := compileKernelText(t, text)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s\n  got %v, want an error containing %q", text, err, want)
		}
	}
}

// Exec rules must fit the kernel exec matcher: 64 bytes for a prefix, 63 for
// an exact path (plus its NUL). The error names the policy and its line.
func TestCompileKernelChecksExecPathLengths(t *testing.T) {
	p63 := "/" + strings.Repeat("a", 62)
	p64 := "/" + strings.Repeat("a", 63)
	p65 := "/" + strings.Repeat("a", 64)
	ok := []string{
		`permit (principal, action == Action::"ProcessExec", resource == File::"` + p63 + `");`,
		`permit (principal, action == Action::"ProcessExec", resource in FilePrefix::"` + p64 + `");`,
		`permit (principal, action == Action::"ProcessExec", resource in Dir::"` + p63 + `/");`,
		// Only exec is limited: a long exact path for file opens is fine.
		`permit (principal, action in Action::"FileOpen", resource == File::"` + p65 + `");`,
	}
	for _, text := range ok {
		if _, err := compileKernelText(t, "@leash_semantics(\"cedar\")\n"+text); err != nil {
			t.Errorf("%s: %v", text, err)
		}
	}
	bad := []string{
		`permit (principal, action == Action::"ProcessExec", resource == File::"` + p64 + `");`,
		`permit (principal, action == Action::"ProcessExec", resource in FilePrefix::"` + p65 + `");`,
		`forbid (principal, action, resource) when { resource in Dir::"` + p64 + `/" };`,
	}
	for _, text := range bad {
		_, err := compileKernelText(t, "@leash_semantics(\"cedar\")\n"+text)
		if err == nil || !strings.Contains(err.Error(), "kernel exec matcher") || !strings.Contains(err.Error(), "strict.cedar:1:1") {
			t.Errorf("%s\n  got %v", text, err)
		}
	}
}

func TestCompileKernelAcceptsUserspaceOnlyPolicies(t *testing.T) {
	for _, text := range []string{
		`permit (principal, action == Action::"McpCall", resource) when { context.server == "mcp.example.com" };`,
		`@expires("2030-01-01T00:00:00Z") permit (principal == Plugin::"p", action == Secret::Action::"Read", resource);`,
		`permit (principal, action == Action::"HttpRewrite", resource == Host::"api") when { context.header == "X" && context.value == "y" };`,
	} {
		if _, err := compileKernelText(t, text); err != nil {
			t.Errorf("%s: %v", text, err)
		}
	}
}

func TestCompileKernelDefaults(t *testing.T) {
	ir, err := compileKernelText(t, `permit (principal, action, resource);`)
	if err != nil {
		t.Fatal(err)
	}
	if len(ir.Open) != 2 || ir.Open[0].String() != "allow file.open /" || ir.Open[1].String() != "allow file.mutate /" || len(ir.Exec) != 1 || !ir.ConnectDefaultAllow || !ir.ConnectDefaultExplicit {
		t.Fatalf("permit-all: open=%v exec=%v connect default=%v", ir.Open, ir.Exec, ir.ConnectDefaultAllow)
	}
	ir, err = compileKernelText(t, ``)
	if err != nil {
		t.Fatal(err)
	}
	// Only the mutation table's marker deny: nothing is mutable.
	if len(ir.Open) != 1 || ir.Open[0].String() != "deny file.mutate /" || len(ir.Exec) != 0 || ir.ConnectDefaultAllow || !ir.ConnectDefaultExplicit {
		t.Fatalf("empty policy is default deny: %+v", ir)
	}
	ir, err = compileKernelText(t, `
permit (principal, action == Action::"NetworkConnect", resource);
forbid (principal, action == Action::"NetworkConnect", resource);
permit (principal, action == Action::"NetworkConnect", resource in Host::"10.0.0.1");`)
	if err != nil {
		t.Fatal(err)
	}
	if ir.ConnectDefaultAllow || len(ir.Connect) != 1 || !lsm.IsConnectDefaultRule(ir.Connect[0]) {
		t.Fatalf("a forbid of every connection beats every permit: %v", ir.Connect)
	}
}

// IPv6 literals (#182) compile to IPv6 kernel rules.
func TestCompileKernelIPv6Hosts(t *testing.T) {
	ir, err := compileKernelText(t, `
permit (principal, action == Action::"NetworkConnect", resource in Host::"[2001:db8::1]:443");
forbid (principal, action == Action::"NetworkConnect", resource in Host::"2001:db8::2");`)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, r := range ir.Connect {
		got[r.String()] = true
	}
	for _, want := range []string{"allow net.send [2001:db8::1]:443", "deny net.send 2001:db8::2"} {
		if !got[want] {
			t.Errorf("missing kernel rule %q in %v", want, got)
		}
	}
	if ir.ConnectDefaultAllow {
		t.Error("IPv6 rules must not change the default deny")
	}
}
