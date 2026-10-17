package transpiler

import (
	"strings"
	"testing"

	"github.com/strongdm/leash/internal/engine"
)

// A legacy IPv6 Host (#182) survives the legacy parser (whose entity split
// must not cut the ID at the "::" of an IPv6 address) and the rewrite, as
// a permit and as a forbid, and compiles to IPv6 kernel rules.
func TestRewriteLegacyIPv6Hosts(t *testing.T) {
	rw := rewriteText(t, `permit (principal, action == Action::"NetworkConnect", resource in Host::"[fd00:6::1]:8443");
forbid (principal, action == Action::"NetworkConnect", resource in Host::"fd00:6::2");
permit (principal, action == Action::"NetworkConnect", resource in Host::"10.0.0.1:8443");`)
	for _, want := range []string{`Host::"[fd00:6::1]:8443"`, `Host::"fd00:6::2"`, `Host::"10.0.0.1:8443"`} {
		if !strings.Contains(rw.Text, want) {
			t.Errorf("rewritten policy lost %s:\n%s", want, rw.Text)
		}
	}
	eng, err := engine.New(rw.Policies)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := CompileKernel(rw.Policies, eng)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, r := range ir.Connect {
		got[r.String()] = true
	}
	for _, want := range []string{"allow net.send [fd00:6::1]:8443", "deny net.send fd00:6::2", "allow net.send 10.0.0.1:8443"} {
		if !got[want] {
			t.Errorf("kernel rules %v lack %q", got, want)
		}
	}
	if !eng.DecideConnect("", "fd00:6::1", 8443).Allow || eng.DecideConnect("", "fd00:6::2", 8443).Allow {
		t.Error("engine decisions over the rewritten IPv6 policy are wrong")
	}
}

func TestParseResourceKeepsIPv6IDs(t *testing.T) {
	tr := NewCedarToLeashTranspiler()
	for in, want := range map[string]Resource{
		`Host::"fd00:6::1"`:                {Type: "Host", Value: "fd00:6::1"},
		`Host::"[2001:db8::1]:443"`:        {Type: "Host", Value: "[2001:db8::1]:443"},
		`Net::Hostname::"a.b"`:             {Type: "Host", Value: "a.b"},
		`Host::"10.0.0.1:22"`:              {Type: "Host", Value: "10.0.0.1:22"},
		`MCP::"Server::\"mcp.example.com"`: {Type: "MCPServer", Value: "mcp.example.com"}, // parseEntityString's nested form
	} {
		got := tr.parseResource(in)
		if got == nil || *got != want {
			t.Errorf("parseResource(%s) = %+v, want %+v", in, got, want)
		}
	}
}
