//go:build darwin

package darwind

import (
	"testing"

	cedarutil "github.com/strongdm/leash/internal/cedar"
	"github.com/strongdm/leash/internal/engine"
)

// A statement the policy API builds from an observed action joins the
// runtime layer it is added to: an unmarked (strict, the default) layer or a
// layer marked @leash_semantics("legacy"). It must load in both and decide
// the observed request the way it says.
func TestActionPoliciesReadTheSameInBothDialects(t *testing.T) {
	for _, tc := range []struct {
		action actionPayload
		check  func(*engine.Engine) bool
	}{
		{actionPayload{Type: "file/open", Name: "/etc/hosts"}, func(e *engine.Engine) bool {
			return e.DecideOpen("/etc/hosts", engine.ActionFileOpenReadOnly).Allow && e.DecideOpen("/etc/hosts", engine.ActionFileOpenReadWrite).Allow
		}},
		{actionPayload{Type: "file/open", Name: "/work/"}, func(e *engine.Engine) bool {
			return e.DecideOpen("/work/a/b", engine.ActionFileOpenReadOnly).Allow
		}},
		{actionPayload{Type: "file/write", Name: "/tmp/out"}, func(e *engine.Engine) bool {
			return e.DecideOpen("/tmp/out", engine.ActionFileOpenReadWrite).Allow
		}},
		{actionPayload{Type: "proc/exec", Name: "/usr/bin/git status"}, func(e *engine.Engine) bool {
			return e.DecideExec("/usr/bin/git").Allow
		}},
		{actionPayload{Type: "net/connect", Name: "api.example.com:443"}, func(e *engine.Engine) bool {
			return e.DecideConnect("api.example.com", "", 443).Allow
		}},
		{actionPayload{Type: "mcp/call", Server: "mcp.example.com", Tool: "search"}, func(e *engine.Engine) bool {
			return e.DecideMCP("mcp.example.com", "search").Allow
		}},
	} {
		stmt, err := buildCedarFromActionRequest(addPolicyFromActionRequest{Effect: "permit", Action: tc.action})
		if err != nil {
			t.Fatal(err)
		}
		for name, layer := range map[string]string{
			"strict": stmt,
			"legacy": stmt + "\n\n@leash_semantics(\"legacy\")\nforbid (principal, action == Action::\"ProcessExec\", resource in Dir::\"/nonexistent/\");",
		} {
			comp, err := cedarutil.CompileString("runtime.cedar", layer)
			if err != nil {
				t.Fatalf("%s %s: %v\n%s", tc.action.Type, name, err, layer)
			}
			if !tc.check(comp.Engine) {
				t.Errorf("%s %s: the statement does not allow the observed request:\n%s", tc.action.Type, name, stmt)
			}
		}
	}
}
