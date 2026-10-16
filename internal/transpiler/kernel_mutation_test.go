package transpiler

import (
	"strings"
	"testing"

	"github.com/strongdm/leash/internal/lsm"
)

func mutationRules(ir *lsm.PolicySet) []string {
	var out []string
	for _, r := range ir.Open {
		if r.Operation == lsm.OpMutation {
			kind := ""
			if r.IsDirectory == lsm.ExactPath {
				kind = " (exact)"
			}
			out = append(out, r.String()+kind)
		}
	}
	return out
}

func TestCompileMutationRules(t *testing.T) {
	cases := []struct {
		name, text string
		want       []string
	}{
		{"default policy: everything mutable",
			`permit (principal, action in Action::"FileOpen", resource in Dir::"/");`,
			[]string{"allow file.mutate /"}},
		{"read-only grants no mutation",
			`permit (principal, action == Action::"FileOpenReadOnly", resource in Dir::"/");`,
			[]string{"deny file.mutate /"}},
		{"a granted tree, not the directory itself (its parent is not writable)",
			`permit (principal, action == Action::"FileOpenReadWrite", resource in Dir::"/work/");`,
			[]string{"allow file.mutate /work/"}},
		{"a forbid nested in a permit",
			`permit (principal, action in Action::"FileOpen", resource in Dir::"/");
forbid (principal, action in Action::"FileOpen", resource in Dir::"/etc/");`,
			[]string{"allow file.mutate /", "deny file.mutate /etc/", "deny file.mutate /etc (exact)"}},
		{"a permit nested in a forbid (an unless exception) under default deny",
			`forbid (principal, action in Action::"FileOpen", resource in Dir::"/srv/") unless { resource in Dir::"/srv/ok/" };
permit (principal, action in Action::"FileOpen", resource in Dir::"/srv/ok/");`,
			[]string{"allow file.mutate /srv/ok/"}},
		{"an exact forbid",
			`permit (principal, action in Action::"FileOpen", resource in Dir::"/");
forbid (principal, action in Action::"FileOpen", resource == File::"/etc/hosts");`,
			[]string{"allow file.mutate /", "deny file.mutate /etc/hosts (exact)"}},
	}
	for _, tc := range cases {
		ir, err := compileKernelText(t, "@leash_semantics(\"cedar\")\n"+tc.text)
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if got := mutationRules(ir); strings.Join(got, "|") != strings.Join(tc.want, "|") {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}

	// A permit nested in a forbid nested in a permit cannot be enforced by
	// the deny-first mutation table.
	_, err := compileKernelText(t, `@leash_semantics("cedar")
permit (principal, action in Action::"FileOpen", resource in Dir::"/");
forbid (principal, action in Action::"FileOpen", resource in Dir::"/srv/") unless { resource in Dir::"/srv/ok/" };
permit (principal, action in Action::"FileOpen", resource in Dir::"/srv/ok/");`)
	if err == nil || !strings.Contains(err.Error(), "directory mutations") || !strings.Contains(err.Error(), "/srv/ok/") {
		t.Fatalf("got %v", err)
	}
}
