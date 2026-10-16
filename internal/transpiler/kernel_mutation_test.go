package transpiler

import (
	"strings"
	"testing"

	cedarlib "github.com/cedar-policy/cedar-go"

	"github.com/strongdm/leash/internal/engine"
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

	// An exact permit carved out of an excluded FilePrefix: Cedar allows
	// mutating that one path, the table has no exact allow, so the kernel
	// denies it and the compiler warns, naming the policy and its line.
	ps, err := cedarlib.NewPolicySetFromBytes("strict.cedar", []byte(`@leash_semantics("cedar")
permit (principal, action in Action::"FileOpen", resource) unless { resource in FilePrefix::"/etc/hostname" };
@leash_semantics("cedar")
@id("hostname-exact")
permit (principal, action in Action::"FileOpen", resource == File::"/etc/hostname");`))
	if err != nil {
		t.Fatal(err)
	}
	eng, err := engine.New(ps)
	if err != nil {
		t.Fatal(err)
	}
	if !eng.DecideMutation("/etc/hostname").Allow {
		t.Fatal("Cedar allows mutating /etc/hostname")
	}
	ir, warnings, err := CompileKernelReport(ps, eng)
	if err != nil {
		t.Fatalf("must load: %v", err)
	}
	if len(warnings) != 1 || warnings[0].Path != "/etc/hostname" || warnings[0].Policy != "hostname-exact at strict.cedar:3:1" {
		t.Fatalf("warnings: %+v", warnings)
	}
	if got := strings.Join(mutationRules(ir), "|"); got != "allow file.mutate /|deny file.mutate /etc/hostname" {
		t.Fatalf("mutation rules: %s", got)
	}

	// A permit nested in a forbid nested in a permit (a legacy exception):
	// the longest-prefix table expresses it.
	ir, err = compileKernelText(t, `@leash_semantics("cedar")
permit (principal, action in Action::"FileOpen", resource in Dir::"/");
forbid (principal, action in Action::"FileOpen", resource in Dir::"/srv/") unless { resource in Dir::"/srv/ok/" };
permit (principal, action in Action::"FileOpen", resource in Dir::"/srv/ok/");`)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(mutationRules(ir), "|"); got != "allow file.mutate /|deny file.mutate /srv/|allow file.mutate /srv/ok/|deny file.mutate /srv (exact)" {
		t.Fatalf("got %s", got)
	}
}
