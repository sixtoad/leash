package lsm_test

import (
	"fmt"
	"testing"

	"github.com/strongdm/leash/internal/lsm"
	"github.com/strongdm/leash/internal/transpiler"
)

func cedarDirPolicy(effect, action, dir string) string {
	return fmt.Sprintf("%s (principal, action == Action::%q, resource) when { resource in [ Dir::%q ] };\n", effect, action, dir)
}

// Issue #119: a Cedar Dir::"/x" rule must cover the directory /x itself
// (opendir/stat/ls), not only paths below it, while keeping byte-prefix
// safety: /x must never authorize the sibling /xy.
func TestCedarDirRuleCoversDirectoryItself(t *testing.T) {
	t.Parallel()

	const (
		allow = lsm.PolicyAllow
		deny  = lsm.PolicyDeny
	)
	p := cedarDirPolicy

	cases := []struct {
		name   string
		policy string
		path   string
		op     uint32
		want   uint32
	}{
		// Permit Dir without trailing slash, default deny.
		{"permit dir self", p("permit", "FileOpen", "/work"), "/work", lsm.OpOpenRO, allow},
		{"permit dir self rw", p("permit", "FileOpen", "/work"), "/work", lsm.OpOpenRW, allow},
		{"permit dir self trailing slash", p("permit", "FileOpen", "/work"), "/work/", lsm.OpOpenRO, allow},
		{"permit dir child", p("permit", "FileOpen", "/work"), "/work/a/b", lsm.OpOpenRO, allow},
		{"permit dir sibling prefix stays denied", p("permit", "FileOpen", "/work"), "/workspace", lsm.OpOpenRO, deny},
		{"permit dir sibling child stays denied", p("permit", "FileOpen", "/work"), "/workx/a", lsm.OpOpenRO, deny},
		{"permit dir parent stays denied", p("permit", "FileOpen", "/work"), "/", lsm.OpOpenRO, deny},
		{"permit dir truncated stays denied", p("permit", "FileOpen", "/work"), "/wor", lsm.OpOpenRO, deny},

		// Same rule written with a trailing slash.
		{"permit dir/ self", p("permit", "FileOpen", "/work/"), "/work", lsm.OpOpenRO, allow},
		{"permit dir/ sibling", p("permit", "FileOpen", "/work/"), "/workspace", lsm.OpOpenRO, deny},

		// Operation-scoped Dir rules keep their operation on the dir itself.
		{"read dir self read", p("permit", "FileOpenReadOnly", "/data"), "/data", lsm.OpOpenRO, allow},
		{"read dir self write denied", p("permit", "FileOpenReadOnly", "/data"), "/data", lsm.OpOpenRW, deny},
		{"write dir self write", p("permit", "FileOpenReadWrite", "/data"), "/data", lsm.OpOpenRW, allow},

		// Nested dirs: a forbid on the inner dir covers the inner dir itself.
		{"forbid inner dir self", p("permit", "FileOpen", "/work") + p("forbid", "FileOpen", "/work/secret"), "/work/secret", lsm.OpOpenRO, deny},
		{"forbid inner dir child", p("permit", "FileOpen", "/work") + p("forbid", "FileOpen", "/work/secret"), "/work/secret/k", lsm.OpOpenRO, deny},
		{"forbid inner dir sibling allowed", p("permit", "FileOpen", "/work") + p("forbid", "FileOpen", "/work/secret"), "/work/secrets", lsm.OpOpenRO, allow},
		{"forbid inner dir keeps outer self", p("permit", "FileOpen", "/work") + p("forbid", "FileOpen", "/work/secret"), "/work", lsm.OpOpenRO, allow},

		// Default allow ("/" permitted) with a forbidden Dir: the dir itself is denied too.
		{"forbid dir self under default allow", p("permit", "FileOpen", "/") + p("forbid", "FileOpen", "/etc/ssh"), "/etc/ssh", lsm.OpOpenRO, deny},
		{"forbid dir sibling under default allow", p("permit", "FileOpen", "/") + p("forbid", "FileOpen", "/etc/ssh"), "/etc/sshd", lsm.OpOpenRO, allow},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			set, _, err := transpiler.NewCedarToLeashTranspiler().TranspileFromString(tc.policy)
			if err != nil {
				t.Fatalf("transpile: %v\n%s", err, tc.policy)
			}
			if err := lsm.ValidateOpenRulesForTest(set.Open); err != nil {
				t.Fatalf("kernel validation rejected transpiled rules: %v", err)
			}
			if got := lsm.OpenDecisionForTest(set.Open, tc.path, tc.op); got != tc.want {
				t.Fatalf("decision(%q, op=%d) = %d, want %d\npolicy:\n%s", tc.path, tc.op, got, tc.want, tc.policy)
			}
		})
	}
}
