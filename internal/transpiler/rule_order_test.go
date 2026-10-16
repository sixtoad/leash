package transpiler

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/strongdm/leash/internal/lsm"
)

// Issue #135: the Cedar policy set is a Go map; the transpiled rules must come
// out in source order on every run.
func TestCedarToLeashTranspiler_RuleOrderIsSourceOrder(t *testing.T) {
	t.Parallel()

	var src strings.Builder
	var want []string
	for i := 0; i < 24; i++ {
		effect := "permit"
		if i%3 == 0 {
			effect = "forbid"
		}
		path := fmt.Sprintf("/order/%02d", i)
		fmt.Fprintf(&src, "%s (principal, action == Action::\"FileOpen\", resource) when { resource in [ File::%q ] };\n", effect, path)
		fmt.Fprintf(&src, "%s (principal, action == Action::\"ProcessExec\", resource) when { resource in [ File::%q ] };\n", effect, path+"/bin")
		fmt.Fprintf(&src, "%s (principal, action == Action::\"NetworkConnect\", resource) when { resource in [ Host::%q ] };\n", effect, fmt.Sprintf("10.0.0.%d", i+1))
		want = append(want, path)
	}

	first, _, err := NewCedarToLeashTranspiler().TranspileFromString(src.String())
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Open) != len(want) || len(first.Exec) != len(want) || len(first.Connect) != len(want) {
		t.Fatalf("rule counts open=%d exec=%d connect=%d, want %d each", len(first.Open), len(first.Exec), len(first.Connect), len(want))
	}
	for i, rule := range first.Open {
		if got := string(rule.Path[:rule.PathLen]); got != want[i] {
			t.Fatalf("open rule %d = %q, want %q (source order)", i, got, want[i])
		}
		wantAction := int32(lsm.PolicyAllow)
		if i%3 == 0 {
			wantAction = lsm.PolicyDeny
		}
		if rule.Action != wantAction {
			t.Fatalf("open rule %d action %d, want %d", i, rule.Action, wantAction)
		}
	}
	for i := 0; i < 50; i++ {
		again, _, err := NewCedarToLeashTranspiler().TranspileFromString(src.String())
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(again, first) {
			t.Fatalf("transpile %d produced a different rule set or order", i)
		}
	}
}
