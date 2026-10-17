package darwind

import (
	"strings"
	"testing"

	"github.com/strongdm/leash/internal/macext"
)

func TestDecideDarwinEnforcementRequiresBothExtensions(t *testing.T) {
	t.Parallel()
	const es, ne = "com.strongdm.leash.LeashES", "com.strongdm.leash.LeashNetworkFilter"
	if err := decideDarwinEnforcement(es, ne, macext.StateActive, macext.StateActive, ""); err != nil {
		t.Fatalf("both active: %v", err)
	}
	for _, tc := range []struct {
		name   string
		es, ne macext.State
	}{
		{"es missing", macext.StateMissing, macext.StateActive},
		{"ne disabled", macext.StateActive, macext.StateDisabled},
		{"unknown", macext.StateUnknown, macext.StateUnknown},
		{"both missing", macext.StateMissing, macext.StateMissing},
	} {
		err := decideDarwinEnforcement(es, ne, tc.es, tc.ne, "")
		if err == nil {
			t.Fatalf("%s: started without enforcement", tc.name)
		}
		if !strings.Contains(err.Error(), "will not start") || !strings.Contains(err.Error(), "Activate them") {
			t.Fatalf("%s: error lacks the refusal and remedy: %v", tc.name, err)
		}
	}
	err := decideDarwinEnforcement(es, ne, macext.StateUnknown, macext.StateUnknown, "exit status 69: permission denied")
	if err == nil || !strings.Contains(err.Error(), "exit status 69") {
		t.Fatalf("query failure reason not surfaced: %v", err)
	}
}

func TestRefuseUnsupportedDarwinFlags(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"--inject-service", "plugin=/x,env=A,socket=/s", "--", "true"},
		{"--inject-service=plugin=/x,env=A,socket=/s,authz=Walk", "true"},
		{"-v", "-C", "/tmp", "--inject-service", "x", "true"},
	} {
		if err := refuseUnsupportedDarwinFlags(args); err == nil || !strings.Contains(err.Error(), "not supported in native macOS mode") {
			t.Fatalf("%q: want a refusal, got %v", args, err)
		}
	}
	for _, args := range [][]string{
		{"--", "tool", "--inject-service", "x"},
		{"tool", "--inject-service"},
		{"-C", "--inject-service", "true"}, // the directory value, not an option
		{"-v", "true"},
	} {
		if err := refuseUnsupportedDarwinFlags(args); err != nil {
			t.Fatalf("%q: the workload's own arguments were refused: %v", args, err)
		}
	}
}
