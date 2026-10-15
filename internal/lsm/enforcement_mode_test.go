package lsm

import (
	"strings"
	"testing"

	"github.com/strongdm/leash/internal/enforcement"
)

// leashd sets the fatal-attach remedy for the session's real state; with the
// proxy off it must not tell the operator to pass --allow-proxy-only.
func TestSetFailClosedRemedy(t *testing.T) {
	orig := FailClosedRemedy()
	t.Cleanup(func() { failClosedRemedy = orig })

	SetFailClosedRemedy(enforcement.FailClosedRemedy(false))
	got := FailClosedRemedy()
	if strings.Contains(got, "pass --allow-proxy-only") || !strings.Contains(got, "fix the egress setup or run as root") {
		t.Fatalf("proxy-off remedy = %q", got)
	}
	SetFailClosedRemedy("")
	if FailClosedRemedy() != got {
		t.Fatal("an empty remedy must not clear the current one")
	}
	SetFailClosedRemedy(enforcement.FailClosedRemedy(true))
	if !strings.Contains(FailClosedRemedy(), "pass --allow-proxy-only") {
		t.Fatalf("proxy-up remedy = %q", FailClosedRemedy())
	}
}
