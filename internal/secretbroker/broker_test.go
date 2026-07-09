package secretbroker

import "testing"

func TestAllowlistServesOnlyAllowed(t *testing.T) {
	a := NewAllowlist([]string{"antigravity", "", "cloudcode"})

	if !a.Enabled() {
		t.Fatal("allow-list with entries should be enabled")
	}
	for _, svc := range []string{"antigravity", "cloudcode"} {
		if !a.AllowsService(svc) {
			t.Fatalf("service %q should be allowed", svc)
		}
	}
	// Everything else — other tokens, browser, ssh — must be denied.
	for _, svc := range []string{"chrome", "ssh", "gh", "", "ANTIGRAVITY", "antigravity "} {
		if a.AllowsService(svc) {
			t.Fatalf("service %q must be denied", svc)
		}
	}
}

func TestAllowlistAttributes(t *testing.T) {
	a := NewAllowlist([]string{"antigravity"})

	if !a.AllowsAttributes(map[string]string{"service": "antigravity", "username": "x"}) {
		t.Fatal("item with allowed service attribute should be served")
	}
	// Denied service, or no service attribute at all → hidden.
	for _, attrs := range []map[string]string{
		{"service": "chrome"},
		{"username": "x"}, // no service key
		{},
		nil,
	} {
		if a.AllowsAttributes(attrs) {
			t.Fatalf("attributes %v must be denied", attrs)
		}
	}
}

// Default-deny: an empty allow-list is disabled and serves nothing.
func TestEmptyAllowlistDeniesAll(t *testing.T) {
	a := NewAllowlist(nil)
	if a.Enabled() {
		t.Fatal("empty allow-list must be disabled")
	}
	if a.AllowsService("antigravity") || a.AllowsAttributes(map[string]string{"service": "antigravity"}) {
		t.Fatal("empty allow-list must serve nothing")
	}
}
