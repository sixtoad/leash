package macsync

import (
	"strings"
	"testing"

	"github.com/strongdm/leash/internal/messages"
)

func TestUnregisterClientRemovesStaleEntry(t *testing.T) {
	m := NewManager(nil)

	hello := &messages.ClientHelloPayload{Platform: "darwin", Capabilities: []string{"pid-sync"}}
	m.RegisterClient("a", hello)
	m.RegisterClient("b", hello)
	m.RegisterClient("c", hello)

	if got := len(m.GetAllClients()); got != 3 {
		t.Fatalf("expected 3 clients, got %d", got)
	}

	m.UnregisterClient("b")

	clients := m.GetAllClients()
	if len(clients) != 2 {
		t.Fatalf("expected 2 clients after unregister, got %d", len(clients))
	}
	for _, c := range clients {
		if c.ID == "b" {
			t.Fatalf("client b should have been removed")
		}
	}

	// Unregistering an unknown or empty ID must be a no-op, not a panic.
	m.UnregisterClient("b")
	m.UnregisterClient("")
	if got := len(m.GetAllClients()); got != 2 {
		t.Fatalf("expected 2 clients to remain, got %d", got)
	}
}

func TestConnectedComponentsTracksWhichExtensionIsMissing(t *testing.T) {
	m := NewManager(nil)

	m.RegisterClient("es", &messages.ClientHelloPayload{Platform: "darwin", Component: ComponentEndpointSecurity})
	m.RegisterClient("filter", &messages.ClientHelloPayload{Platform: "darwin", Component: "  Leash.NetFilter  "})
	m.RegisterClient("proxy", &messages.ClientHelloPayload{Platform: "darwin", Component: ComponentTransparentProxy})

	got := strings.Join(m.ConnectedComponents(), ",")
	want := strings.Join([]string{ComponentEndpointSecurity, ComponentNetworkFilter, ComponentTransparentProxy}, ",")
	if got != want {
		t.Fatalf("expected components %q, got %q", want, got)
	}

	// The degraded-filter case from #62: the provider drops off the websocket and
	// the daemon must be able to name which component went away.
	m.UnregisterClient("filter")
	for _, component := range m.ConnectedComponents() {
		if component == ComponentNetworkFilter {
			t.Fatalf("network filter should no longer be listed as connected")
		}
	}

	// A hello without a component (older extension build) is still tracked.
	m.RegisterClient("legacy", &messages.ClientHelloPayload{Platform: "darwin"})
	var sawUnknown bool
	for _, component := range m.ConnectedComponents() {
		if component == ComponentUnknown {
			sawUnknown = true
		}
	}
	if !sawUnknown {
		t.Fatalf("expected a component-less hello to register as %q", ComponentUnknown)
	}
}

func TestConnectedComponentsDeduplicates(t *testing.T) {
	m := NewManager(nil)

	// Reconnect churn can leave two live connections for the same component
	// briefly; the component list must not report it twice.
	m.RegisterClient("app-1", &messages.ClientHelloPayload{Platform: "darwin", Component: ComponentApp})
	m.RegisterClient("app-2", &messages.ClientHelloPayload{Platform: "darwin", Component: ComponentApp})

	if got := m.ConnectedComponents(); len(got) != 1 || got[0] != ComponentApp {
		t.Fatalf("expected exactly [%s], got %v", ComponentApp, got)
	}
}
