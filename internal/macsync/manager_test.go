package macsync

import (
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
