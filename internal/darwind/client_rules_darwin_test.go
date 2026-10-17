//go:build darwin

package darwind

import (
	"encoding/json"
	"testing"

	"github.com/strongdm/leash/internal/lsm"
	"github.com/strongdm/leash/internal/macsync"
	"github.com/strongdm/leash/internal/messages"
)

// The Control UI/API can rewrite the enforced policy, so by default it listens
// on loopback only; --serve still binds an explicit address.
func TestControlUIBindsLoopbackByDefault(t *testing.T) {
	cfg, err := parseConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.WebBind != "127.0.0.1:18080" {
		t.Fatalf("default WebBind = %q, want 127.0.0.1:18080", cfg.WebBind)
	}
	cfg, err = parseConfig([]string{"--serve", "0.0.0.0:18080"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.WebBind != "0.0.0.0:18080" {
		t.Fatalf("explicit --serve = %q", cfg.WebBind)
	}
}

// A websocket client must not be able to change the rules the extensions
// enforce: they are compiled from the Cedar policy only.
func TestClientRuleMutationsAreRefused(t *testing.T) {
	rt := &runtimeState{macSync: macsync.NewManager(nil)}
	seed, err := macsync.CompileTables(&lsm.PolicySet{ConnectDefaultExplicit: true}, macsync.Protection{})
	if err != nil {
		t.Fatal(err)
	}
	rt.macSync.SetTables(seed)
	rt.macSync.StorePolicyEvent(&messages.MacPolicyEventPayload{ID: "0123456789", Kind: "fileAccess", ProcessPath: "/bin/cat", FilePath: "/secret/x"})

	payloads := map[string]any{
		messages.TypeMacRuleAdd:           messages.MacRuleAddPayload{Rules: []messages.MacPolicyRule{{ID: "x", Kind: "fileAccess", Action: "allow", ExecutablePath: "*", Directory: "/"}}},
		messages.TypeMacRuleRemove:        messages.MacRuleRemovePayload{IDs: []string{"policy-rule"}},
		messages.TypeMacRuleClear:         map[string]any{},
		messages.TypeMacNetworkRuleUpdate: messages.MacNetworkRuleUpdatePayload{},
		messages.TypeMacPolicyDecision:    map[string]any{"event_id": "0123456789", "action": "allow", "scope": map[string]any{"type": "always"}},
	}
	for typ, payload := range payloads {
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		rt.dispatchClientEnvelope("workload", &messages.Envelope{Type: typ, Payload: raw})
	}

	if got := rt.macSync.CurrentTables(); got != seed {
		t.Fatalf("the enforced tables were changed by a client: %+v", got)
	}
}

// Only the ES extension may replace the tracked PID set the network filter
// and the transparent proxy enforce for.
func TestPIDSyncOnlyFromEndpointSecurity(t *testing.T) {
	rt := &runtimeState{macSync: macsync.NewManager(nil)}
	rt.macSync.RegisterClient("es", &messages.ClientHelloPayload{Component: macsync.ComponentEndpointSecurity})
	rt.macSync.RegisterClient("other", &messages.ClientHelloPayload{Component: "leash.cli"})
	send := func(client string, pids ...int) {
		var entries []messages.MacTrackedPID
		for _, p := range pids {
			entries = append(entries, messages.MacTrackedPID{PID: p, LeashPID: 1, Executable: "/bin/sh"})
		}
		raw, _ := json.Marshal(messages.MacPIDSyncPayload{Entries: entries})
		rt.dispatchClientEnvelope(client, &messages.Envelope{Type: messages.TypeMacPIDSync, Payload: raw})
	}
	send("es", 10, 11)
	send("other") // an empty set would stop enforcement for 10 and 11
	if got := rt.macSync.CurrentTrackedPIDs(); len(got) != 2 {
		t.Fatalf("tracked PIDs = %+v, want the ES extension's two", got)
	}
}
