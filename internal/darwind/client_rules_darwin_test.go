//go:build darwin

package darwind

import (
	"encoding/json"
	"testing"

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
	seed := messages.MacPolicyRule{ID: "policy-rule", Kind: "fileAccess", Action: "deny", ExecutablePath: "*", Directory: "/secret/"}
	rt.macSync.AddPolicyRules([]messages.MacPolicyRule{seed})
	rt.macSync.UpdateNetworkRules([]messages.MacNetworkRule{{ID: "net-rule", TargetType: "domain", TargetValue: "evil.test", Action: "deny", Enabled: true}})
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

	rules := rt.macSync.GetPolicyRules()
	if len(rules) != 1 || rules[0].ID != "policy-rule" || rules[0].Action != "deny" {
		t.Fatalf("file/exec rules changed by a client: %+v", rules)
	}
	net := rt.macSync.GetNetworkRules()
	if len(net) != 1 || net[0].ID != "net-rule" {
		t.Fatalf("network rules changed by a client: %+v", net)
	}
}
