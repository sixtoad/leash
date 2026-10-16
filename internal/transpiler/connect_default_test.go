package transpiler

import (
	"testing"

	"github.com/strongdm/leash/internal/lsm"
)

func hostRule(action int32, host string) lsm.PolicyRule {
	r := lsm.PolicyRule{Action: action, Operation: lsm.OpConnect, HostnameLen: int32(len(host))}
	copy(r.Hostname[:], host)
	return r
}

// Leash writes the connect default as `resource == Host::"*"`. Round-tripped
// through Cedar, that rule must act as the default and not shadow the
// explicit rules once denies are ordered first (#135).
func TestConnectDefaultRoundTripKeepsAllowlistAndDenylist(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name         string
		defaultAllow bool
		rule         lsm.PolicyRule
		allowed      []string
		denied       []string
	}{
		{"default deny with allowlist", false, hostRule(lsm.PolicyAllow, "api.openai.com"), []string{"api.openai.com"}, []string{"example.com"}},
		{"default allow with denylist", true, hostRule(lsm.PolicyDeny, "evil.test"), []string{"example.com"}, []string{"evil.test"}},
	} {
		written := PolicySetToCedar(&lsm.PolicySet{
			Connect:                []lsm.PolicyRule{tc.rule},
			ConnectDefaultAllow:    tc.defaultAllow,
			ConnectDefaultExplicit: true,
		})
		set, _, err := NewCedarToLeashTranspiler().TranspileFromString(written)
		if err != nil {
			t.Fatalf("%s: %v\n%s", tc.name, err, written)
		}
		if set.ConnectDefaultAllow != tc.defaultAllow {
			t.Fatalf("%s: default allow = %v, want %v\n%s", tc.name, set.ConnectDefaultAllow, tc.defaultAllow, written)
		}
		pc := legacyEngine(t, written)
		for _, host := range tc.allowed {
			if !pc.CheckConnect(host, "", 443) {
				t.Errorf("%s: %s denied", tc.name, host)
			}
		}
		for _, host := range tc.denied {
			if pc.CheckConnect(host, "", 443) {
				t.Errorf("%s: %s allowed", tc.name, host)
			}
		}
	}
}
