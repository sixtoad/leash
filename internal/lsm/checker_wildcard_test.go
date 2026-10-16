package lsm

import (
	"strings"
	"testing"
)

func checkerHostRule(action int32, host string) ConnectPolicyRule {
	r := PolicyRule{Action: action, Operation: OpConnect, HostnameLen: int32(len(host))}
	copy(r.Hostname[:], host)
	if strings.HasPrefix(host, "*.") {
		r.IsWildcard = 1
	}
	return ConvertToConnectRules([]PolicyRule{r})[0]
}

// A wildcard needs a label boundary: before, "*.example.com" matched
// "evilexample.com" (the suffix check lacked the dot), which widened a
// permit and let a wildcard forbid hit unrelated hosts. Names compare
// case-insensitively and a trailing dot is ignored.
func TestCheckConnectWildcardNeedsALabelBoundary(t *testing.T) {
	pc := newLegacyChecker([]ConnectPolicyRule{checkerHostRule(PolicyAllow, "*.example.com")}, false, nil)
	for host, want := range map[string]bool{
		"api.example.com":   true,
		"a.b.example.com":   true,
		"API.Example.COM":   true,
		"api.example.com.":  true,
		"example.com":       false,
		"evilexample.com":   false,
		"xexample.com":      false,
		"example.com.evil":  false,
		"xexample.com.test": false,
	} {
		if got := pc.CheckConnect(host, "", 443); got != want {
			t.Errorf("%q: allow=%v, want %v", host, got, want)
		}
	}
}

func TestCheckConnectExactHostIsCaseInsensitive(t *testing.T) {
	pc := newLegacyChecker([]ConnectPolicyRule{checkerHostRule(PolicyDeny, "API.example.com")}, true, nil)
	for host, want := range map[string]bool{
		"api.example.com":  false,
		"Api.Example.Com.": false,
		"web.example.com":  true,
	} {
		if got := pc.CheckConnect(host, "", 443); got != want {
			t.Errorf("%q: allow=%v, want %v", host, got, want)
		}
	}
}
