package proxy

import (
	"sync"
	"testing"

	"github.com/strongdm/leash/internal/engine"
)

func TestSetEngineInstallsTheDecisionEngine(t *testing.T) {
	e, err := engine.NewFromText("p.cedar", `
@leash_semantics("cedar")
permit (principal, action == Action::"NetworkConnect", resource in Host::"*.example.com");
forbid (principal, action == Action::"NetworkConnect", resource in Host::"bad.example.com");`)
	if err != nil {
		t.Fatal(err)
	}
	p := &MITMProxy{}
	p.SetEngine(e)
	for host, want := range map[string]bool{
		"api.example.com": true,
		"API.Example.com": true,
		"bad.example.com": false, // forbid overrides permit
		"evilexample.com": false, // label boundary
		"example.com":     false,
	} {
		if got := p.checkConnectPolicy(host, "203.0.113.1", 443); got != want {
			t.Errorf("%s: allow=%v, want %v", host, got, want)
		}
	}
	var none *MITMProxy
	none.SetEngine(e) // nil-safe consumer
	p.SetEngine(nil)
	if p.checker() != e {
		t.Fatal("SetEngine(nil) must keep the current engine")
	}
}

// Policy reloads swap the checker while requests read it.
func TestPolicyCheckerSwapIsRaceFree(t *testing.T) {
	a, _ := engine.NewFromText("a", `permit (principal, action, resource);`)
	b, _ := engine.NewFromText("b", ``)
	p := &MITMProxy{}
	p.SetEngine(a)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				p.checkConnectPolicy("x.org", "203.0.113.1", 443)
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				if j%2 == 0 {
					p.SetEngine(a)
				} else {
					p.SetEngine(b)
				}
			}
		}()
	}
	wg.Wait()
}
