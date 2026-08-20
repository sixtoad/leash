package darwind

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/strongdm/leash/internal/macext"
)

func fetchHealth(t *testing.T, snapshot func() macext.DaemonHealth) (*http.Response, macext.DaemonHealth) {
	t.Helper()
	rec := httptest.NewRecorder()
	darwinHealthHandler(snapshot)(rec, httptest.NewRequest(http.MethodGet, "/health/darwin", nil))
	resp := rec.Result()
	t.Cleanup(func() { _ = resp.Body.Close() })

	var health macext.DaemonHealth
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		t.Fatalf("the health document must decode into what doctor reads: %v", err)
	}
	return resp, health
}

func TestDarwinHealthReportsTheSnapshot(t *testing.T) {
	resp, health := fetchHealth(t, func() macext.DaemonHealth {
		return macext.DaemonHealth{
			Components:     []string{macext.ComponentEndpointSecurity},
			FullDiskAccess: macext.FDAGranted.String(),
		}
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Errorf("content type = %q", got)
	}
	if macext.ParseFDA(health.FullDiskAccess) != macext.FDAGranted {
		t.Errorf("full_disk_access = %q", health.FullDiskAccess)
	}
	if len(health.Components) != 1 || health.Components[0] != macext.ComponentEndpointSecurity {
		t.Errorf("components = %v", health.Components)
	}
}

// A daemon with no macsync yet still has to answer, and its answer has to be
// "unknown" rather than an empty document: doctor reads a missing
// full_disk_access as unknown either way, but a 503 or a null components list
// would be read as the daemon being down, whose remedy is different.
func TestDarwinHealthAnswersBeforeAnythingIsKnown(t *testing.T) {
	for name, snapshot := range map[string]func() macext.DaemonHealth{
		"no manager":    nil,
		"empty manager": func() macext.DaemonHealth { return macext.DaemonHealth{} },
	} {
		t.Run(name, func(t *testing.T) {
			resp, health := fetchHealth(t, snapshot)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200 even with nothing known", resp.StatusCode)
			}
			if health.Components == nil {
				t.Error("components must be [] rather than null")
			}
			if macext.ParseFDA(health.FullDiskAccess) != macext.FDAUnknown {
				t.Errorf("full_disk_access = %q, want unknown", health.FullDiskAccess)
			}
		})
	}
}
