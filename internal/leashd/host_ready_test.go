package leashd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/strongdm/leash/internal/enforcement"
	"github.com/strongdm/leash/internal/entrypoint"
)

func TestEffectiveEnforcement(t *testing.T) {
	cases := []struct {
		name     string
		cfg      runtimeConfig
		degraded bool
		want     string
		layer2   string
	}{
		{name: "lsm + proxy", cfg: runtimeConfig{CgroupPath: "/sys/fs/cgroup/x", RequireLSM: true}, want: enforcement.LevelLSM, layer2: enforcement.LayerActive},
		{name: "lsm-only mode", cfg: runtimeConfig{CgroupPath: "/sys/fs/cgroup/x", LSMOnly: true, RequireLSM: true}, want: enforcement.LevelLSM, layer2: enforcement.LayerDisabled},
		{name: "attach failed, proxy-only allowed", cfg: runtimeConfig{CgroupPath: "/sys/fs/cgroup/x"}, degraded: true, want: enforcement.LevelProxyOnly, layer2: enforcement.LayerActive},
		{name: "no cgroup, proxy-only allowed", cfg: runtimeConfig{}, want: enforcement.LevelProxyOnly, layer2: enforcement.LayerActive},
		{name: "attach failed in lsm-only mode", cfg: runtimeConfig{CgroupPath: "/sys/fs/cgroup/x", LSMOnly: true}, degraded: true, want: enforcement.LevelNone, layer2: enforcement.LayerDisabled},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg
			st := effectiveEnforcement(&cfg, tc.degraded)
			if st.Enforcement != tc.want || st.Layer2 != tc.layer2 {
				t.Fatalf("got %+v, want enforcement=%s layer2=%s", st, tc.want, tc.layer2)
			}
			if st.RequireLSM != cfg.RequireLSM || st.AllowProxyOnly == cfg.RequireLSM {
				t.Fatalf("posture fields wrong: %+v", st)
			}
		})
	}
}

// The marker must stay a file whose existence gates the workload, and carry
// the effective enforcement level as JSON.
func TestWriteEnforcementReadyMarkerJSON(t *testing.T) {
	dir := t.TempDir()
	want := enforcement.Describe(true, true, true)
	writeEnforcementReadyMarker(dir, want)
	data, err := os.ReadFile(filepath.Join(dir, entrypoint.EnforcementReadyFileName))
	if err != nil {
		t.Fatalf("marker not written: %v", err)
	}
	var got enforcement.Status
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("marker is not JSON: %v (%q)", err, data)
	}
	if got != want {
		t.Fatalf("marker = %+v, want %+v", got, want)
	}
}
