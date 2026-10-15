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
	const cg = "/sys/fs/cgroup/x"
	cases := []struct {
		name       string
		cfg        runtimeConfig
		degraded   bool
		attached   int
		want       string
		layer2     string
		releasable bool
	}{
		{name: "lsm + proxy", cfg: runtimeConfig{CgroupPath: cg, RequireLSM: true}, attached: 3, want: enforcement.LevelLSM, layer2: enforcement.LayerActive, releasable: true},
		{name: "lsm-only mode", cfg: runtimeConfig{CgroupPath: cg, LSMOnly: true, RequireLSM: true}, attached: 3, want: enforcement.LevelLSM, layer2: enforcement.LayerDisabled, releasable: true},
		{name: "attach failed, proxy-only allowed", cfg: runtimeConfig{CgroupPath: cg}, degraded: true, attached: 2, want: enforcement.LevelProxyOnly, layer2: enforcement.LayerActive, releasable: true},
		{name: "no cgroup, proxy-only allowed", cfg: runtimeConfig{}, want: enforcement.LevelProxyOnly, layer2: enforcement.LayerActive, releasable: true},
		// Review finding: --allow-proxy-only with the proxy also off must not
		// release (lsm-only forces fail-closed; level is "none").
		{name: "attach failed in lsm-only mode", cfg: runtimeConfig{CgroupPath: cg, LSMOnly: true}, degraded: true, want: enforcement.LevelNone, layer2: enforcement.LayerDisabled, releasable: false},
		// Review finding: nothing attached (e.g. a policy that created no LSM
		// modules) must not be reported as "lsm".
		{name: "zero programs attached, fail-closed", cfg: runtimeConfig{CgroupPath: cg, RequireLSM: true}, want: enforcement.LevelProxyOnly, layer2: enforcement.LayerActive, releasable: false},
		{name: "attach failed, fail-closed", cfg: runtimeConfig{CgroupPath: cg, RequireLSM: true}, degraded: true, attached: 1, want: enforcement.LevelProxyOnly, layer2: enforcement.LayerActive, releasable: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg
			st := effectiveEnforcement(&cfg, tc.degraded, tc.attached)
			if st.Enforcement != tc.want || st.Layer2 != tc.layer2 {
				t.Fatalf("got %+v, want enforcement=%s layer2=%s", st, tc.want, tc.layer2)
			}
			if st.RequireLSM != cfg.failClosed() || st.AllowProxyOnly == cfg.failClosed() {
				t.Fatalf("posture fields wrong: %+v", st)
			}
			if err := st.Check(st.RequireLSM); (err == nil) != tc.releasable {
				t.Fatalf("Check = %v, releasable want %v", err, tc.releasable)
			}
		})
	}
}

func TestFailClosedForcedInLSMOnly(t *testing.T) {
	if !(&runtimeConfig{LSMOnly: true}).failClosed() {
		t.Fatal("--lsm-only has no proxy to degrade to: must fail closed even with --allow-proxy-only")
	}
	if (&runtimeConfig{}).failClosed() {
		t.Fatal("proxy-only allowed with the proxy active should not fail closed")
	}
}

// The marker must stay a file whose existence gates the workload, and carry
// the effective enforcement level as JSON. It is written atomically (no temp
// file left behind).
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
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected only the marker in %s, found %d entries", dir, len(entries))
	}
}
