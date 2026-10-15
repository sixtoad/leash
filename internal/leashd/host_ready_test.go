package leashd

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
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
			st := effectiveEnforcement(&cfg, tc.degraded, tc.attached, enforcement.LSMListActive, "")
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

// Real-kernel finding on #117 (Ubuntu 24.04, 6.8.0): with CONFIG_BPF_LSM=y but
// bpf not in the active list, every program attaches yet no hook runs. Layer 1
// must not be reported active from attach success alone.
func TestEffectiveEnforcementRequiresActiveBPFLSM(t *testing.T) {
	orig := readActiveLSMList
	t.Cleanup(func() { readActiveLSMList = orig })

	cases := []struct {
		name       string
		list       string
		readErr    error
		allowProxy bool
		want       string
		releasable bool
	}{
		{name: "bpf active", list: "lockdown,capability,yama,apparmor,bpf\n", want: enforcement.LevelLSM, releasable: true},
		{name: "bpf inactive, fail-closed", list: "lockdown,capability,landlock,yama,apparmor\n", want: enforcement.LevelProxyOnly, releasable: false},
		{name: "bpf inactive, proxy-only allowed", list: "lockdown,capability,landlock,yama,apparmor\n", allowProxy: true, want: enforcement.LevelProxyOnly, releasable: true},
		{name: "list unreadable, fail-closed", readErr: errors.New("no such file or directory"), want: enforcement.LevelProxyOnly, releasable: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			readActiveLSMList = func() ([]byte, error) { return []byte(tc.list), tc.readErr }
			cfg := runtimeConfig{CgroupPath: "/sys/fs/cgroup/x", RequireLSM: !tc.allowProxy}
			state, reason := enforcement.ClassifyLSMList(readActiveLSMList())
			// Every program attached successfully: only the LSM list decides.
			st := effectiveEnforcement(&cfg, false, 3, state, reason)
			if st.Enforcement != tc.want {
				t.Fatalf("enforcement = %s, want %s (%+v)", st.Enforcement, tc.want, st)
			}
			err := st.Check(st.RequireLSM)
			if (err == nil) != tc.releasable {
				t.Fatalf("Check = %v, releasable want %v", err, tc.releasable)
			}
			if st.Enforcement != enforcement.LevelLSM {
				if st.Reason == "" {
					t.Fatal("a non-lsm level must carry a reason")
				}
				if err != nil && !strings.Contains(err.Error(), st.Reason) {
					t.Fatalf("refusal must echo the reason %q: %v", st.Reason, err)
				}
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
