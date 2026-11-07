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
	"github.com/strongdm/leash/internal/lsm"
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
		{name: "lsm + proxy", cfg: runtimeConfig{CgroupPath: cg}, attached: 3, want: enforcement.LevelLSM, layer2: enforcement.LayerActive, releasable: true},
		{name: "lsm-only mode", cfg: runtimeConfig{CgroupPath: cg, LSMOnly: true}, attached: 3, want: enforcement.LevelLSM, layer2: enforcement.LayerDisabled, releasable: true},
		// Layer 1 unavailable is refused even with the proxy up: leash never
		// runs a workload with only the L7 proxy enforcing.
		{name: "attach failed, proxy up", cfg: runtimeConfig{CgroupPath: cg}, degraded: true, attached: 2, want: enforcement.LevelNone, layer2: enforcement.LayerActive},
		{name: "no cgroup, proxy up", cfg: runtimeConfig{}, want: enforcement.LevelNone, layer2: enforcement.LayerActive},
		{name: "attach failed in lsm-only mode", cfg: runtimeConfig{CgroupPath: cg, LSMOnly: true}, degraded: true, want: enforcement.LevelNone, layer2: enforcement.LayerDisabled},
		// Nothing attached (e.g. a policy that created no LSM modules) must
		// not be reported as "lsm".
		{name: "zero programs attached", cfg: runtimeConfig{CgroupPath: cg}, want: enforcement.LevelNone, layer2: enforcement.LayerActive},
		{name: "attach failed, one program attached", cfg: runtimeConfig{CgroupPath: cg}, degraded: true, attached: 1, want: enforcement.LevelNone, layer2: enforcement.LayerActive},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg
			st := effectiveEnforcement(&cfg, tc.degraded, tc.attached, enforcement.LSMListActive, "")
			if st.Enforcement != tc.want || st.Layer2 != tc.layer2 {
				t.Fatalf("got %+v, want enforcement=%s layer2=%s", st, tc.want, tc.layer2)
			}
			if !st.RequireLSM {
				t.Fatalf("requireLSM must always be true: %+v", st)
			}
			if err := st.Check(); (err == nil) != tc.releasable {
				t.Fatalf("Check = %v, releasable want %v", err, tc.releasable)
			}
		})
	}
}

// Real-kernel finding on #117 (Ubuntu 24.04, 6.8.0): with CONFIG_BPF_LSM=y but
// bpf not in the active list, every program attaches yet no hook runs. Layer 1
// must not be reported active from attach success alone, and the run is
// refused.
func TestEffectiveEnforcementRequiresActiveBPFLSM(t *testing.T) {
	orig := readActiveLSMList
	t.Cleanup(func() { readActiveLSMList = orig })

	cases := []struct {
		name       string
		list       string
		readErr    error
		want       string
		releasable bool
	}{
		{name: "bpf active", list: "lockdown,capability,yama,apparmor,bpf\n", want: enforcement.LevelLSM, releasable: true},
		{name: "bpf inactive", list: "lockdown,capability,landlock,yama,apparmor\n", want: enforcement.LevelNone},
		{name: "list unreadable", readErr: errors.New("no such file or directory"), want: enforcement.LevelNone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			readActiveLSMList = func() ([]byte, error) { return []byte(tc.list), tc.readErr }
			cfg := runtimeConfig{CgroupPath: "/sys/fs/cgroup/x"}
			state, reason := enforcement.ClassifyLSMList(readActiveLSMList())
			// Every program attached successfully: only the LSM list decides.
			st := effectiveEnforcement(&cfg, false, 3, state, reason)
			if st.Enforcement != tc.want {
				t.Fatalf("enforcement = %s, want %s (%+v)", st.Enforcement, tc.want, st)
			}
			err := st.Check()
			if (err == nil) != tc.releasable {
				t.Fatalf("Check = %v, releasable want %v", err, tc.releasable)
			}
			if st.Enforcement != enforcement.LevelLSM {
				if st.Reason == "" {
					t.Fatal("a non-lsm level must carry a reason")
				}
				if !strings.Contains(err.Error(), st.Reason) {
					t.Fatalf("refusal must echo the reason %q: %v", st.Reason, err)
				}
			}
		})
	}
}

// The marker must stay a file whose existence gates the workload, and carry
// the effective enforcement level as JSON. It is written atomically (no temp
// file left behind).
func TestWriteEnforcementReadyMarkerJSON(t *testing.T) {
	dir := t.TempDir()
	want := enforcement.Describe(true, true)
	writeEnforcementReadyMarker(dir, want)
	data, err := os.ReadFile(filepath.Join(dir, entrypoint.EnforcementReadyFileName))
	if err != nil {
		t.Fatalf("marker not written: %v", err)
	}
	var got enforcement.Status
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("marker is not JSON: %v (%q)", err, data)
	}
	// An active Layer 1 also states the audit posture (#241).
	if got.Audit == nil || got.Audit.RingBufferBytes != lsm.DefaultAuditRingBufferBytes || got.Audit.Lossless {
		t.Fatalf("marker audit = %+v, want the default posture", got.Audit)
	}
	got.Audit = nil
	if got != want {
		t.Fatalf("marker = %+v, want %+v", got, want)
	}
	if strings.Contains(string(data), "allowProxyOnly") || strings.Contains(string(data), "proxy-only") {
		t.Fatalf("marker must not mention proxy-only: %s", data)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected only the marker in %s, found %d entries", dir, len(entries))
	}
}

// Audit records the kernel could not write are added to the published marker
// as they are counted, including the enforcer daemon's (#241).
func TestAuditDropsUpdateMarker(t *testing.T) {
	dir := t.TempDir()
	defer func() {
		auditMarker.mu.Lock()
		auditMarker.dir, auditMarker.status, auditMarker.remoteDropped = "", nil, 0
		auditMarker.mu.Unlock()
	}()
	writeEnforcementReadyMarker(dir, enforcement.Describe(true, true))
	read := func() enforcement.Status {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(dir, entrypoint.EnforcementReadyFileName))
		if err != nil {
			t.Fatal(err)
		}
		var st enforcement.Status
		if err := json.Unmarshal(data, &st); err != nil || st.Audit == nil {
			t.Fatalf("marker %q: %v", data, err)
		}
		return st
	}
	base := read().Audit.Dropped

	noteRemoteAuditLine(`time=t event=file.open pid=1 path="count=9" decision=allowed`)
	noteRemoteAuditLine("time=t event=audit.dropped kind=file.open count=5 kind_total=5 total=5 lossless=false")
	if got := read().Audit.Dropped - base; got != 5 {
		t.Fatalf("marker dropped grew by %d, want 5", got)
	}
	noteRemoteAuditLine("time=t event=audit.dropped kind=net.send count=2 kind_total=2 total=7 lossless=false")
	st := read()
	if got := st.Audit.Dropped - base; got != 7 {
		t.Fatalf("marker dropped grew by %d, want 7", got)
	}
	if st.Enforcement != enforcement.LevelLSM {
		t.Fatalf("rewriting the marker changed the level: %+v", st)
	}
}
