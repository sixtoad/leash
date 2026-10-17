package runner

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/strongdm/leash/internal/enforcement"
)

func TestValidatePostureOverrides(t *testing.T) {
	cases := []struct {
		name      string
		env       []string
		wantErrIn string
	}{
		{name: "nothing", env: []string{"FOO=1", "BAR"}},
		{name: "-e LEASH_REQUIRE_LSM=0", env: []string{"LEASH_REQUIRE_LSM=0"}, wantErrIn: "LEASH_REQUIRE_LSM"},
		{name: "-e LEASH_REQUIRE_LSM (inherit)", env: []string{"LEASH_REQUIRE_LSM"}, wantErrIn: "LEASH_REQUIRE_LSM"},
		{name: "similar key is fine", env: []string{"LEASH_REQUIRE_LSM_X=1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validatePostureOverrides(tc.env)
			if tc.wantErrIn == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErrIn) {
				t.Fatalf("err = %v, want mention of %q", err, tc.wantErrIn)
			}
		})
	}
}

// The client cross-checks leashd's reported level: only "lsm" is released,
// so an older leashd that reports any other level (including the
// "proxy-only" an older image could write) cannot run the workload.
func TestCheckReleasedEnforcement(t *testing.T) {
	cases := []struct {
		name    string
		st      enforcement.Status
		ok      bool
		wantErr bool
	}{
		{"legacy marker", enforcement.Status{}, false, false},
		{"lsm", enforcement.Describe(true, true), true, false},
		{"lsm, proxy off", enforcement.Describe(true, false), true, false},
		{"layer 1 unavailable, proxy up", enforcement.Describe(false, true), true, true},
		{"layer 1 unavailable, proxy off", enforcement.Describe(false, false), true, true},
		{"older leashd proxy-only marker", enforcement.Status{Enforcement: "proxy-only", Layer1: enforcement.LayerUnavailable, Layer2: enforcement.LayerActive}, true, true},
	}
	for _, tc := range cases {
		if err := checkReleasedEnforcement(tc.st, tc.ok); (err != nil) != tc.wantErr {
			t.Fatalf("%s: err = %v, wantErr %v", tc.name, err, tc.wantErr)
		}
	}
}

func TestLoadConfigRejectsPostureEnvOverride(t *testing.T) {
	t.Setenv("LEASH_REQUIRE_LSM", "")
	t.Setenv("LEASH_EXTRA_ARGS", "")
	t.Setenv("LEASH_WORK_DIR", t.TempDir())
	t.Setenv("LEASH_HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if _, _, err := loadConfig(t.TempDir(), options{envVars: []string{"LEASH_REQUIRE_LSM=0"}}); err == nil {
		t.Fatal("-e LEASH_REQUIRE_LSM=0 must be rejected with a clear client error")
	}
}

// Real-kernel finding on #117: an older/confused leashd may report lsm while
// the client preflight already saw bpf inactive. The client's observation can
// only narrow the level, never raise it, and a narrowed level is refused.
func TestReportEnforcementNarrowsWithPreflight(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "enforcement.ready")
	lsmLevel := `{"enforcement":"lsm","layer1":"active","layer2":"active","requireLSM":true}`
	if err := os.WriteFile(marker, []byte(lsmLevel+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var diag bytes.Buffer
	r := &runner{diagnostics: &diag}
	r.layer1PreflightDown = "bpf is not an active LSM on this host (lockdown,apparmor)"

	err := r.reportEnforcement(marker)
	if err == nil || !strings.Contains(err.Error(), "bpf is not an active LSM") {
		t.Fatalf("a narrowed level must be refused with the reason: %v", err)
	}
	if !strings.Contains(diag.String(), "enforcement=none layer1=unavailable layer2=active") {
		t.Fatalf("narrowed level not reported: %q", diag.String())
	}
	if strings.Contains(diag.String(), "proxy-only") {
		t.Fatalf("proxy-only must never be reported: %q", diag.String())
	}

	// Without a preflight finding, a reported lsm stays lsm.
	r.layer1PreflightDown = ""
	if err := r.reportEnforcement(marker); err != nil {
		t.Fatalf("lsm should release: %v", err)
	}
}

func TestLeashdFailureReason(t *testing.T) {
	path := filepath.Join(t.TempDir(), "leashd.log")
	log := "starting\nleash: FATAL: old\nmore\nleash: FATAL: enforcement=none (layer1=unavailable layer2=active): \"bpf\" is not among the active LSMs (lockdown,apparmor); fail-closed, refusing to run the workload\ntrailer\n"
	if err := os.WriteFile(path, []byte(log), 0o644); err != nil {
		t.Fatal(err)
	}
	got := leashdFailureReason(path)
	if !strings.HasPrefix(got, "enforcement=none") || !strings.Contains(got, "not among the active LSMs") {
		t.Fatalf("reason = %q, want the last FATAL line", got)
	}
	if leashdFailureReason(filepath.Join(t.TempDir(), "missing")) != "" {
		t.Fatal("missing log should yield no reason")
	}
}
