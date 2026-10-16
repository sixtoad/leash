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
		extra     string
		wantErrIn string
	}{
		{name: "nothing", env: []string{"FOO=1", "BAR"}, extra: "--verbose"},
		{name: "-e LEASH_ALLOW_PROXY_ONLY=1", env: []string{"LEASH_ALLOW_PROXY_ONLY=1"}, wantErrIn: "LEASH_ALLOW_PROXY_ONLY"},
		{name: "-e LEASH_REQUIRE_LSM (inherit)", env: []string{"LEASH_REQUIRE_LSM"}, wantErrIn: "LEASH_REQUIRE_LSM"},
		{name: "similar key is fine", env: []string{"LEASH_REQUIRE_LSM_X=1"}},
		{name: "extra --allow-proxy-only", extra: "--foo --allow-proxy-only", wantErrIn: "--allow-proxy-only"},
		{name: "extra -require-lsm=true", extra: "-require-lsm=true", wantErrIn: "--require-lsm"},
		{name: "extra value that merely mentions it", extra: "--note allow-proxy-only"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validatePostureOverrides(tc.env, tc.extra)
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

// Review finding on #117: the client cross-checks leashd's reported level, so
// a diverged leashd posture cannot release a less-enforced workload.
func TestCheckReleasedEnforcement(t *testing.T) {
	lsmFull := enforcement.Describe(true, true, true)
	proxyOnly := enforcement.Describe(false, true, false)
	none := enforcement.Describe(false, false, false)
	cases := []struct {
		name    string
		st      enforcement.Status
		ok      bool
		require bool
		wantErr bool
	}{
		{"legacy marker", enforcement.Status{}, false, true, false},
		{"lsm under fail-closed", lsmFull, true, true, false},
		{"proxy-only under fail-closed (diverged leashd)", proxyOnly, true, true, true},
		{"proxy-only when allowed", proxyOnly, true, false, false},
		{"none is never released", none, true, false, true},
	}
	for _, tc := range cases {
		if err := checkReleasedEnforcement(tc.st, tc.ok, tc.require); (err != nil) != tc.wantErr {
			t.Fatalf("%s: err = %v, wantErr %v", tc.name, err, tc.wantErr)
		}
	}
}

func TestLoadConfigRejectsPostureEnvOverride(t *testing.T) {
	t.Setenv("LEASH_REQUIRE_LSM", "")
	t.Setenv("LEASH_ALLOW_PROXY_ONLY", "")
	t.Setenv("LEASH_EXTRA_ARGS", "")
	t.Setenv("LEASH_WORK_DIR", t.TempDir())
	t.Setenv("LEASH_HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if _, _, err := loadConfig(t.TempDir(), options{envVars: []string{"LEASH_ALLOW_PROXY_ONLY=1"}}); err == nil {
		t.Fatal("-e LEASH_ALLOW_PROXY_ONLY=1 must be rejected with a clear client error")
	}
	t.Setenv("LEASH_EXTRA_ARGS", "--allow-proxy-only")
	if _, _, err := loadConfig(t.TempDir(), options{}); err == nil {
		t.Fatal("LEASH_EXTRA_ARGS=--allow-proxy-only must be rejected")
	}
}

// Real-kernel finding on #117: an older/confused leashd may report lsm while
// the client preflight already saw bpf inactive. The client's observation can
// only narrow the level, never raise it.
func TestReportEnforcementNarrowsWithPreflight(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "enforcement.ready")
	lsmLevel := `{"enforcement":"lsm","layer1":"active","layer2":"active","requireLSM":false,"allowProxyOnly":true}`
	if err := os.WriteFile(marker, []byte(lsmLevel+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var diag bytes.Buffer
	r := &runner{diagnostics: &diag}
	r.layer1PreflightDown = "bpf is not an active LSM on this host (lockdown,apparmor)"

	// Proxy-only allowed: released, but reported as proxy-only, not lsm.
	if err := r.reportEnforcement(marker); err != nil {
		t.Fatalf("proxy-only allowed should release: %v", err)
	}
	if !strings.Contains(diag.String(), "enforcement=proxy-only") {
		t.Fatalf("narrowed level not reported: %q", diag.String())
	}

	// Fail-closed: refused, with the reason echoed.
	r.cfg.requireLSM = true
	err := r.reportEnforcement(marker)
	if err == nil || !strings.Contains(err.Error(), "bpf is not an active LSM") {
		t.Fatalf("fail-closed must refuse and echo the reason: %v", err)
	}

	// Without a preflight finding, a reported lsm stays lsm.
	r.layer1PreflightDown = ""
	if err := r.reportEnforcement(marker); err != nil {
		t.Fatalf("lsm under fail-closed should release: %v", err)
	}
}

func TestLeashdFailureReason(t *testing.T) {
	path := filepath.Join(t.TempDir(), "leashd.log")
	log := "starting\nleash: FATAL: old\nmore\nleash: FATAL: enforcement=proxy-only (layer1=unavailable layer2=active): \"bpf\" is not among the active LSMs (lockdown,apparmor); but fail-closed is in effect\ntrailer\n"
	if err := os.WriteFile(path, []byte(log), 0o644); err != nil {
		t.Fatal(err)
	}
	got := leashdFailureReason(path)
	if !strings.HasPrefix(got, "enforcement=proxy-only") || !strings.Contains(got, "not among the active LSMs") {
		t.Fatalf("reason = %q, want the last FATAL line", got)
	}
	if leashdFailureReason(filepath.Join(t.TempDir(), "missing")) != "" {
		t.Fatal("missing log should yield no reason")
	}
}
