package runner

import (
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
