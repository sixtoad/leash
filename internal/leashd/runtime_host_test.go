package leashd

import "testing"

func TestLeashdEnvTruthy(t *testing.T) {
	for _, v := range []string{"1", "true", "TRUE", "Yes", "on"} {
		t.Setenv("LEASH_HOST", v)
		if !leashdEnvTruthy("LEASH_HOST") {
			t.Errorf("LEASH_HOST=%q should be truthy", v)
		}
	}
	for _, v := range []string{"", "0", "false", "no", "off", "maybe"} {
		t.Setenv("LEASH_HOST", v)
		if leashdEnvTruthy("LEASH_HOST") {
			t.Errorf("LEASH_HOST=%q should be falsey", v)
		}
	}
}

func TestResolvePolicyPath(t *testing.T) {
	// Explicit always wins, in either mode.
	if got := resolvePolicyPath("/custom.cedar", true); got != "/custom.cedar" {
		t.Fatalf("explicit host = %q", got)
	}
	if got := resolvePolicyPath("/custom.cedar", false); got != "/custom.cedar" {
		t.Fatalf("explicit container = %q", got)
	}
	// Container default is the image path.
	if got := resolvePolicyPath("", false); got != "/cfg/leash.cedar" {
		t.Fatalf("container default = %q, want /cfg/leash.cedar", got)
	}
	// Host default lives under LEASH_DIR (no /cfg on a host).
	t.Setenv("LEASH_DIR", "/run/leash/s1/public")
	if got := resolvePolicyPath("", true); got != "/run/leash/s1/public/leash.cedar" {
		t.Fatalf("host default = %q", got)
	}
}

func TestParseConfigHostMode(t *testing.T) {
	t.Setenv("LEASH_DIR", "/run/leash/s2/public")
	t.Setenv("LEASH_POLICY", "")
	t.Setenv("LEASH_HOST", "")

	cfg, err := parseConfig([]string{"leash", "--host", "--cgroup", "/sys/fs/cgroup/x"})
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if !cfg.HostMode {
		t.Fatal("HostMode should be true with --host")
	}
	if cfg.PolicyPath != "/run/leash/s2/public/leash.cedar" {
		t.Fatalf("host policy default = %q", cfg.PolicyPath)
	}

	// Without --host, container default applies.
	cfg2, err := parseConfig([]string{"leash", "--cgroup", "/sys/fs/cgroup/x"})
	if err != nil {
		t.Fatalf("parseConfig (container): %v", err)
	}
	if cfg2.HostMode {
		t.Fatal("HostMode should be false without --host")
	}
	if cfg2.PolicyPath != "/cfg/leash.cedar" {
		t.Fatalf("container policy default = %q", cfg2.PolicyPath)
	}
}

func TestParseConfigHostModeFromEnv(t *testing.T) {
	t.Setenv("LEASH_HOST", "1")
	cfg, err := parseConfig([]string{"leash", "--cgroup", "/sys/fs/cgroup/x"})
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if !cfg.HostMode {
		t.Fatal("LEASH_HOST=1 should enable host mode")
	}
}
