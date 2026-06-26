package runner

import "testing"

// The --network flag (issue #69) attaches the agent container to a user-chosen
// docker network; the leash container follows it via `--network container:<target>`.

func TestParseArgsNetworkFlag(t *testing.T) {
	t.Parallel()

	opts, err := parseArgs([]string{"--network", "compose_default", "claude"})
	if err != nil {
		t.Fatalf("parseArgs returned error: %v", err)
	}
	if opts.network != "compose_default" {
		t.Fatalf("network = %q, want %q", opts.network, "compose_default")
	}
	if opts.subcommand != "claude" {
		t.Fatalf("subcommand = %q, want %q", opts.subcommand, "claude")
	}
}

func TestParseArgsNetworkEquals(t *testing.T) {
	t.Parallel()

	opts, err := parseArgs([]string{"--network=mynet"})
	if err != nil {
		t.Fatalf("parseArgs returned error: %v", err)
	}
	if opts.network != "mynet" {
		t.Fatalf("network = %q, want %q", opts.network, "mynet")
	}
}

func TestParseArgsNetworkMissingArg(t *testing.T) {
	t.Parallel()

	if _, err := parseArgs([]string{"--network"}); err == nil {
		t.Fatal("expected error for --network with no argument")
	}
}

func clearNetworkEnv(t *testing.T) {
	t.Helper()
	clearEnv(t, "LEASH_WORK_DIR")
	clearEnv(t, "LEASH_LOG_DIR")
	clearEnv(t, "LEASH_CFG_DIR")
	clearEnv(t, "LEASH_WORKSPACE_DIR")
	clearEnv(t, "LEASH_NETWORK")
	setEnv(t, "XDG_CONFIG_HOME", t.TempDir())
}

func TestLoadConfigNetworkFromEnv(t *testing.T) {
	clearNetworkEnv(t)
	setEnv(t, "LEASH_NETWORK", "env_net")

	cfg, _, err := loadConfig(t.TempDir(), options{})
	if err != nil {
		t.Fatalf("loadConfig returned error: %v", err)
	}
	if cfg.dockerNetwork != "env_net" {
		t.Fatalf("dockerNetwork = %q, want %q", cfg.dockerNetwork, "env_net")
	}
}

func TestLoadConfigNetworkFlagOverridesEnv(t *testing.T) {
	clearNetworkEnv(t)
	setEnv(t, "LEASH_NETWORK", "env_net")

	cfg, _, err := loadConfig(t.TempDir(), options{network: "flag_net"})
	if err != nil {
		t.Fatalf("loadConfig returned error: %v", err)
	}
	if cfg.dockerNetwork != "flag_net" {
		t.Fatalf("dockerNetwork = %q, want %q (flag must win over env)", cfg.dockerNetwork, "flag_net")
	}
}

func TestLoadConfigNetworkUnsetByDefault(t *testing.T) {
	clearNetworkEnv(t)

	cfg, _, err := loadConfig(t.TempDir(), options{})
	if err != nil {
		t.Fatalf("loadConfig returned error: %v", err)
	}
	if cfg.dockerNetwork != "" {
		t.Fatalf("dockerNetwork = %q, want empty", cfg.dockerNetwork)
	}
}
