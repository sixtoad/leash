package runner

import (
	"context"
	"fmt"
	"log"
	"strings"
	"testing"
)

// --container-name forces the exact agent container name (no sanitization, no
// collision suffix) so orchestrators can address it deterministically.

func TestParseArgsContainerNameFlag(t *testing.T) {
	t.Parallel()

	opts, err := parseArgs([]string{"--container-name", "my-agent", "claude"})
	if err != nil {
		t.Fatalf("parseArgs returned error: %v", err)
	}
	if opts.containerName != "my-agent" {
		t.Fatalf("containerName = %q, want %q", opts.containerName, "my-agent")
	}
	if opts.subcommand != "claude" {
		t.Fatalf("subcommand = %q, want %q", opts.subcommand, "claude")
	}
}

func TestParseArgsContainerNameEquals(t *testing.T) {
	t.Parallel()

	opts, err := parseArgs([]string{"--container-name=my-agent"})
	if err != nil {
		t.Fatalf("parseArgs returned error: %v", err)
	}
	if opts.containerName != "my-agent" {
		t.Fatalf("containerName = %q, want %q", opts.containerName, "my-agent")
	}
}

func TestParseArgsContainerNameMissingArg(t *testing.T) {
	t.Parallel()

	if _, err := parseArgs([]string{"--container-name"}); err == nil {
		t.Fatal("expected error for --container-name with no argument")
	}
}

func TestParseArgsContainerNameEmpty(t *testing.T) {
	t.Parallel()

	if _, err := parseArgs([]string{"--container-name="}); err == nil {
		t.Fatal("expected error for empty --container-name=")
	}
}

func TestLoadConfigContainerNameDerivesPair(t *testing.T) {
	clearEnv(t, "LEASH_WORK_DIR")
	clearEnv(t, "LEASH_LOG_DIR")
	clearEnv(t, "LEASH_CFG_DIR")
	clearEnv(t, "LEASH_WORKSPACE_DIR")
	clearEnv(t, "TARGET_CONTAINER")
	clearEnv(t, "LEASH_CONTAINER")
	setEnv(t, "XDG_CONFIG_HOME", t.TempDir())

	cfg, _, err := loadConfig(t.TempDir(), options{containerName: "my-agent"})
	if err != nil {
		t.Fatalf("loadConfig returned error: %v", err)
	}
	if cfg.targetContainer != "my-agent" || cfg.targetContainerBase != "my-agent" {
		t.Fatalf("target = %q/%q, want my-agent/my-agent", cfg.targetContainer, cfg.targetContainerBase)
	}
	if cfg.leashContainer != "my-agent-leash" || cfg.leashContainerBase != "my-agent-leash" {
		t.Fatalf("leash = %q/%q, want my-agent-leash/my-agent-leash", cfg.leashContainer, cfg.leashContainerBase)
	}
}

func TestLoadConfigContainerNameOverridesEnv(t *testing.T) {
	clearEnv(t, "LEASH_WORK_DIR")
	clearEnv(t, "LEASH_LOG_DIR")
	clearEnv(t, "LEASH_CFG_DIR")
	clearEnv(t, "LEASH_WORKSPACE_DIR")
	setEnv(t, "XDG_CONFIG_HOME", t.TempDir())
	setEnv(t, "TARGET_CONTAINER", "from-env")

	cfg, _, err := loadConfig(t.TempDir(), options{containerName: "from-flag"})
	if err != nil {
		t.Fatalf("loadConfig returned error: %v", err)
	}
	if cfg.targetContainer != "from-flag" {
		t.Fatalf("targetContainer = %q, want from-flag (flag must win over env)", cfg.targetContainer)
	}
}

// inspectedName pulls the container name out of a mocked
// `docker inspect -f {{.Name}} <name>` call.
func inspectedName(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return args[len(args)-1]
}

func TestAssignContainerNamesExplicitVerbatim(t *testing.T) {
	mountStateTestMu.Lock()
	t.Cleanup(mountStateTestMu.Unlock)

	restore := commandOutput
	// Every name is free: inspect always reports "no such object".
	commandOutput = func(_ context.Context, _ string, args ...string) (string, error) {
		return "", fmt.Errorf("Error: No such object: %s", inspectedName(args))
	}
	t.Cleanup(func() { commandOutput = restore })

	r := &runner{
		opts: options{containerName: "my-agent"},
		cfg: config{
			targetContainer:     "my-agent",
			targetContainerBase: "my-agent",
			leashContainer:      "my-agent-leash",
			leashContainerBase:  "my-agent-leash",
		},
		logger: log.New(&strings.Builder{}, "", 0),
	}

	if err := r.assignContainerNames(context.Background()); err != nil {
		t.Fatalf("assignContainerNames returned error: %v", err)
	}
	if r.cfg.targetContainer != "my-agent" {
		t.Fatalf("targetContainer = %q, want my-agent (no suffix)", r.cfg.targetContainer)
	}
	if r.cfg.leashContainer != "my-agent-leash" {
		t.Fatalf("leashContainer = %q, want my-agent-leash (no suffix)", r.cfg.leashContainer)
	}
}

func TestAssignContainerNamesExplicitFailsWhenTaken(t *testing.T) {
	mountStateTestMu.Lock()
	t.Cleanup(mountStateTestMu.Unlock)

	restore := commandOutput
	// The target name already exists; everything else is free.
	commandOutput = func(_ context.Context, _ string, args ...string) (string, error) {
		if inspectedName(args) == "my-agent" {
			return "/my-agent\n", nil
		}
		return "", fmt.Errorf("Error: No such object: %s", inspectedName(args))
	}
	t.Cleanup(func() { commandOutput = restore })

	r := &runner{
		opts: options{containerName: "my-agent"},
		cfg: config{
			targetContainer:     "my-agent",
			targetContainerBase: "my-agent",
			leashContainer:      "my-agent-leash",
			leashContainerBase:  "my-agent-leash",
		},
		logger: log.New(&strings.Builder{}, "", 0),
	}

	err := r.assignContainerNames(context.Background())
	if err == nil {
		t.Fatal("expected error when the forced container name is already in use")
	}
	if !strings.Contains(err.Error(), "already in use") {
		t.Fatalf("error = %q, want it to mention 'already in use'", err.Error())
	}
}
