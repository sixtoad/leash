package runner

import (
	"context"
	"fmt"
	"testing"
)

func TestParseArgsRuntimeFlag(t *testing.T) {
	t.Parallel()

	opts, err := parseArgs([]string{"--runtime", "podman", "claude"})
	if err != nil {
		t.Fatalf("parseArgs returned error: %v", err)
	}
	if opts.runtime != "podman" {
		t.Fatalf("runtime = %q, want podman", opts.runtime)
	}
}

func TestParseArgsRuntimeEquals(t *testing.T) {
	t.Parallel()

	opts, err := parseArgs([]string{"--runtime=podman"})
	if err != nil {
		t.Fatalf("parseArgs returned error: %v", err)
	}
	if opts.runtime != "podman" {
		t.Fatalf("runtime = %q, want podman", opts.runtime)
	}
}

func TestParseArgsRuntimeMissingArg(t *testing.T) {
	t.Parallel()

	if _, err := parseArgs([]string{"--runtime"}); err == nil {
		t.Fatal("expected error for --runtime with no argument")
	}
}

func TestNewRuntime(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		want    string
		wantErr bool
	}{
		{name: "docker", want: "docker"},
		{name: "podman", want: "podman"},
		{name: "", want: "docker"}, // empty defaults to docker
		{name: "  podman  ", want: "podman"},
		{name: "lxc", wantErr: true},
		{name: "nope", wantErr: true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rt, err := newRuntime(tc.name)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("newRuntime(%q) = nil error, want error", tc.name)
				}
				return
			}
			if err != nil {
				t.Fatalf("newRuntime(%q) error: %v", tc.name, err)
			}
			if rt.Name() != tc.want {
				t.Fatalf("newRuntime(%q).Name() = %q, want %q", tc.name, rt.Name(), tc.want)
			}
		})
	}
}

func TestLoadConfigRuntimeFromEnv(t *testing.T) {
	clearEnv(t, "LEASH_WORK_DIR")
	clearEnv(t, "LEASH_LOG_DIR")
	clearEnv(t, "LEASH_CFG_DIR")
	clearEnv(t, "LEASH_WORKSPACE_DIR")
	setEnv(t, "XDG_CONFIG_HOME", t.TempDir())
	setEnv(t, "LEASH_RUNTIME", "podman")

	cfg, _, err := loadConfig(t.TempDir(), options{})
	if err != nil {
		t.Fatalf("loadConfig returned error: %v", err)
	}
	if cfg.runtime != "podman" {
		t.Fatalf("runtime = %q, want podman", cfg.runtime)
	}
}

func TestLoadConfigRuntimeFlagOverridesEnv(t *testing.T) {
	clearEnv(t, "LEASH_WORK_DIR")
	clearEnv(t, "LEASH_LOG_DIR")
	clearEnv(t, "LEASH_CFG_DIR")
	clearEnv(t, "LEASH_WORKSPACE_DIR")
	setEnv(t, "XDG_CONFIG_HOME", t.TempDir())
	setEnv(t, "LEASH_RUNTIME", "docker")

	cfg, _, err := loadConfig(t.TempDir(), options{runtime: "podman"})
	if err != nil {
		t.Fatalf("loadConfig returned error: %v", err)
	}
	if cfg.runtime != "podman" {
		t.Fatalf("runtime = %q, want podman (flag must win over env)", cfg.runtime)
	}
}

// The configured runtime binary must actually reach the command layer.
func TestRunnerUsesConfiguredRuntimeBinary(t *testing.T) {
	mountStateTestMu.Lock()
	t.Cleanup(mountStateTestMu.Unlock)

	var gotBin string
	restore := commandOutput
	commandOutput = func(_ context.Context, name string, _ ...string) (string, error) {
		gotBin = name
		return "", fmt.Errorf("Error: No such object") // -> containerExists reports false, no error
	}
	t.Cleanup(func() { commandOutput = restore })

	rt, err := newRuntime("podman")
	if err != nil {
		t.Fatalf("newRuntime: %v", err)
	}
	r := &runner{runtime: rt}
	if _, err := r.containerExists(context.Background(), "x"); err != nil {
		t.Fatalf("containerExists: %v", err)
	}
	if gotBin != "podman" {
		t.Fatalf("runtime binary = %q, want podman", gotBin)
	}
}

// A runner with no runtime configured defaults to docker.
func TestRunnerDefaultsToDocker(t *testing.T) {
	mountStateTestMu.Lock()
	t.Cleanup(mountStateTestMu.Unlock)

	var gotBin string
	restore := commandOutput
	commandOutput = func(_ context.Context, name string, _ ...string) (string, error) {
		gotBin = name
		return "", fmt.Errorf("Error: No such object")
	}
	t.Cleanup(func() { commandOutput = restore })

	r := &runner{}
	if _, err := r.containerExists(context.Background(), "x"); err != nil {
		t.Fatalf("containerExists: %v", err)
	}
	if gotBin != "docker" {
		t.Fatalf("runtime binary = %q, want docker", gotBin)
	}
}
