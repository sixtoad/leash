package runner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"
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

// fakeEngine writes an executable named after a supported runtime into dir.
func fakeEngine(t *testing.T, dir, name, script string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
		t.Fatalf("write fake %s: %v", name, err)
	}
}

// CAP-4: an engine on PATH is not a usable engine. These tests mutate PATH and
// the probe timeout, so no t.Parallel().
func TestDetectContainerEngineChecksDaemonReachability(t *testing.T) {
	t.Run("no engine installed", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		engine, err := DetectContainerEngine()
		if engine != "" || err != nil {
			t.Fatalf("DetectContainerEngine() = (%q, %v), want (\"\", nil)", engine, err)
		}
	})

	t.Run("engine present and daemon answers", func(t *testing.T) {
		dir := t.TempDir()
		fakeEngine(t, dir, "docker", "exit 0")
		t.Setenv("PATH", dir)

		engine, err := DetectContainerEngine()
		if engine != "docker" || err != nil {
			t.Fatalf("DetectContainerEngine() = (%q, %v), want (\"docker\", nil)", engine, err)
		}
	})

	t.Run("engine present but daemon unreachable", func(t *testing.T) {
		dir := t.TempDir()
		fakeEngine(t, dir, "docker", `echo "permission denied while trying to connect to the docker API" >&2; exit 1`)
		t.Setenv("PATH", dir)

		engine, err := DetectContainerEngine()
		if engine != "docker" {
			t.Fatalf("the engine must still be named so doctor can report it, got %q", engine)
		}
		if err == nil {
			t.Fatal("an unreachable daemon must be reported as an error, not as a usable engine")
		}
		if !strings.Contains(err.Error(), "permission denied") {
			t.Errorf("the engine's own diagnosis should reach the caller, got %v", err)
		}
	})

	t.Run("silent failure still produces an error", func(t *testing.T) {
		dir := t.TempDir()
		fakeEngine(t, dir, "docker", "exit 7")
		t.Setenv("PATH", dir)

		if _, err := DetectContainerEngine(); err == nil {
			t.Fatal("a non-zero exit with no stderr must still be an error")
		}
	})

	t.Run("a hung daemon times out rather than hanging doctor", func(t *testing.T) {
		dir := t.TempDir()
		fakeEngine(t, dir, "docker", "sleep 30")
		// The fake needs a real /bin on PATH to find sleep; LookPath still
		// resolves docker to the fake because dir comes first.
		t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

		original := containerEngineProbeTimeout
		t.Cleanup(func() { containerEngineProbeTimeout = original })
		containerEngineProbeTimeout = 100 * time.Millisecond

		start := time.Now()
		engine, err := DetectContainerEngine()
		elapsed := time.Since(start)

		if engine != "docker" {
			t.Fatalf("engine = %q, want docker", engine)
		}
		if err == nil || !strings.Contains(err.Error(), "did not answer") {
			t.Fatalf("a hung daemon must be reported as a timeout, got %v", err)
		}
		if elapsed > 5*time.Second {
			t.Fatalf("probe took %s; the timeout did not bound it", elapsed)
		}
	})

	t.Run("the first supported engine on PATH is the one reported", func(t *testing.T) {
		// newRuntime defaults to docker, so doctor must report on docker even
		// when podman would work — otherwise a "ready" verdict describes a
		// runtime a default `leash run` never touches.
		dir := t.TempDir()
		fakeEngine(t, dir, "docker", `echo "daemon down" >&2; exit 1`)
		fakeEngine(t, dir, "podman", "exit 0")
		t.Setenv("PATH", dir)

		engine, err := DetectContainerEngine()
		if engine != "docker" {
			t.Fatalf("engine = %q, want docker (the default runtime)", engine)
		}
		if err == nil {
			t.Fatal("docker's daemon is down; that must not be masked by podman")
		}
	})
}

func TestFirstLines(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in   string
		n    int
		want string
	}{
		{"", 2, ""},
		{"\n\n  \n", 2, ""},
		{"one\ntwo\nthree\n", 2, "one two"},
		{"  padded  \n", 3, "padded"},
	}
	for _, c := range cases {
		if got := firstLines(c.in, c.n); got != c.want {
			t.Errorf("firstLines(%q, %d) = %q, want %q", c.in, c.n, got, c.want)
		}
	}
}

// This text is pasted verbatim into a doctor issue, so it reaches a terminal.
// Engine clients colour their stderr and redraw progress with carriage
// returns; passed through, a failing daemon's output can repaint the readiness
// report a reader is consulting precisely because they do not trust the
// machine.
func TestFirstLinesStripsControlCharacters(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		n    int
		want string
	}{
		{
			name: "ANSI colour (SGR)",
			in:   "\x1b[31mCannot connect to the Docker daemon\x1b[0m\n",
			n:    3,
			want: "Cannot connect to the Docker daemon",
		},
		{
			name: "cursor movement and erase-line",
			in:   "\x1b[2K\x1b[1Gpulling\x1b[A\x1b[Bdone\n",
			n:    3,
			want: "pullingdone",
		},
		{
			name: "OSC title sequence",
			in:   "\x1b]0;docker\x07error: daemon down\n",
			n:    2,
			want: "error: daemon down",
		},
		{
			name: "carriage-return progress redraw becomes separate lines",
			in:   "10%\r50%\r100%\n",
			n:    2,
			want: "10% 50%",
		},
		{
			name: "bare control bytes collapse to whitespace",
			in:   "permission\x00denied\x07 while\tconnecting\n",
			n:    1,
			want: "permission denied while connecting",
		},
		{
			name: "invalid UTF-8 does not reach the JSON document",
			in:   "bad \xff\xfe byte\n",
			n:    1,
			want: "bad byte",
		},
		{
			name: "a line that was only escapes is skipped, not counted",
			in:   "\x1b[2K\x1b[1G\nreal message\n",
			n:    1,
			want: "real message",
		},
		{
			name: "ordinary text is untouched",
			in:   "Cannot connect to the Docker daemon at unix:///var/run/docker.sock.\n",
			n:    1,
			want: "Cannot connect to the Docker daemon at unix:///var/run/docker.sock.",
		},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got := firstLines(c.in, c.n)
			if got != c.want {
				t.Errorf("firstLines(%q, %d) = %q, want %q", c.in, c.n, got, c.want)
			}
			for _, r := range got {
				if unicode.IsControl(r) || r == utf8.RuneError {
					t.Errorf("control character %U survived in %q", r, got)
				}
			}
		})
	}
}
