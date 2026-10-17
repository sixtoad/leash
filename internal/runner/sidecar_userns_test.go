package runner

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/strongdm/leash/internal/leashd/listen"
)

// launchBoth runs launchTargetContainer and launchLeashContainer against a
// recording runtime and returns the two `run` argv lines.
func launchBoth(t *testing.T, runtimeName, usernsMode string) (target, leash []string) {
	t.Helper()
	var (
		mu       sync.Mutex
		commands [][]string
	)
	origRun, origOutput := runCommand, commandOutput
	runCommand = func(_ context.Context, _, _ io.Writer, name string, args ...string) error {
		mu.Lock()
		defer mu.Unlock()
		commands = append(commands, append([]string(nil), args...))
		return nil
	}
	commandOutput = func(_ context.Context, name string, args ...string) (string, error) {
		if len(args) >= 3 && args[0] == "inspect" && strings.Contains(args[2], "{{.Architecture}}") {
			return "amd64\n", nil
		}
		if len(args) >= 3 && args[0] == "inspect" && strings.Contains(args[2], "UsernsMode") {
			return usernsMode + "\n", nil
		}
		if len(args) > 0 && args[0] == "run" {
			mu.Lock()
			defer mu.Unlock()
			commands = append(commands, append([]string(nil), args...))
			return "cid\n", nil
		}
		return "", fmt.Errorf("unexpected commandOutput call: %s %s", name, strings.Join(args, " "))
	}
	t.Cleanup(func() { runCommand, commandOutput = origRun, origOutput })

	dir := t.TempDir()
	mk := func(name string) string {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	r := &runner{
		runtime: cliRuntime{bin: runtimeName},
		logger:  log.New(ioDiscard{}, "", 0),
		cfg: config{
			hostOS: "linux", workDir: mk("work"), shareDir: mk("share"), privateDir: mk("private"),
			logDir: mk("log"), cfgDir: mk("cfg"), callerDir: mk("caller"),
			targetImage: "example/target:latest", leashImage: "example/leash:latest",
			targetContainer: "t", leashContainer: "t-leash", proxyPort: "18000",
			bootstrapTimeout: 30 * time.Second, listenCfg: listen.Default(),
		},
		opts:           options{command: []string{"bash"}},
		selinuxChecked: true,
	}
	if err := r.launchTargetContainer(context.Background(), "SIGTERM"); err != nil {
		t.Fatalf("launch target: %v", err)
	}
	if err := r.launchLeashContainer(context.Background(), "/sys/fs/cgroup/x"); err != nil {
		t.Fatalf("launch leash: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(commands) != 2 {
		t.Fatalf("want 2 runs, got %d", len(commands))
	}
	return commands[0], commands[1]
}

func argValue(args []string, flag string) (string, bool) {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1], true
		}
		if v, ok := strings.CutPrefix(a, flag+"="); ok {
			return v, true
		}
	}
	return "", false
}

// #121: with podman the sidecar joins the target's user namespace, so an
// ambient containers.conf `userns = "keep-id"` (which gives the target its own
// user namespace) cannot leave the sidecar without CAP_NET_ADMIN over the
// shared network namespace. The target itself keeps the ambient userns.
func TestPodmanSidecarJoinsTargetUserNamespace(t *testing.T) {
	target, leash := launchBoth(t, "podman", "private")
	if v, ok := argValue(leash, "--userns"); !ok || v != "container:t" {
		t.Fatalf("podman sidecar must join the target's user namespace (--userns container:t), got %q in %v", v, leash)
	}
	if v, ok := argValue(leash, "--network"); !ok || v != "container:t" {
		t.Fatalf("sidecar must still share the target's netns, got %q", v)
	}
	if _, ok := argValue(target, "--userns"); ok {
		t.Fatalf("the target keeps the ambient userns (keep-id stays the user's choice): %v", target)
	}
	if v, _ := argValue(target, "--user"); v != "0" {
		t.Fatalf("leash-entry must bootstrap as container root, got --user %q", v)
	}
	// Flags must precede the image.
	img := -1
	for i, a := range leash {
		if a == "example/leash:latest" {
			img = i
		}
	}
	for i, a := range leash {
		if a == "--userns" && i > img {
			t.Fatalf("--userns after the image: %v", leash)
		}
	}
}

// In the engine's own user namespace (rootful, or rootless podman's default)
// the sidecar is already there: setns into it again fails with EINVAL, so no
// flag is passed.
func TestPodmanSidecarStaysInEngineUserNamespace(t *testing.T) {
	for _, mode := range []string{"", "host"} {
		_, leash := launchBoth(t, "podman", mode)
		if _, ok := argValue(leash, "--userns"); ok {
			t.Fatalf("mode %q: sidecar must not setns into the namespace it is already in: %v", mode, leash)
		}
	}
}

func TestTargetHasOwnUserns(t *testing.T) {
	for mode, want := range map[string]bool{"": false, "host": false, "<no value>": false, "private\n": true, "keep-id": true, "auto": true, "ns:/proc/1/ns/user": true} {
		if got := targetHasOwnUserns(mode); got != want {
			t.Errorf("targetHasOwnUserns(%q) = %v, want %v", mode, got, want)
		}
	}
}

func TestDockerSidecarHasNoUsernsFlag(t *testing.T) {
	_, leash := launchBoth(t, "docker", "")
	if _, ok := argValue(leash, "--userns"); ok {
		t.Fatalf("docker has no per-container user namespace to join: %v", leash)
	}
}
