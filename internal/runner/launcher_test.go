package runner

import (
	"context"
	"path/filepath"
	"testing"
)

func TestRunnerLauncherDefaultsToContainer(t *testing.T) {
	r := &runner{}
	l := r.launcher()
	cl, ok := l.(containerLauncher)
	if !ok {
		t.Fatalf("launcher() = %T, want containerLauncher", l)
	}
	if cl.r != r {
		t.Fatal("containerLauncher does not wrap the runner")
	}
}

func TestContainerLauncherNameTracksRuntime(t *testing.T) {
	// Default runtime is docker.
	if got := (&runner{}).launcher().Name(); got != "docker" {
		t.Fatalf("Name() = %q, want docker", got)
	}
	// Honors the configured runtime.
	r := &runner{runtime: cliRuntime{bin: "podman"}}
	if got := r.launcher().Name(); got != "podman" {
		t.Fatalf("Name() = %q, want podman", got)
	}
}

func TestCACertPath(t *testing.T) {
	if got := caCertPath("/share"); got != filepath.Join("/share", "ca-cert.pem") {
		t.Fatalf("caCertPath = %q", got)
	}
}

// PullImages must drive the same wrappers ensureLocalImage used, in order
// (target then leash). We intercept commandOutput to record image inspections.
func TestContainerLauncherPullImagesOrder(t *testing.T) {
	mountStateTestMu.Lock()
	defer mountStateTestMu.Unlock()

	origOut := commandOutput
	defer func() { commandOutput = origOut }()

	var inspected []string
	commandOutput = func(ctx context.Context, name string, args ...string) (string, error) {
		// `image inspect <img>` — record the image so we can assert order. A
		// successful inspect means "present", so no pull is attempted.
		if len(args) >= 3 && args[0] == "image" && args[1] == "inspect" {
			inspected = append(inspected, args[2])
		}
		return "ok", nil
	}

	r := &runner{}
	r.cfg.targetImage = "target:latest"
	r.cfg.leashImage = "leash:latest"

	if err := r.launcher().PullImages(context.Background()); err != nil {
		t.Fatalf("PullImages: %v", err)
	}
	want := []string{"target:latest", "leash:latest"}
	if len(inspected) != 2 || inspected[0] != want[0] || inspected[1] != want[1] {
		t.Fatalf("inspected = %v, want %v (target before leash)", inspected, want)
	}
}
