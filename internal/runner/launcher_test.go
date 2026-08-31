package runner

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/strongdm/leash/internal/entrypoint"
)

// recordingRuntime is an in-memory Runtime that records image inspections, so
// launcher tests need not swap package-level globals (which races the other
// global-swapping tests in this package).
type recordingRuntime struct {
	inspected *[]string
}

func (rr recordingRuntime) Run(ctx context.Context, args ...string) error { return nil }

func (rr recordingRuntime) Output(ctx context.Context, args ...string) (string, error) {
	if len(args) == 3 && args[0] == "image" && args[1] == "inspect" {
		*rr.inspected = append(*rr.inspected, args[2])
	}
	if len(args) >= 5 && args[0] == "image" && args[1] == "inspect" && args[2] == "--format" {
		return `{"io.leash.manager.contract.version":"1","io.leash.manager.contract.min-compatible":"1","org.opencontainers.image.revision":"dev"}`, nil
	}
	return "ok", nil
}

func (rr recordingRuntime) ExecWithInput(ctx context.Context, container, shellCommand string, input io.Reader) error {
	return nil
}

func (rr recordingRuntime) Cmd(ctx context.Context, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, "true")
}

func (rr recordingRuntime) Name() string { return "fake" }

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

func TestContainerWaitReadyRequiresPostAttachMarker(t *testing.T) {
	share := t.TempDir()
	for _, name := range []string{"ca-cert.pem", entrypoint.BootstrapReadyFileName} {
		if err := os.WriteFile(filepath.Join(share, name), []byte("ready\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var inspected []string
	r := &runner{runtime: recordingRuntime{inspected: &inspected}}
	r.cfg.shareDir = share
	r.cfg.bootstrapTimeout = 2 * time.Second

	done := make(chan error, 1)
	go func() { done <- (containerLauncher{r: r}).WaitReady(context.Background()) }()
	select {
	case err := <-done:
		t.Fatalf("WaitReady returned on pre-attach bootstrap marker: %v", err)
	case <-time.After(150 * time.Millisecond):
	}

	if err := os.WriteFile(filepath.Join(share, entrypoint.EnforcementReadyFileName), []byte("ready\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("WaitReady after enforcement marker: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("WaitReady did not observe enforcement marker")
	}
}

// PullImages must inspect (and so would pull) target before leash. Uses an
// injected Runtime — no package globals touched.
func TestContainerLauncherPullImagesOrder(t *testing.T) {
	t.Parallel()

	var inspected []string
	r := &runner{runtime: recordingRuntime{inspected: &inspected}}
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
