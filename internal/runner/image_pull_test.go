package runner

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"strings"
	"testing"
)

// imageStoreRuntime is an in-memory Runtime modelling an engine's local image
// store: `image inspect` succeeds for present images and fails with the
// engine's own "missing" wording otherwise; `pull` adds the image or fails
// with a scripted error. It touches no package globals, so tests run in
// parallel.
type imageStoreRuntime struct {
	engine string
	// present is the local store. A successful pull adds to it.
	present map[string]bool
	// pullErrs scripts a pull failure per image.
	pullErrs map[string]error
	// inspectErrs is consumed one entry per plain `image inspect`, before the
	// store is consulted; a nil entry falls through to the store.
	inspectErrs []error
	// appearAfterPull marks images that a failed pull reveals as present
	// (models the transient false "missing" from issue #170).
	appearAfterPull map[string]bool
	calls           *[]string
}

func newImageStore(engine string, present ...string) *imageStoreRuntime {
	rt := &imageStoreRuntime{
		engine:          engine,
		present:         map[string]bool{},
		pullErrs:        map[string]error{},
		appearAfterPull: map[string]bool{},
		calls:           new([]string),
	}
	for _, p := range present {
		rt.present[p] = true
	}
	return rt
}

func (s *imageStoreRuntime) missingErr(image string) error {
	if s.engine == "podman" {
		return errors.New("podman image inspect " + image + ": exit status 125: Error: " + image + ": image not known")
	}
	return errors.New("docker image inspect " + image + ": exit status 1: []\nError: No such image: " + image)
}

func (s *imageStoreRuntime) Run(ctx context.Context, args ...string) error {
	*s.calls = append(*s.calls, strings.Join(args, " "))
	if len(args) == 2 && args[0] == "pull" {
		image := args[1]
		if err := s.pullErrs[image]; err != nil {
			if s.appearAfterPull[image] {
				s.present[image] = true
			}
			return err
		}
		s.present[image] = true
	}
	return nil
}

func (s *imageStoreRuntime) Output(ctx context.Context, args ...string) (string, error) {
	*s.calls = append(*s.calls, strings.Join(args, " "))
	if len(args) >= 3 && args[0] == "image" && args[1] == "inspect" {
		image := args[len(args)-1]
		if len(args) == 3 && len(s.inspectErrs) > 0 {
			err := s.inspectErrs[0]
			s.inspectErrs = s.inspectErrs[1:]
			if err != nil {
				return "", err
			}
		}
		if !s.present[image] {
			return "", s.missingErr(image)
		}
		if args[2] == "--format" {
			return `{"io.leash.manager.contract.version":"1","io.leash.manager.contract.min-compatible":"1","org.opencontainers.image.revision":"dev"}`, nil
		}
		return "[{}]", nil
	}
	return "ok", nil
}

func (s *imageStoreRuntime) ExecWithInput(ctx context.Context, container, shellCommand string, input io.Reader) error {
	return nil
}

func (s *imageStoreRuntime) Cmd(ctx context.Context, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, "true")
}

func (s *imageStoreRuntime) Name() string { return s.engine }

func (s *imageStoreRuntime) pulls() []string {
	var out []string
	for _, c := range *s.calls {
		if strings.HasPrefix(c, "pull ") {
			out = append(out, strings.TrimPrefix(c, "pull "))
		}
	}
	return out
}

func pullRunner(rt Runtime) *runner {
	r := &runner{runtime: rt}
	r.cfg.targetImage = "my-coder"
	r.cfg.leashImage = "ghcr.io/strongdm/leash:latest"
	return r
}

func TestPullImagesSkipsPullForLocalImages(t *testing.T) {
	t.Parallel()
	for _, engine := range []string{"docker", "podman"} {
		rt := newImageStore(engine, "my-coder", "ghcr.io/strongdm/leash:latest")
		// Any pull would fail: proves none is attempted.
		rt.pullErrs["my-coder"] = errors.New("pull access denied for my-coder, repository does not exist or may require 'docker login'")
		rt.pullErrs["ghcr.io/strongdm/leash:latest"] = errors.New("unauthorized")
		if err := pullRunner(rt).launcher().PullImages(context.Background()); err != nil {
			t.Fatalf("%s: PullImages with both images local: %v", engine, err)
		}
		if got := rt.pulls(); len(got) != 0 {
			t.Fatalf("%s: pulled %v, want no pulls for local images", engine, got)
		}
	}
}

func TestPullImagesPullsAbsentImages(t *testing.T) {
	t.Parallel()
	for _, engine := range []string{"docker", "podman"} {
		rt := newImageStore(engine)
		if err := pullRunner(rt).launcher().PullImages(context.Background()); err != nil {
			t.Fatalf("%s: PullImages: %v", engine, err)
		}
		got := rt.pulls()
		if len(got) != 2 || got[0] != "my-coder" || got[1] != "ghcr.io/strongdm/leash:latest" {
			t.Fatalf("%s: pulled %v, want target then manager", engine, got)
		}
	}
}

func TestPullImagesPullsOnlyTheMissingImage(t *testing.T) {
	t.Parallel()
	rt := newImageStore("docker", "my-coder")
	if err := pullRunner(rt).launcher().PullImages(context.Background()); err != nil {
		t.Fatalf("PullImages: %v", err)
	}
	if got := rt.pulls(); len(got) != 1 || got[0] != "ghcr.io/strongdm/leash:latest" {
		t.Fatalf("pulled %v, want only the manager image", got)
	}
}

func TestPullImagesFailureNamesRealCause(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		engine     string
		missing    string // which role's image is absent: "target" or "manager"
		pullErr    string
		want       []string
		wantAbsent []string
	}{
		{
			name:    "docker local target not found",
			engine:  "docker",
			missing: "target",
			pullErr: "docker: exit status 1: Error response from daemon: pull access denied for my-coder, repository does not exist or may require 'docker login': denied: requested access to the resource is denied",
			want: []string{`target image "my-coder" is not in the local docker image store`, "repository does not exist there, or it is private",
				"if it is a locally built image", "docker said: Error response from daemon: pull access denied"},
		},
		{
			name:    "docker manager manifest unknown",
			engine:  "docker",
			missing: "manager",
			pullErr: "docker: exit status 1: Error response from daemon: manifest for ghcr.io/strongdm/leash:latest not found: manifest unknown: manifest unknown",
			want:    []string{`manager image "ghcr.io/strongdm/leash:latest" is not in the local docker image store`, "no such image or tag"},
			// Registry-qualified: the local-build hint would mislead.
			wantAbsent: []string{"locally built", "docker login"},
		},
		{
			name:       "docker manager auth",
			engine:     "docker",
			missing:    "manager",
			pullErr:    "docker: exit status 1: Error response from daemon: Head \"https://ghcr.io/v2/strongdm/leash/manifests/latest\": unauthorized: authentication required",
			want:       []string{"requires authentication", "docker login ghcr.io", "unauthorized"},
			wantAbsent: []string{"locally built"},
		},
		{
			name:       "docker target network",
			engine:     "docker",
			missing:    "target",
			pullErr:    "docker: exit status 1: Error response from daemon: Get \"https://registry-1.docker.io/v2/\": dial tcp: lookup registry-1.docker.io: no such host",
			want:       []string{`target image "my-coder"`, "could not be reached", "no such host"},
			wantAbsent: []string{"login", "locally built"},
		},
		{
			name:       "podman manager network",
			engine:     "podman",
			missing:    "manager",
			pullErr:    "podman: exit status 125: Trying to pull ghcr.io/strongdm/leash:latest...\nError: initializing source docker://ghcr.io/strongdm/leash:latest: pinging container registry ghcr.io: Get \"https://ghcr.io/v2/\": dial tcp 140.82.121.34:443: i/o timeout",
			want:       []string{`manager image "ghcr.io/strongdm/leash:latest" is not in the local podman image store`, "could not be reached", "i/o timeout"},
			wantAbsent: []string{"Trying to pull", "login"},
		},
		{
			name:    "podman target short-name",
			engine:  "podman",
			missing: "target",
			pullErr: "podman: exit status 125: Error: short-name \"my-coder\" did not resolve to an alias and no unqualified-search registries are defined in \"/etc/containers/registries.conf\"",
			want:    []string{"could not resolve the unqualified name", "localhost/<name>", "podman said: Error: short-name"},
		},
		{
			name:    "podman target not found",
			engine:  "podman",
			missing: "target",
			pullErr: "podman: exit status 125: Trying to pull docker.io/library/my-coder:latest...\nError: initializing source docker://my-coder:latest: reading manifest latest in docker.io/library/my-coder: requested access to the resource is denied",
			want:    []string{"repository does not exist there, or it is private and needs `podman login`", "localhost/<name>"},
		},
		{
			name:    "manager pull failure with unknown cause",
			engine:  "docker",
			missing: "manager",
			pullErr: "docker: exit status 1: something unexpected \x1b[31mbroke\x1b[0m",
			want:    []string{"pulling it failed: the pull failed", "docker said: something unexpected broke"},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := pullRunner(nil)
			missing := r.cfg.targetImage
			var present []string
			if tc.missing == "target" {
				present = []string{r.cfg.leashImage}
			} else {
				missing = r.cfg.leashImage
				present = []string{r.cfg.targetImage}
			}
			rt := newImageStore(tc.engine, present...)
			rt.pullErrs[missing] = errors.New(tc.pullErr)
			r.runtime = rt

			err := r.launcher().PullImages(context.Background())
			if err == nil {
				t.Fatal("PullImages succeeded, want pull failure")
			}
			msg := err.Error()
			for _, w := range tc.want {
				if !strings.Contains(msg, w) {
					t.Errorf("error %q\n  missing %q", msg, w)
				}
			}
			for _, w := range tc.wantAbsent {
				if strings.Contains(msg, w) {
					t.Errorf("error %q\n  should not contain %q", msg, w)
				}
			}
			if strings.ContainsRune(msg, '\x1b') || strings.ContainsRune(msg, '\n') {
				t.Errorf("error is not sanitized: %q", msg)
			}
		})
	}
}

// A first inspect that falsely reports the image missing (issue #170's
// trigger) must not kill the run when the image is there after all.
func TestPullImagesToleratesFalseMissingInspect(t *testing.T) {
	t.Parallel()
	rt := newImageStore("docker", "ghcr.io/strongdm/leash:latest")
	rt.pullErrs["my-coder"] = errors.New("pull access denied for my-coder, repository does not exist or may require 'docker login'")
	rt.appearAfterPull["my-coder"] = true
	if err := pullRunner(rt).launcher().PullImages(context.Background()); err != nil {
		t.Fatalf("PullImages: %v", err)
	}
}

// A non-"missing" inspect failure is retried once and does not trigger a pull.
func TestPullImagesRetriesTransientInspectError(t *testing.T) {
	t.Parallel()
	rt := newImageStore("docker", "my-coder", "ghcr.io/strongdm/leash:latest")
	rt.inspectErrs = []error{errors.New("docker image inspect my-coder: exit status 1: Cannot connect to the Docker daemon at unix:///var/run/docker.sock")}
	if err := pullRunner(rt).launcher().PullImages(context.Background()); err != nil {
		t.Fatalf("PullImages: %v", err)
	}
	if got := rt.pulls(); len(got) != 0 {
		t.Fatalf("pulled %v after a transient inspect error, want none", got)
	}
}

func TestPullImagesPersistentInspectErrorIsReported(t *testing.T) {
	t.Parallel()
	daemonDown := errors.New("docker image inspect my-coder: exit status 1: Cannot connect to the Docker daemon at unix:///var/run/docker.sock")
	rt := newImageStore("docker", "my-coder", "ghcr.io/strongdm/leash:latest")
	rt.inspectErrs = []error{daemonDown, daemonDown}
	err := pullRunner(rt).launcher().PullImages(context.Background())
	if err == nil || !strings.Contains(err.Error(), `inspect target image "my-coder" with docker`) || !strings.Contains(err.Error(), "Cannot connect to the Docker daemon") {
		t.Fatalf("PullImages error = %v, want the inspect failure named", err)
	}
	if got := rt.pulls(); len(got) != 0 {
		t.Fatalf("pulled %v, want no pull when inspect itself fails", got)
	}
}

func TestEngineDetailIsBounded(t *testing.T) {
	t.Parallel()
	got := engineDetail(errors.New("Error: " + strings.Repeat("x", 5000)))
	if n := len([]rune(got)); n > pullDetailLimit+3 {
		t.Fatalf("detail length %d exceeds bound", n)
	}
}

func TestImageHasRegistryHost(t *testing.T) {
	t.Parallel()
	for image, want := range map[string]bool{
		"my-coder":                      false,
		"leash/build-base:latest":       false,
		"localhost/my-coder":            true,
		"ghcr.io/strongdm/leash:latest": true,
		"registry:5000/img":             true,
		"docker.io/library/debian":      true,
	} {
		if got := imageHasRegistryHost(image); got != want {
			t.Errorf("imageHasRegistryHost(%q) = %v, want %v", image, got, want)
		}
	}
}

func TestIsNoSuchImageErrorCoversPodman(t *testing.T) {
	t.Parallel()
	for _, msg := range []string{
		"Error: No such image: foo",
		"Error: No such object: foo",
		"Error: foo: image not known",
		"Error: failed to find image foo",
	} {
		if !isNoSuchImageError(errors.New(msg)) {
			t.Errorf("isNoSuchImageError(%q) = false", msg)
		}
	}
	if isNoSuchImageError(errors.New("Cannot connect to the Docker daemon")) {
		t.Error("daemon error misclassified as missing image")
	}
}
