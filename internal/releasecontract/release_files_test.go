package releasecontract

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func readRepositoryFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repositoryRoot(t), path))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func TestManagerTargetConsumesGeneratedBPFArtifacts(t *testing.T) {
	dockerfile := readRepositoryFile(t, "Dockerfile.leash")
	if !strings.Contains(dockerfile, "FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-bookworm AS build-base") {
		t.Fatal("shared manager build-base must execute on BUILDPLATFORM")
	}
	if !strings.Contains(dockerfile, "FROM --platform=$BUILDPLATFORM ${BASE_BUILD_IMAGE} AS lsm-generate") {
		t.Fatal("BPF generator must execute on BUILDPLATFORM")
	}
	start := strings.Index(dockerfile, "FROM --platform=$BUILDPLATFORM ${BASE_BUILD_IMAGE} AS build")
	if start < 0 {
		t.Fatal("manager build stage not found")
	}
	endOffset := strings.Index(dockerfile[start+1:], "\nFROM ")
	if endOffset < 0 {
		t.Fatal("manager build stage terminator not found")
	}
	buildStage := dockerfile[start : start+1+endOffset]
	buildBase := dockerfile[:start]
	if strings.Contains(buildBase, "ARG TARGETARCH") || strings.Contains(buildBase, "${TARGETARCH") {
		t.Fatal("shared build-base depends on target architecture and cannot be reused across platforms")
	}

	for _, instruction := range dockerInstructions(buildStage) {
		if !strings.HasPrefix(instruction, "RUN ") {
			continue
		}
		for _, forbidden := range []string{"bpf2go", "go generate", "lsm-generate"} {
			if strings.Contains(strings.ToLower(instruction), forbidden) {
				t.Fatalf("target-platform manager build runs build-host tool %q in %q", forbidden, instruction)
			}
		}
	}
	for _, required := range []string{
		"ARG TARGETOS=linux",
		"ARG TARGETARCH",
		"CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH}",
	} {
		if !strings.Contains(buildStage, required) {
			t.Errorf("build-platform manager stage missing cross-build contract %q", required)
		}
	}
	for _, artifact := range []string{
		"lsmopen_bpfeb.go", "lsmopen_bpfeb.o",
		"lsmopen_bpfel.go", "lsmopen_bpfel.o",
		"lsmexec_bpfeb.go", "lsmexec_bpfeb.o",
		"lsmexec_bpfel.go", "lsmexec_bpfel.o",
		"lsmconnect_bpfeb.go", "lsmconnect_bpfeb.o",
		"lsmconnect_bpfel.go", "lsmconnect_bpfel.o",
	} {
		if !strings.Contains(buildStage, artifact) {
			t.Errorf("target-platform manager build does not validate %s", artifact)
		}
	}
}

func dockerInstructions(stage string) []string {
	var instructions []string
	var current strings.Builder
	flush := func() {
		if current.Len() > 0 {
			instructions = append(instructions, current.String())
			current.Reset()
		}
	}
	for _, line := range strings.Split(stage, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		first := strings.Fields(trimmed)[0]
		if first == strings.ToUpper(first) && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			flush()
		}
		current.WriteString(trimmed)
		current.WriteByte('\n')
	}
	flush()
	return instructions
}

func TestReleaseGeneratesBeforeBuildAndVerifiesPublishedPlatforms(t *testing.T) {
	release := readRepositoryFile(t, "scripts/release.sh")
	generation := strings.Index(release, "make lsm-generate")
	preflight := strings.Index(release, "verify-manager-manifest.py oci")
	publication := strings.Index(release, "./build/publish-docker.sh")
	platformGate := strings.Index(release, "verify-manager-manifest.py registry")
	pull := strings.Index(release, "docker pull \"$MANAGER_REF\"")
	if generation < 0 || preflight < 0 || publication < 0 || platformGate < 0 || pull < 0 {
		t.Fatalf("release boundary missing: generation=%d preflight=%d publication=%d platformGate=%d pull=%d", generation, preflight, publication, platformGate, pull)
	}
	if !(generation < preflight && preflight < publication && publication < platformGate && platformGate < pull) {
		t.Fatalf("release boundary out of order: generation=%d preflight=%d publication=%d platformGate=%d pull=%d", generation, preflight, publication, platformGate, pull)
	}
	if !strings.Contains(release, "--no-latest") {
		t.Fatal("release must preserve immutable manager publication without latest")
	}
	if !strings.Contains(release, "timeout 10m docker buildx build") ||
		strings.Count(release, "timeout 2m docker buildx imagetools inspect") != 2 {
		t.Fatal("local build and registry inspection gates must be bounded")
	}
}

func TestVerifyManagerManifest(t *testing.T) {
	root := repositoryRoot(t)
	script := filepath.Join(root, "scripts", "verify-manager-manifest.py")

	tests := []struct {
		name     string
		manifest string
		images   string
		wantErr  string
	}{
		{
			name: "required platforms plus attestation",
			manifest: `{"manifests":[
				{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":100,"platform":{"os":"linux","architecture":"amd64"}},
				{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","size":50,"platform":{"os":"unknown","architecture":"unknown"}},
				{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size":100,"platform":{"os":"linux","architecture":"arm64","variant":"v8"}}
			]}`,
			images: validManagerImages("test-revision"),
		},
		{
			name:     "missing arm64",
			manifest: `{"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":100,"platform":{"os":"linux","architecture":"amd64"}}]}`,
			images:   validManagerImages("test-revision"),
			wantErr:  "manager manifest missing required platform(s): linux/arm64",
		},
		{
			name: "same image for both platforms",
			manifest: `{"manifests":[
				{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":100,"platform":{"os":"linux","architecture":"amd64"}},
				{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":100,"platform":{"os":"linux","architecture":"arm64"}}
			]}`,
			images:  validManagerImages("test-revision"),
			wantErr: "required platforms must use distinct images",
		},
		{
			name: "descriptor without digest",
			manifest: `{"manifests":[
				{"mediaType":"application/vnd.oci.image.manifest.v1+json","size":100,"platform":{"os":"linux","architecture":"amd64"}},
				{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size":100,"platform":{"os":"linux","architecture":"arm64"}}
			]}`,
			images:  validManagerImages("test-revision"),
			wantErr: "invalid sha256 digest",
		},
		{
			name: "wrong arm64 label",
			manifest: `{"manifests":[
				{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":100,"platform":{"os":"linux","architecture":"amd64"}},
				{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size":100,"platform":{"os":"linux","architecture":"arm64"}}
			]}`,
			images:  validManagerImages("wrong-revision"),
			wantErr: "org.opencontainers.image.revision",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			manifestPath := filepath.Join(t.TempDir(), "manifest.json")
			if err := os.WriteFile(manifestPath, []byte(tc.manifest), 0o600); err != nil {
				t.Fatal(err)
			}
			imagesPath := filepath.Join(t.TempDir(), "images.json")
			if err := os.WriteFile(imagesPath, []byte(tc.images), 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("python3", script, "registry", manifestPath,
				"--images", imagesPath, "--revision", "test-revision")
			output, err := cmd.CombinedOutput()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("verify manifest: %v\n%s", err, output)
				}
				return
			}
			if err == nil {
				t.Fatalf("verify manifest succeeded, want error containing %q", tc.wantErr)
			}
			if !strings.Contains(string(output), tc.wantErr) {
				t.Fatalf("verify manifest output = %q, want %q", output, tc.wantErr)
			}
		})
	}
}

func validManagerImages(revision string) string {
	return `{
		"linux/amd64":{"architecture":"amd64","os":"linux","config":{"Labels":{
			"org.opencontainers.image.revision":"` + revision + `",
			"io.leash.manager.contract.version":"1",
			"io.leash.manager.contract.min-compatible":"1"}}},
		"linux/arm64":{"architecture":"arm64","os":"linux","config":{"Labels":{
			"org.opencontainers.image.revision":"` + revision + `",
			"io.leash.manager.contract.version":"1",
			"io.leash.manager.contract.min-compatible":"1"}}}
	}`
}
