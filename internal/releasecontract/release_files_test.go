package releasecontract

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
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
		strings.Count(release, "timeout 2m docker buildx imagetools inspect") != 3 {
		t.Fatal("local build and registry inspection gates must be bounded")
	}
	for _, required := range []string{
		`--raw "$MANAGER_REF"`,
		`"$MANAGER_REPO@$MANAGER_DIGEST_AMD64"`,
		`"$MANAGER_REPO@$MANAGER_DIGEST_ARM64"`,
		`native_assert_manager_digest "$MANAGER_TAG" "$MANAGER_DIGEST"`,
	} {
		if !strings.Contains(release, required) {
			t.Errorf("release is missing digest-bound recovery gate %q", required)
		}
	}
}

func TestVerifyManagerManifest(t *testing.T) {
	root := repositoryRoot(t)
	script := filepath.Join(root, "scripts", "verify-manager-manifest.py")
	testDigest := "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

	tests := []struct {
		name           string
		manifest       string
		images         string
		expectedDigest string
		wantErr        string
	}{
		{
			name: "required platforms plus attestation",
			manifest: `{"digest":"` + testDigest + `","manifests":[
				{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":100,"platform":{"os":"linux","architecture":"amd64"}},
				{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","size":50,"annotations":{"vnd.docker.reference.type":"attestation-manifest","vnd.docker.reference.digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"platform":{"os":"unknown","architecture":"unknown"}},
				{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size":100,"platform":{"os":"linux","architecture":"arm64","variant":"v8"}}
			]}`,
			images: validManagerImages("test-revision"),
		},
		{
			name:     "missing arm64",
			manifest: `{"digest":"` + testDigest + `","manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":100,"platform":{"os":"linux","architecture":"amd64"}}]}`,
			images:   validManagerImages("test-revision"),
			wantErr:  "manager manifest missing required platform(s): linux/arm64",
		},
		{
			name: "same image for both platforms",
			manifest: `{"digest":"` + testDigest + `","manifests":[
				{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":100,"platform":{"os":"linux","architecture":"amd64"}},
				{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":100,"platform":{"os":"linux","architecture":"arm64"}}
			]}`,
			images:  validManagerImages("test-revision"),
			wantErr: "required platforms must use distinct images",
		},
		{
			name: "descriptor without digest",
			manifest: `{"digest":"` + testDigest + `","manifests":[
				{"mediaType":"application/vnd.oci.image.manifest.v1+json","size":100,"platform":{"os":"linux","architecture":"amd64"}},
				{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size":100,"platform":{"os":"linux","architecture":"arm64"}}
			]}`,
			images:  validManagerImages("test-revision"),
			wantErr: "invalid sha256 digest",
		},
		{
			name: "wrong arm64 label",
			manifest: `{"digest":"` + testDigest + `","manifests":[
				{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":100,"platform":{"os":"linux","architecture":"amd64"}},
				{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size":100,"platform":{"os":"linux","architecture":"arm64"}}
			]}`,
			images:  validManagerImages("wrong-revision"),
			wantErr: "org.opencontainers.image.revision",
		},
		{
			name: "unexpected runnable platform",
			manifest: `{"digest":"` + testDigest + `","manifests":[
				{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":100,"platform":{"os":"linux","architecture":"amd64"}},
				{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size":100,"platform":{"os":"linux","architecture":"arm64"}},
				{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","size":100,"platform":{"os":"linux","architecture":"s390x"}}
			]}`,
			images:  validManagerImages("test-revision"),
			wantErr: "unexpected runnable platform linux/s390x",
		},
		{
			name: "wrong index digest",
			manifest: `{"digest":"sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","manifests":[
				{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":100,"platform":{"os":"linux","architecture":"amd64"}},
				{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size":100,"platform":{"os":"linux","architecture":"arm64"}}
			]}`,
			images:         validManagerImages("test-revision"),
			expectedDigest: testDigest,
			wantErr:        "manager registry digest",
		},
		{
			name: "wrong release version",
			manifest: `{"digest":"` + testDigest + `","manifests":[
				{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":100,"platform":{"os":"linux","architecture":"amd64"}},
				{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size":100,"platform":{"os":"linux","architecture":"arm64"}}
			]}`,
			images:  validManagerImagesWithRelease("test-revision", "v9.9.9", "release"),
			wantErr: "org.opencontainers.image.version",
		},
		{
			name: "wrong release channel",
			manifest: `{"digest":"` + testDigest + `","manifests":[
				{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":100,"platform":{"os":"linux","architecture":"amd64"}},
				{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size":100,"platform":{"os":"linux","architecture":"arm64"}}
			]}`,
			images:  validManagerImagesWithRelease("test-revision", "v0.3.4", "main"),
			wantErr: "org.opencontainers.image.ref.name",
		},
		{
			name: "invalid arm64 variant",
			manifest: `{"digest":"` + testDigest + `","manifests":[
				{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":100,"platform":{"os":"linux","architecture":"amd64"}},
				{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size":100,"platform":{"os":"linux","architecture":"arm64","variant":"v7"}}
			]}`,
			images:  validManagerImages("test-revision"),
			wantErr: "unsupported platform variant",
		},
		{
			name: "unknown descriptor without attestation identity",
			manifest: `{"digest":"` + testDigest + `","manifests":[
				{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":100,"platform":{"os":"linux","architecture":"amd64"}},
				{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size":100,"platform":{"os":"linux","architecture":"arm64"}},
				{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","size":50,"platform":{"os":"unknown","architecture":"unknown"}}
			]}`,
			images:  validManagerImages("test-revision"),
			wantErr: "missing attestation annotations",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			manifestPath := filepath.Join(t.TempDir(), "manifest.json")
			if err := os.WriteFile(manifestPath, []byte(tc.manifest), 0o600); err != nil {
				t.Fatal(err)
			}
			var images map[string]json.RawMessage
			if err := json.Unmarshal([]byte(tc.images), &images); err != nil {
				t.Fatal(err)
			}
			amd64Path := filepath.Join(t.TempDir(), "amd64.json")
			arm64Path := filepath.Join(t.TempDir(), "arm64.json")
			if err := os.WriteFile(amd64Path, images["linux/amd64"], 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(arm64Path, images["linux/arm64"], 0o600); err != nil {
				t.Fatal(err)
			}
			expectedDigest := tc.expectedDigest
			if expectedDigest == "" {
				expectedDigest = fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(tc.manifest)))
			}
			cmd := exec.Command("python3", script, "registry", manifestPath,
				"--image-amd64", amd64Path, "--image-arm64", arm64Path,
				"--revision", "test-revision", "--digest", expectedDigest,
				"--version", "0.3.4", "--channel", "release")
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
	return validManagerImagesWithRelease(revision, "v0.3.4", "release")
}

func validManagerImagesWithRelease(revision, version, channel string) string {
	return `{
		"linux/amd64":{"architecture":"amd64","os":"linux","config":{"Labels":{
			"org.opencontainers.image.revision":"` + revision + `",
			"org.opencontainers.image.version":"` + version + `",
			"org.opencontainers.image.ref.name":"` + channel + `",
			"io.leash.manager.contract.version":"1",
			"io.leash.manager.contract.min-compatible":"1"}}},
		"linux/arm64":{"architecture":"arm64","os":"linux","config":{"Labels":{
			"org.opencontainers.image.revision":"` + revision + `",
			"org.opencontainers.image.version":"` + version + `",
			"org.opencontainers.image.ref.name":"` + channel + `",
			"io.leash.manager.contract.version":"1",
			"io.leash.manager.contract.min-compatible":"1"}}}
	}`
}
