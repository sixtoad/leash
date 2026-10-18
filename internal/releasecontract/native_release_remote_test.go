package releasecontract

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeManagerVersionNormalizer(t *testing.T) {
	for _, tc := range []struct {
		tag     string
		want    string
		wantErr bool
	}{
		{tag: "native-v0.3.4", want: "native-v0.3.4\n"},
		{tag: "v0.3.4", wantErr: true},
		{tag: "native-v0.3", wantErr: true},
	} {
		t.Run(tc.tag, func(t *testing.T) {
			command := exec.Command("bash", "-c", `source "$1"; native_manager_version "$2"`, "bash",
				filepath.Join(repositoryRoot(t), "scripts", "native-release-remote.sh"), tc.tag)
			output, err := command.CombinedOutput()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("normalizer succeeded: %s", output)
				}
				return
			}
			if err != nil || string(output) != tc.want {
				t.Fatalf("normalizer: %v, output %q, want %q", err, output, tc.want)
			}
		})
	}
}

func TestNativePublisherUsesCanonicalLabelVersionWithNativeTag(t *testing.T) {
	fakeBin := t.TempDir()
	logPath := filepath.Join(fakeBin, "docker.log")
	docker := `#!/bin/sh
printf '%s\n' "$*" >> "$DOCKER_LOG"
`
	if err := os.WriteFile(filepath.Join(fakeBin, "docker"), []byte(docker), 0o755); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("bash", filepath.Join(repositoryRoot(t), "build", "publish-docker.sh"),
		"--only-leash", "--no-latest", "native-v0.3.4")
	command.Dir = repositoryRoot(t)
	command.Env = append(os.Environ(), "PATH="+fakeBin+":"+os.Getenv("PATH"), "DOCKER_LOG="+logPath,
		"LEASH_IMAGE=ghcr.io/sixtoad/leash-manager", "RELEASE_CHANNEL=release")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("publisher: %v\n%s", err, output)
	}
	logged, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	args := string(logged)
	for _, want := range []string{
		"-t ghcr.io/sixtoad/leash-manager:native-v0.3.4",
		"--build-arg VERSION=native-v0.3.4",
	} {
		if !strings.Contains(args, want) {
			t.Fatalf("publisher args %q lack %q", args, want)
		}
	}
	if strings.Contains(args, "VERSION=0.3.4") || strings.Contains(args, "VERSION=v0.3.4") {
		t.Fatalf("publisher transformed the canonical release identifier: %s", args)
	}
}

func TestNativeReleaseRemoteModes(t *testing.T) {
	tests := []struct {
		name      string
		scenario  string
		resume    string
		want      string
		wantErr   string
		forbidden string
	}{
		{name: "fresh publication", scenario: "fresh", resume: "0", want: "fresh\n"},
		{name: "matching recovery", scenario: "manager-present", resume: "1", want: "resume\n", forbidden: "--method PATCH"},
		{name: "ordinary retry refuses manager", scenario: "manager-present", resume: "0", wantErr: "--resume-existing-manager"},
		{name: "recovery requires manager", scenario: "fresh", resume: "1", wantErr: "requires existing manager tag"},
		{name: "existing Git tag refuses recovery", scenario: "git-tag", resume: "1", wantErr: "refusing to mutate existing Git tag"},
		{name: "existing release refuses recovery", scenario: "release", resume: "1", wantErr: "refusing to mutate existing GitHub release"},
		{name: "package 404 registry tag exists", scenario: "package-404-existing", resume: "1", want: "resume\n"},
		{name: "package 404 registry tag absent", scenario: "package-404-missing", resume: "0", want: "fresh\n"},
		{name: "package 404 registry access denied", scenario: "package-404-denied", resume: "0", wantErr: "could not prove"},
		{name: "workflow token package 403 falls back to registry", scenario: "package-403-missing", resume: "0", want: "fresh\n"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fakeBin, logPath := fakeGitHubCLI(t)
			command := exec.Command("bash", "-c", `
source "$1"
native_remote_mode "$2" sixtoad/leash sixtoad leash-manager native-v0.3.4 "$3"
`, "bash", filepath.Join(repositoryRoot(t), "scripts", "native-release-remote.sh"), t.TempDir(), tc.resume)
			command.Env = append(os.Environ(),
				"PATH="+fakeBin+":"+os.Getenv("PATH"),
				"GH_SCENARIO="+tc.scenario,
				"GH_LOG="+logPath,
			)
			output, err := command.CombinedOutput()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("remote mode: %v\n%s", err, output)
				}
				if string(output) != tc.want {
					t.Fatalf("remote mode output = %q, want %q", output, tc.want)
				}
			} else {
				if err == nil {
					t.Fatalf("remote mode succeeded, want %q\n%s", tc.wantErr, output)
				}
				if !strings.Contains(string(output), tc.wantErr) {
					t.Fatalf("remote mode output = %q, want %q", output, tc.wantErr)
				}
			}
			if tc.forbidden != "" {
				log, readErr := os.ReadFile(logPath)
				if readErr != nil {
					t.Fatal(readErr)
				}
				if strings.Contains(string(log), tc.forbidden) {
					t.Fatalf("remote-state planning mutated package: %s", log)
				}
			}
		})
	}
}

func TestNativeReleaseVisibility(t *testing.T) {
	tests := []struct {
		name     string
		scenario string
		wantErr  string
	}{
		{name: "already public", scenario: "public"},
		{name: "private requires UI and resume", scenario: "private", wantErr: "https://github.com/users/sixtoad/packages/container/leash-manager/settings"},
		{name: "visibility read failure is diagnosed", scenario: "visibility-fail", wantErr: "could not read manager package visibility via GET /user/packages/container/leash-manager"},
		{name: "workflow token proves public anonymously", scenario: "anonymous-public"},
		{name: "workflow token anonymous refusal is private", scenario: "anonymous-private", wantErr: "https://github.com/users/sixtoad/packages/container/leash-manager/settings"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fakeBin, logPath := fakeGitHubCLI(t)
			temp := t.TempDir()
			command := exec.Command("bash", "-c", `
source "$1"
native_require_manager_public "$2" sixtoad leash-manager native-v0.3.4 /release/source
`, "bash", filepath.Join(repositoryRoot(t), "scripts", "native-release-remote.sh"), temp)
			command.Env = append(os.Environ(),
				"PATH="+fakeBin+":"+os.Getenv("PATH"),
				"GH_SCENARIO="+tc.scenario,
				"GH_LOG="+logPath,
			)
			output, err := command.CombinedOutput()
			if tc.wantErr == "" && err != nil {
				t.Fatalf("visibility: %v\n%s", err, output)
			}
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(string(output), tc.wantErr) {
					t.Fatalf("visibility output = %q, want failure containing %q", output, tc.wantErr)
				}
			}
			log, readErr := os.ReadFile(logPath)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if strings.Contains(string(log), "--method") {
				t.Fatalf("visibility gate attempted unsupported mutation: %s", log)
			}
			if tc.scenario == "private" && !strings.Contains(string(output), "scripts/release.sh --resume-existing-manager --release-source-root /release/source native-v0.3.4") {
				t.Fatalf("private-package output lacks exact resume command: %s", output)
			}
		})
	}
}

func TestRecoveryBranchNeverPublishesManager(t *testing.T) {
	release := readRepositoryFile(t, "scripts/release.sh")
	fresh := strings.Index(release, "publish_fresh_manager()")
	recovery := strings.Index(release, "resume_existing_manager()")
	common := strings.Index(release, "if (( !DRY_RUN )); then\n  MANAGER_REF=")
	publication := strings.Index(release, "./build/publish-docker.sh")
	resolve := strings.Index(release, "native_resolve_manager_digest")
	dispatch := strings.Index(release, `native_execute_manager_mode "$REMOTE_MODE" publish_fresh_manager resume_existing_manager`)
	if fresh < 0 || publication < fresh || recovery < publication || resolve < recovery || dispatch < resolve || common < dispatch {
		t.Fatalf("fresh/recovery boundary missing or out of order: fresh=%d publication=%d recovery=%d resolve=%d dispatch=%d common=%d", fresh, publication, recovery, resolve, dispatch, common)
	}
	if !strings.Contains(release, `native_require_manager_public "$TEMP"`) ||
		!strings.Contains(release, `DOCKER_CONFIG="$TEMP/anonymous-docker" timeout 2m docker pull "$MANAGER_REF"`) {
		t.Fatal("fresh and recovery paths must converge before visibility and anonymous-pull gates")
	}
	if strings.Contains(release, "--method PATCH") || strings.Contains(readRepositoryFile(t, "scripts/native-release-remote.sh"), "--method PATCH") {
		t.Fatal("release must not use unsupported GitHub Packages visibility mutation")
	}
}

func TestNativeExecuteManagerMode(t *testing.T) {
	for _, tc := range []struct {
		mode string
		want string
	}{
		{mode: "fresh", want: "push\n"},
		{mode: "resume", want: "resolve\n"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			command := exec.Command("bash", "-c", `
source "$1"
publish() { printf '%s\n' push; }
resolve() { printf '%s\n' resolve; }
native_execute_manager_mode "$2" publish resolve
`, "bash", filepath.Join(repositoryRoot(t), "scripts", "native-release-remote.sh"), tc.mode)
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("manager dispatch: %v\n%s", err, output)
			}
			if string(output) != tc.want {
				t.Fatalf("manager dispatch output = %q, want %q", output, tc.want)
			}
			if tc.mode == "resume" && strings.Contains(string(output), "push") {
				t.Fatalf("resume dispatched publication: %s", output)
			}
		})
	}
}

func TestNativeReleaseDigestResolutionAndDrift(t *testing.T) {
	fakeBin, _ := fakeGitHubCLI(t)
	digestA := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digestB := "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	for _, tc := range []struct {
		name     string
		scenario string
		expected string
		wantErr  string
	}{
		{name: "matching digest", scenario: "digest-match", expected: digestA},
		{name: "tag drift", scenario: "digest-drift", expected: digestA, wantErr: "drifted from " + digestA + " to " + digestB},
	} {
		t.Run(tc.name, func(t *testing.T) {
			command := exec.Command("bash", "-c", `
source "$1"
native_assert_manager_digest ghcr.io/sixtoad/leash-manager:native-v0.3.4 "$2" "$3"
`, "bash", filepath.Join(repositoryRoot(t), "scripts", "native-release-remote.sh"), tc.expected, filepath.Join(t.TempDir(), "manifest.json"))
			command.Env = append(os.Environ(), "PATH="+fakeBin+":"+os.Getenv("PATH"), "GH_SCENARIO="+tc.scenario)
			output, err := command.CombinedOutput()
			if tc.wantErr == "" && err != nil {
				t.Fatalf("digest assertion: %v\n%s", err, output)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(string(output), tc.wantErr)) {
				t.Fatalf("digest assertion output = %q, want %q", output, tc.wantErr)
			}
		})
	}
}

func TestNativeReleaseSourceRoot(t *testing.T) {
	toolingRoot, toolingHead := committedCheckout(t, "tooling")
	sourceRoot, sourceHead := committedCheckout(t, "source")
	if toolingHead == sourceHead {
		t.Fatal("test requires distinct tooling and release-source revisions")
	}

	tests := []struct {
		name     string
		override string
		resume   string
		want     string
		wantErr  string
	}{
		{name: "resume selects distinct clean source", override: sourceRoot, resume: "1", want: sourceRoot + "\n"},
		{name: "resume requires source", resume: "1", wantErr: "requires --release-source-root"},
		{name: "fresh refuses source override", override: sourceRoot, resume: "0", wantErr: "allowed only with --resume-existing-manager"},
		{name: "resume refuses tooling checkout as source", override: toolingRoot, resume: "1", wantErr: "must be separate checkouts"},
		{name: "relative source refused", override: "relative/source", resume: "1", wantErr: "existing absolute directory"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			command := exec.Command("bash", "-c", `
source "$1"
native_release_source_root "$2" "$3" "$4"
`, "bash", filepath.Join(repositoryRoot(t), "scripts", "native-release-remote.sh"), toolingRoot, tc.override, tc.resume)
			output, err := command.CombinedOutput()
			if tc.wantErr == "" {
				if err != nil || string(output) != tc.want {
					t.Fatalf("source selection: %v, output %q, want %q", err, output, tc.want)
				}
				selectedHead := gitOutput(t, tc.override, "rev-parse", "HEAD")
				if selectedHead != sourceHead || selectedHead == toolingHead {
					t.Fatalf("selected HEAD = %s, source = %s, tooling = %s", selectedHead, sourceHead, toolingHead)
				}
			} else if err == nil || !strings.Contains(string(output), tc.wantErr) {
				t.Fatalf("source selection output = %q, want failure containing %q", output, tc.wantErr)
			}
		})
	}

	t.Run("dirty source refused", func(t *testing.T) {
		if err := os.WriteFile(filepath.Join(sourceRoot, "dirty"), []byte("dirty"), 0o600); err != nil {
			t.Fatal(err)
		}
		command := exec.Command("bash", "-c", `source "$1"; native_release_source_root "$2" "$3" 1`, "bash",
			filepath.Join(repositoryRoot(t), "scripts", "native-release-remote.sh"), toolingRoot, sourceRoot)
		output, err := command.CombinedOutput()
		if err == nil || !strings.Contains(string(output), "must be clean") {
			t.Fatalf("dirty source output = %q, want clean-checkout refusal", output)
		}
	})
}

func TestReleaseUsesToolingVerifierAndSourceRevision(t *testing.T) {
	release := readRepositoryFile(t, "scripts/release.sh")
	required := []string{
		`COMMIT="$(git -C "$RELEASE_ROOT" rev-parse HEAD)"`,
		`python3 "$TOOL_ROOT/scripts/verify-manager-manifest.py" registry`,
		`"$RELEASE_ROOT/scripts/verify-native-release.sh"`,
		`gh release create "$TAG" --repo "$REPO" --target "$COMMIT"`,
		`DIST="$TEMP/dist"`,
	}
	for _, fragment := range required {
		if !strings.Contains(release, fragment) {
			t.Fatalf("release source/tooling boundary missing %q", fragment)
		}
	}
}

func committedCheckout(t *testing.T, content string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	for _, args := range [][]string{
		{"init", "-q"},
		{"config", "user.name", "Release Test"},
		{"config", "user.email", "release-test@example.invalid"},
	} {
		if output, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, output)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "source.txt"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"add", "source.txt"}, {"commit", "-qm", "fixture"}} {
		if output, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, output)
		}
	}
	return dir, gitOutput(t, dir, "rev-parse", "HEAD")
}

func gitOutput(t *testing.T, dir string, args ...string) string {
	t.Helper()
	output, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, output)
	}
	return strings.TrimSpace(string(output))
}

func fakeGitHubCLI(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "gh.log")
	script := `#!/bin/sh
printf '%s\n' "$*" >> "$GH_LOG"
case "$*" in
  *'/git/ref/tags/'*)
    if [ "$GH_SCENARIO" = git-tag ]; then printf '%s\n' '{}'; exit 0; fi
    case "$GH_SCENARIO" in
      pushed-annotated) printf '%s\n' 'tag 1111111111111111111111111111111111111111'; exit 0 ;;
      pushed-lightweight) printf '%s\n' 'commit 2222222222222222222222222222222222222222'; exit 0 ;;
      pushed-elsewhere) printf '%s\n' 'commit 3333333333333333333333333333333333333333'; exit 0 ;;
    esac
    printf '%s\n' 'gh: Not Found (HTTP 404)' >&2; exit 1 ;;
  *'/git/tags/1111111111111111111111111111111111111111'*)
    printf '%s\n' 'commit 2222222222222222222222222222222222222222'; exit 0 ;;
  *'/releases/tags/'*)
    if [ "$GH_SCENARIO" = release ]; then printf '%s\n' '{}'; exit 0; fi
    printf '%s\n' 'gh: Not Found (HTTP 404)' >&2; exit 1 ;;
  *'/versions?per_page=100'*)
	if [ "$GH_SCENARIO" = package-404-existing ] || [ "$GH_SCENARIO" = package-404-missing ] || [ "$GH_SCENARIO" = package-404-denied ]; then
	  printf '%s\n' 'gh: Not Found (HTTP 404)' >&2; exit 1
	fi
	if [ "$GH_SCENARIO" = package-403-missing ]; then
	  printf '%s\n' 'gh: Resource not accessible by integration (HTTP 403)' >&2; exit 1
	fi
    if [ "$GH_SCENARIO" = manager-present ]; then printf '%s\n' 'native-v0.3.4'; fi
    exit 0 ;;
  *'/user/packages/container/leash-manager --jq .visibility'*)
    case "$GH_SCENARIO" in
      public) printf '%s\n' public ;;
	  private) printf '%s\n' private ;;
	  visibility-fail|anonymous-public|anonymous-private) printf '%s\n' 'gh: Forbidden (HTTP 403)' >&2; exit 1 ;;
      *) printf '%s\n' private ;;
    esac
    exit 0 ;;
esac
printf '%s\n' "unexpected gh invocation: $*" >&2
exit 2
`
	path := filepath.Join(dir, "gh")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(logPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	docker := `#!/bin/sh
case "$GH_SCENARIO" in
  package-404-existing|digest-match)
    printf '%s\n' '{"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}' ;;
  digest-drift)
    printf '%s\n' '{"digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}' ;;
  package-404-missing|package-403-missing)
    printf '%s\n' 'manifest unknown' >&2; exit 1 ;;
  anonymous-public)
    [ -n "$DOCKER_CONFIG" ] || { printf '%s\n' 'anonymous probe must not use stored credentials' >&2; exit 2; }
    printf '%s\n' '{"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}' ;;
  anonymous-private)
    printf '%s\n' 'ERROR: unexpected status from HEAD request: 401 Unauthorized' >&2; exit 1 ;;
  package-404-denied)
    printf '%s\n' 'denied: permission_denied' >&2; exit 1 ;;
  *)
    printf '%s\n' 'unexpected docker invocation' >&2; exit 2 ;;
esac
`
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(docker), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir, logPath
}

func TestNativeReleasePushedTag(t *testing.T) {
	commit := "2222222222222222222222222222222222222222"
	for _, tc := range []struct {
		name     string
		scenario string
		wantErr  string
	}{
		{name: "annotated tag at release commit", scenario: "pushed-annotated"},
		{name: "lightweight tag at release commit", scenario: "pushed-lightweight"},
		{name: "tag at another commit", scenario: "pushed-elsewhere", wantErr: "not release commit " + commit},
		{name: "missing tag", scenario: "fresh", wantErr: "requires existing Git tag"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fakeBin, _ := fakeGitHubCLI(t)
			command := exec.Command("bash", "-c", `
source "$1"
NATIVE_PUSHED_TAG_COMMIT="$3"
native_require_release_names_absent "$2" sixtoad/leash native-v0.3.4
`, "bash", filepath.Join(repositoryRoot(t), "scripts", "native-release-remote.sh"), t.TempDir(), commit)
			command.Env = append(os.Environ(), "PATH="+fakeBin+":"+os.Getenv("PATH"),
				"GH_SCENARIO="+tc.scenario, "GH_LOG="+filepath.Join(t.TempDir(), "gh.log"))
			output, err := command.CombinedOutput()
			if tc.wantErr == "" && err != nil {
				t.Fatalf("pushed tag: %v\n%s", err, output)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(string(output), tc.wantErr)) {
				t.Fatalf("pushed tag output = %q, want failure containing %q", output, tc.wantErr)
			}
		})
	}
}

func TestReleaseGateSSHSpec(t *testing.T) {
	for _, tc := range []struct {
		spec, want, wantErr string
	}{
		{spec: "ubuntu@127.0.0.1:2222", want: "ubuntu@127.0.0.1 2222"},
		{spec: "leash-release-gate", want: "leash-release-gate "},
		{spec: "ubuntu@host;rm -rf /", wantErr: "must be [user@]host[:port]"},
		{spec: "-oProxyCommand", wantErr: "must be [user@]host[:port]"},
	} {
		t.Run(tc.spec, func(t *testing.T) {
			command := exec.Command("bash", "-c", `
source "$1"
release_gate_configure "$2" || exit 1
printf '%s %s' "$RELEASE_GATE_DEST" "$RELEASE_GATE_PORT"
`, "bash", filepath.Join(repositoryRoot(t), "scripts", "release-gate-remote.sh"), tc.spec)
			output, err := command.CombinedOutput()
			if tc.wantErr == "" {
				if err != nil || string(output) != tc.want {
					t.Fatalf("gate spec: %v, output %q, want %q", err, output, tc.want)
				}
				return
			}
			if err == nil || !strings.Contains(string(output), tc.wantErr) {
				t.Fatalf("gate spec output = %q, want failure containing %q", output, tc.wantErr)
			}
		})
	}
}

// The remote kernel gates must run the same scripts with no inert escape and
// re-check every copied artifact; local gates stay the default.
func TestReleaseRemoteGatePreservesGates(t *testing.T) {
	release := readRepositoryFile(t, "scripts/release.sh")
	for _, required := range []string{
		`RELEASE_GATE_SSH="${LEASH_RELEASE_GATE_SSH:-}"`,
		`timeout 10m env -u LEASH_KERNEL_LOAD_ALLOW_INERT "$RELEASE_ROOT/scripts/verify-lsm-kernel-load.sh"`,
		`release_gate_kernel_load "$RELEASE_ROOT/scripts/verify-lsm-kernel-load.sh" "$TEMP" "${LSM_OBJECTS[@]}"`,
		`"$RELEASE_ROOT/scripts/verify-native-release.sh" "$TEMP/leash" "$MANAGER_REF" "$COMMIT"`,
		`release_gate_native_release "$TEMP/leash" "$MANAGER_REF" "$COMMIT"`,
	} {
		if !strings.Contains(release, required) {
			t.Errorf("release.sh missing %q", required)
		}
	}
	gate := readRepositoryFile(t, "scripts/release-gate-remote.sh")
	for _, required := range []string{
		"env -u LEASH_KERNEL_LOAD_ALLOW_INERT",
		"scripts/verify-lsm-kernel-load.sh --test-binary",
		"scripts/verify-native-release.sh",
		"sha256sum -c --quiet -",
		"obj not in binary",
		`archive --format=tar "$commit"`,
		"*,bpf,*",
	} {
		if !strings.Contains(gate, required) {
			t.Errorf("release-gate-remote.sh missing %q", required)
		}
	}
	vm := readRepositoryFile(t, "scripts/release-gate-vm.sh")
	for _, forbidden := range []string{"LEASH_KERNEL_LOAD_ALLOW_INERT=1", "StrictHostKeyChecking=no", "StrictHostKeyChecking no"} {
		if strings.Contains(gate, forbidden) || strings.Contains(vm, forbidden) {
			t.Errorf("remote gate must not contain %q", forbidden)
		}
	}
}
