package releasecontract

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

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
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fakeBin, logPath := fakeGitHubCLI(t)
			temp := t.TempDir()
			command := exec.Command("bash", "-c", `
source "$1"
native_require_manager_public "$2" sixtoad leash-manager native-v0.3.4
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
			if tc.scenario == "private" && !strings.Contains(string(output), "scripts/release.sh --resume-existing-manager native-v0.3.4") {
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

func fakeGitHubCLI(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "gh.log")
	script := `#!/bin/sh
printf '%s\n' "$*" >> "$GH_LOG"
case "$*" in
  *'/git/ref/tags/'*)
    if [ "$GH_SCENARIO" = git-tag ]; then printf '%s\n' '{}'; exit 0; fi
    printf '%s\n' 'gh: Not Found (HTTP 404)' >&2; exit 1 ;;
  *'/releases/tags/'*)
    if [ "$GH_SCENARIO" = release ]; then printf '%s\n' '{}'; exit 0; fi
    printf '%s\n' 'gh: Not Found (HTTP 404)' >&2; exit 1 ;;
  *'/versions?per_page=100'*)
	if [ "$GH_SCENARIO" = package-404-existing ] || [ "$GH_SCENARIO" = package-404-missing ] || [ "$GH_SCENARIO" = package-404-denied ]; then
	  printf '%s\n' 'gh: Not Found (HTTP 404)' >&2; exit 1
	fi
    if [ "$GH_SCENARIO" = manager-present ]; then printf '%s\n' 'native-v0.3.4'; fi
    exit 0 ;;
  *'/user/packages/container/leash-manager --jq .visibility'*)
    case "$GH_SCENARIO" in
      public) printf '%s\n' public ;;
	  private) printf '%s\n' private ;;
	  visibility-fail) printf '%s\n' 'gh: Forbidden (HTTP 403)' >&2; exit 1 ;;
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
  package-404-missing)
    printf '%s\n' 'manifest unknown' >&2; exit 1 ;;
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
