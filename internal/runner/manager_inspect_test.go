package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/strongdm/leash/internal/managercontract"
)

// inspectFakeRuntime models an engine's local image store.
type inspectFakeRuntime struct {
	images   map[string]string // ref -> facts JSON line
	pullable map[string]string // ref -> facts after a pull
	warning  string            // stderr noise mixed into Output
	calls    [][]string
}

func (f *inspectFakeRuntime) Run(_ context.Context, args ...string) error {
	f.calls = append(f.calls, append([]string(nil), args...))
	if len(args) == 2 && args[0] == "pull" {
		facts, ok := f.pullable[args[1]]
		if !ok {
			return errors.New("docker pull: exit status 1: manifest unknown")
		}
		f.images[args[1]] = facts
	}
	return nil
}

func (f *inspectFakeRuntime) Output(_ context.Context, args ...string) (string, error) {
	f.calls = append(f.calls, append([]string(nil), args...))
	if len(args) < 3 || args[0] != "image" || args[1] != "inspect" {
		return "", fmt.Errorf("unexpected %v", args)
	}
	ref := args[len(args)-1]
	facts, ok := f.images[ref]
	if !ok {
		return "", fmt.Errorf("docker image inspect: exit status 1: Error: No such image: %s", ref)
	}
	if args[2] == "--format" {
		return f.warning + facts + "\n", nil
	}
	return "[{}]", nil
}

func (f *inspectFakeRuntime) ExecWithInput(context.Context, string, string, io.Reader) error {
	return nil
}

func (f *inspectFakeRuntime) Cmd(ctx context.Context, _ ...string) *exec.Cmd {
	return exec.CommandContext(ctx, "true")
}

func (f *inspectFakeRuntime) Name() string { return "docker" }

func factsJSON(t *testing.T, labels map[string]string, repoDigests ...string) string {
	t.Helper()
	if repoDigests == nil {
		repoDigests = []string{}
	}
	image := engineImage{ID: "sha256:imageid", RepoDigests: repoDigests}
	image.Config.Labels = labels
	out, err := json.Marshal(image)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func fullLabels(revision string) map[string]string {
	return map[string]string{
		managercontract.LabelVersion:                  "native-v0.4.0",
		managercontract.LabelRevision:                 revision,
		managercontract.LabelContractVersion:          "1",
		managercontract.LabelMinCompatibleContract:    "1",
		managercontract.LabelCLIContractVersion:       "3",
		managercontract.LabelCLIMinCompatibleContract: "0",
		managercontract.LabelCapabilities:             "policy,runtime,manager-inspect",
	}
}

func inspectDeps(t *testing.T, rt Runtime, dir string) (managerInspectDeps, *bytes.Buffer) {
	t.Helper()
	var diag bytes.Buffer
	return managerInspectDeps{
		callerDir:   func() (string, error) { return dir, nil },
		newRuntime:  func(string) (Runtime, error) { return rt, nil },
		lookPath:    func(name string) (string, error) { return "/usr/bin/" + name, nil },
		getenv:      func(string) string { return "" },
		diagnostics: &diag,
	}, &diag
}

func withManagerRelease(t *testing.T, image, revision string) {
	t.Helper()
	oldImage, oldRevision := defaultLeashImage, expectedManagerRevision
	defaultLeashImage, expectedManagerRevision = image, revision
	t.Cleanup(func() { defaultLeashImage, expectedManagerRevision = oldImage, oldRevision })
}

func runInspect(t *testing.T, deps managerInspectDeps, args ...string) (int, ManagerInspectDocument, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := managerMain(append([]string{"inspect"}, args...), &stdout, &stderr, deps)
	var doc ManagerInspectDocument
	if code == ManagerExitSuccess {
		dec := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&doc); err != nil {
			t.Fatalf("stdout is not a pure document: %v\n%s", err, stdout.String())
		}
		if dec.More() {
			t.Fatalf("stdout carries more than one value: %q", stdout.String())
		}
	}
	return code, doc, stdout.String(), stderr.String()
}

func TestManagerInspectDefaultImageCompatible(t *testing.T) {
	t.Setenv("LEASH_IMAGE", "")
	const ref = "ghcr.io/sixtoad/leash-manager@sha256:abc"
	withManagerRelease(t, ref, "rev1")
	rt := &inspectFakeRuntime{images: map[string]string{
		ref: factsJSON(t, fullLabels("rev1"), "ghcr.io/sixtoad/leash-manager@sha256:abc"),
	}, warning: "WARNING: some engine noise\n"}
	deps, _ := inspectDeps(t, rt, t.TempDir())

	code, doc, _, stderr := runInspect(t, deps, "--json")
	if code != ManagerExitSuccess {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
	if doc.Ref != ref || doc.Source != imageSourceDefault || doc.Digest != "sha256:abc" || doc.ImageID != "sha256:imageid" {
		t.Fatalf("identity = %+v", doc)
	}
	if doc.Version != "native-v0.4.0" || doc.Revision != "rev1" {
		t.Fatalf("version/revision = %q %q", doc.Version, doc.Revision)
	}
	if doc.ManagerContract == nil || doc.ManagerContract.Version != 1 || doc.ManagerContract.MinCompatible != 1 {
		t.Fatalf("manager contract = %+v", doc.ManagerContract)
	}
	if doc.ContractVersion == nil || *doc.ContractVersion != 3 || doc.MinCompatibleContract == nil || *doc.MinCompatibleContract != 0 {
		t.Fatalf("cli contract = %v %v", doc.ContractVersion, doc.MinCompatibleContract)
	}
	if strings.Join(doc.Capabilities, ",") != "policy,runtime,manager-inspect" || !doc.CapabilitiesLabeled {
		t.Fatalf("capabilities = %v labeled=%t", doc.Capabilities, doc.CapabilitiesLabeled)
	}
	if !doc.CompatibleWithThisCLI || !strings.Contains(doc.Reason, "revision matches") {
		t.Fatalf("verdict = %t %q", doc.CompatibleWithThisCLI, doc.Reason)
	}
	for _, call := range rt.calls {
		if call[0] == "pull" || call[0] == "run" {
			t.Fatalf("local image must not be pulled or started: %v", call)
		}
	}
}

func TestManagerInspectDefaultRevisionMismatchIsReportedNotFatal(t *testing.T) {
	t.Setenv("LEASH_IMAGE", "")
	withManagerRelease(t, "mgr:default", "new")
	rt := &inspectFakeRuntime{images: map[string]string{"mgr:default": factsJSON(t, fullLabels("old"))}}
	deps, _ := inspectDeps(t, rt, t.TempDir())
	code, doc, _, _ := runInspect(t, deps, "--json")
	if code != ManagerExitSuccess || doc.CompatibleWithThisCLI || !strings.Contains(doc.Reason, "revision mismatch") {
		t.Fatalf("code=%d doc=%+v", code, doc)
	}
}

func TestManagerInspectPrecedenceMatchesRun(t *testing.T) {
	withManagerRelease(t, "mgr:default", "")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, devDockerLeashFile), []byte("sha256:devimage\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	labels := fullLabels("custom")
	rt := &inspectFakeRuntime{images: map[string]string{
		"sha256:devimage": factsJSON(t, labels),
		"env/img:1":       factsJSON(t, labels),
		"flag/img:1":      factsJSON(t, labels),
	}}
	deps, _ := inspectDeps(t, rt, dir)

	t.Setenv("LEASH_IMAGE", "")
	if _, doc, _, _ := runInspect(t, deps, "--json"); doc.Ref != "sha256:devimage" || doc.Source != imageSourceDevFile {
		t.Fatalf("dev file: %+v", doc)
	}
	t.Setenv("LEASH_IMAGE", "env/img:1")
	if _, doc, _, _ := runInspect(t, deps, "--json"); doc.Ref != "env/img:1" || doc.Source != imageSourceEnv {
		t.Fatalf("env: %+v", doc)
	}
	if _, doc, _, _ := runInspect(t, deps, "--image", "flag/img:1", "--json"); doc.Ref != "flag/img:1" || doc.Source != imageSourceFlag {
		t.Fatalf("flag: %+v", doc)
	}
	if _, doc, _, _ := runInspect(t, deps, "--leash-image", "flag/img:1", "--json"); doc.Ref != "flag/img:1" || doc.Source != imageSourceFlag {
		t.Fatalf("leash-image alias: %+v", doc)
	}

	// The run resolves the same image for the same inputs.
	image, source, _, err := resolveManagerImage(dir, "")
	if err != nil || image != "env/img:1" || source != imageSourceEnv {
		t.Fatalf("resolveManagerImage = %q %q %v", image, source, err)
	}
}

func TestManagerInspectPullsOnlyWhenMissingAndAllowed(t *testing.T) {
	t.Setenv("LEASH_IMAGE", "")
	withManagerRelease(t, "mgr:remote", "")
	rt := &inspectFakeRuntime{
		images:   map[string]string{},
		pullable: map[string]string{"mgr:remote": factsJSON(t, fullLabels("r"), "mgr@sha256:def")},
	}
	deps, _ := inspectDeps(t, rt, t.TempDir())

	code, _, stdout, stderr := runInspect(t, deps, "--pull", "never", "--json")
	if code != ManagerExitUnresolved || stdout != "" || !strings.Contains(stderr, "--pull never") {
		t.Fatalf("never: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, doc, _, stderr := runInspect(t, deps, "--json")
	if code != ManagerExitSuccess || doc.Digest != "sha256:def" {
		t.Fatalf("missing: code=%d doc=%+v stderr=%s", code, doc, stderr)
	}
}

func TestManagerInspectUnresolvableImageExitsNonZeroWithEmptyStdout(t *testing.T) {
	t.Setenv("LEASH_IMAGE", "")
	withManagerRelease(t, "mgr:gone", "")
	rt := &inspectFakeRuntime{images: map[string]string{}, pullable: map[string]string{}}
	deps, _ := inspectDeps(t, rt, t.TempDir())
	code, _, stdout, stderr := runInspect(t, deps, "--json")
	if code != ManagerExitUnresolved || stdout != "" || !strings.Contains(stderr, "mgr:gone") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestManagerInspectUnlabeledImage(t *testing.T) {
	t.Setenv("LEASH_IMAGE", "")
	withManagerRelease(t, "old:image", "")
	rt := &inspectFakeRuntime{images: map[string]string{"old:image": `{"Id":"sha256:x","RepoDigests":null,"Config":{"Labels":null}}`}}
	deps, _ := inspectDeps(t, rt, t.TempDir())
	code, doc, stdout, _ := runInspect(t, deps, "--json")
	if code != ManagerExitSuccess || doc.CompatibleWithThisCLI || doc.ManagerContract != nil ||
		doc.ContractVersion != nil || doc.CapabilitiesLabeled || len(doc.Capabilities) != 0 {
		t.Fatalf("doc=%+v", doc)
	}
	for _, want := range []string{`"managerContract": null`, `"contractVersion": null`, `"capabilities": []`, `"repoDigests": []`} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("stdout missing %s:\n%s", want, stdout)
		}
	}
}

func TestManagerInspectUsage(t *testing.T) {
	deps, _ := inspectDeps(t, &inspectFakeRuntime{}, t.TempDir())
	for _, args := range [][]string{
		{},              // --json required
		{"--json", "x"}, // stray argument
		{"--json", "--pull", "always"},
		{"--json", "--runtime", "native"},
		{"--json", "--runtime", "lxc"},
		{"--json", "--image", "a", "--leash-image", "b"},
	} {
		code, _, stdout, _ := runInspect(t, deps, args...)
		if code != ManagerExitUsage || stdout != "" {
			t.Fatalf("%v: code=%d stdout=%q", args, code, stdout)
		}
	}
	var stdout, stderr bytes.Buffer
	if code := managerMain(nil, &stdout, &stderr, deps); code != ManagerExitUsage || stdout.Len() != 0 {
		t.Fatalf("bare manager: code=%d", code)
	}
}

func TestSelectManagerEngine(t *testing.T) {
	onPath := map[string]bool{}
	deps := managerInspectDeps{
		getenv: func(string) string { return "" },
		lookPath: func(name string) (string, error) {
			if onPath[name] {
				return "/bin/" + name, nil
			}
			return "", errors.New("not found")
		},
	}
	onPath["podman"] = true
	if got, err := selectManagerEngine("", deps); err != nil || got != "podman" {
		t.Fatalf("detect = %q %v", got, err)
	}
	onPath["docker"] = true
	if got, _ := selectManagerEngine("", deps); got != "docker" {
		t.Fatalf("docker first = %q", got)
	}
	deps.getenv = func(string) string { return "podman" }
	if got, _ := selectManagerEngine("", deps); got != "podman" {
		t.Fatalf("LEASH_RUNTIME = %q", got)
	}
	if got, _ := selectManagerEngine("docker", deps); got != "docker" {
		t.Fatalf("flag wins = %q", got)
	}
	deps.getenv = func(string) string { return "native" }
	if got, _ := selectManagerEngine("", deps); got != "docker" {
		t.Fatalf("LEASH_RUNTIME=native falls back to detection, got %q", got)
	}
}

func TestManifestDigest(t *testing.T) {
	for _, tt := range []struct {
		ref     string
		digests []string
		want    string
	}{
		{"ghcr.io/o/m@sha256:aa", nil, "sha256:aa"},
		{"ghcr.io/o/m:tag", []string{"other/x@sha256:bb", "ghcr.io/o/m@sha256:cc"}, "sha256:cc"},
		{"localhost:5000/m:tag", []string{"localhost:5000/m@sha256:dd"}, "sha256:dd"},
		{"alpine:3", []string{"docker.io/library/alpine@sha256:ee"}, "sha256:ee"},
		{"local:dev", []string{}, ""},
	} {
		if got := manifestDigest(tt.ref, tt.digests); got != tt.want {
			t.Errorf("manifestDigest(%q) = %q, want %q", tt.ref, got, tt.want)
		}
	}
}

// TestManagerInspectRealEngineOutputStaysOffStdout drives a fake engine binary
// that prints pull progress on its stdout, the way docker does, and checks the
// command's stdout is still exactly one document.
func TestManagerInspectRealEngineOutputStaysOffStdout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fake")
	}
	bin := t.TempDir()
	state := filepath.Join(bin, "pulled")
	labels := factsJSON(t, fullLabels("r"), "mgr@sha256:ff")
	script := fmt.Sprintf(`#!/bin/sh
if [ "$1" = pull ]; then echo "Pulling from mgr"; echo "Status: Downloaded"; : > %q; exit 0; fi
if [ "$1" = image ] && [ "$2" = inspect ]; then
  if [ ! -f %q ]; then echo "Error: No such image: $3" >&2; exit 1; fi
  if [ "$3" = --format ]; then printf '%%s\n' '%s'; else echo '[{}]'; fi
  exit 0
fi
exit 3
`, state, state, labels)
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	t.Setenv("LEASH_IMAGE", "")
	t.Setenv("LEASH_RUNTIME", "")
	withManagerRelease(t, "mgr:tag", "")

	var stdout, stderr bytes.Buffer
	deps := defaultManagerInspectDeps(&stderr)
	deps.callerDir = func() (string, error) { return t.TempDir(), nil }
	code := managerMain([]string{"inspect", "--json"}, &stdout, &stderr, deps)
	if code != ManagerExitSuccess {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	var doc ManagerInspectDocument
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("stdout not pure JSON: %v\n%s", err, stdout.String())
	}
	if !strings.Contains(stderr.String(), "Pulling from mgr") {
		t.Fatalf("pull progress should be on stderr: %q", stderr.String())
	}
	if doc.Digest != "sha256:ff" || doc.Runtime != "docker" {
		t.Fatalf("doc = %+v", doc)
	}
}
