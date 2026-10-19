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

	"github.com/strongdm/leash/internal/configstore"
	"github.com/strongdm/leash/internal/leashd/listen"
)

func TestParseSELinuxMode(t *testing.T) {
	for in, want := range map[string]string{"": "auto", "auto": "auto", " Relabel ": "relabel", "DISABLE": "disable"} {
		got, err := parseSELinuxMode(in)
		if err != nil || got != want {
			t.Fatalf("parseSELinuxMode(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := parseSELinuxMode("Z"); err == nil {
		t.Fatal("parseSELinuxMode accepted an unknown mode")
	}
}

// stubSELinux makes the host look SELinux-enforcing with the given labels and
// records docker invocations made through runCommand/commandOutput.
func stubSELinux(t *testing.T, enforcing bool, labels map[string]string, dockerSecurityOptions string) *[][]string {
	t.Helper()
	mountStateTestMu.Lock()
	t.Cleanup(mountStateTestMu.Unlock)
	origEnforcing, origType := selinuxEnforcing, selinuxFileType
	origRun, origOutput := runCommand, commandOutput
	selinuxEnforcing = func() bool { return enforcing }
	selinuxFileType = func(path string) (string, error) {
		if typ, ok := labels[filepath.Clean(path)]; ok {
			return typ, nil
		}
		return "", fmt.Errorf("no label for %s", path)
	}
	var (
		mu   sync.Mutex
		runs [][]string
	)
	runCommand = func(_ context.Context, _, _ io.Writer, name string, args ...string) error {
		mu.Lock()
		defer mu.Unlock()
		runs = append(runs, append([]string{name}, args...))
		return nil
	}
	commandOutput = func(_ context.Context, name string, args ...string) (string, error) {
		switch {
		case len(args) >= 1 && args[0] == "inspect":
			return "amd64\n", nil
		case len(args) >= 1 && args[0] == "info":
			return dockerSecurityOptions, nil
		case len(args) >= 1 && args[0] == "run":
			mu.Lock()
			defer mu.Unlock()
			runs = append(runs, append([]string{name}, args...))
			return "cid\n", nil
		default:
			return "", fmt.Errorf("unexpected commandOutput call: %s %s", name, strings.Join(args, " "))
		}
	}
	t.Cleanup(func() {
		selinuxEnforcing, selinuxFileType = origEnforcing, origType
		runCommand, commandOutput = origRun, origOutput
	})
	return &runs
}

func selinuxTestRunner(t *testing.T, mode string) (*runner, string, string) {
	t.Helper()
	workDir := t.TempDir()
	shareDir := filepath.Join(workDir, "share")
	if err := os.MkdirAll(shareDir, 0o755); err != nil {
		t.Fatal(err)
	}
	callerDir := t.TempDir()
	autoHost := filepath.Join(t.TempDir(), ".claude")
	if err := os.Mkdir(autoHost, 0o755); err != nil {
		t.Fatal(err)
	}
	r := &runner{
		logger: log.New(ioDiscard{}, "", 0),
		cfg: config{
			hostOS:           "linux",
			workDir:          workDir,
			shareDir:         shareDir,
			callerDir:        callerDir,
			targetImage:      "example/target:latest",
			targetContainer:  "leash-target-123",
			proxyPort:        "18000",
			bootstrapTimeout: 30 * time.Second,
			listenCfg:        listen.Default(),
			selinuxMode:      mode,
		},
		opts: options{command: []string{"bash"}},
		mountState: &mountState{
			command: "claude",
			mounts:  []configstore.Mount{{Host: autoHost, Container: "/root/.claude", Mode: "rw", Scope: configstore.ScopeGlobal}},
		},
	}
	r.selinuxChecked = true
	r.selinuxRelabel = true
	return r, callerDir, autoHost
}

func TestSELinuxAutoRefusesUnlabelledWorkspace(t *testing.T) {
	r, callerDir, autoHost := selinuxTestRunner(t, selinuxModeAuto)
	runs := stubSELinux(t, true, map[string]string{
		filepath.Clean(r.cfg.callerDir): "user_home_t",
		filepath.Clean(autoHost):        "container_file_t",
	}, `["name=seccomp,profile=builtin","name=selinux"]`)

	err := r.launchTargetContainer(context.Background(), "SIGTERM")
	if err == nil {
		t.Fatal("launch succeeded with a user_home_t project on an enforcing host")
	}
	for _, want := range []string{callerDir + " (user_home_t)", "--selinux relabel", "--selinux disable", "chcon -R -t container_file_t"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("refusal missing %q:\n%v", want, err)
		}
	}
	if strings.Contains(err.Error(), autoHost) {
		t.Fatalf("refusal names an already container-readable path:\n%v", err)
	}
	if len(*runs) != 0 {
		t.Fatalf("a container was started before the refusal: %v", *runs)
	}
}

func TestSELinuxAutoRunsUnchangedWhenLabelled(t *testing.T) {
	r, callerDir, autoHost := selinuxTestRunner(t, selinuxModeAuto)
	runs := stubSELinux(t, true, map[string]string{
		filepath.Clean(callerDir): "container_file_t",
		filepath.Clean(autoHost):  "container_ro_file_t",
	}, `["name=selinux"]`)
	if err := r.launchTargetContainer(context.Background(), "SIGTERM"); err != nil {
		t.Fatal(err)
	}
	args := (*runs)[0]
	if !containsArg(args, callerDir+":"+callerDir) || !containsArg(args, autoHost+":/root/.claude:rw") {
		t.Fatalf("user mounts changed although already labelled: %v", args)
	}
	if containsArg(args, "label=disable") {
		t.Fatalf("label=disable chosen silently: %v", args)
	}
}

func TestSELinuxAutoSkipsEngineWithoutLabels(t *testing.T) {
	r, callerDir, _ := selinuxTestRunner(t, selinuxModeAuto)
	runs := stubSELinux(t, true, map[string]string{filepath.Clean(callerDir): "user_home_t"}, `["name=seccomp,profile=builtin"]`)
	if err := r.launchTargetContainer(context.Background(), "SIGTERM"); err != nil {
		t.Fatalf("docker without selinux-enabled does not confine containers, launch should proceed: %v", err)
	}
	if len(*runs) != 1 {
		t.Fatalf("expected one docker run, got %v", *runs)
	}
}

func TestSELinuxNotEnforcingIsNoop(t *testing.T) {
	r, callerDir, _ := selinuxTestRunner(t, selinuxModeDisable)
	runs := stubSELinux(t, false, nil, "")
	if err := r.launchTargetContainer(context.Background(), "SIGTERM"); err != nil {
		t.Fatal(err)
	}
	args := (*runs)[0]
	if containsArg(args, "label=disable") || !containsArg(args, callerDir+":"+callerDir) {
		t.Fatalf("SELinux options applied on a host that is not enforcing: %v", args)
	}
}

func TestSELinuxRelabelAddsSharedLabelToUserMounts(t *testing.T) {
	r, callerDir, autoHost := selinuxTestRunner(t, selinuxModeRelabel)
	runs := stubSELinux(t, true, nil, "")
	if err := r.launchTargetContainer(context.Background(), "SIGTERM"); err != nil {
		t.Fatal(err)
	}
	args := (*runs)[0]
	if !containsArg(args, callerDir+":"+callerDir+":z") {
		t.Fatalf("project mount not relabelled with :z: %v", args)
	}
	if !containsArg(args, autoHost+":/root/.claude:rw,z") {
		t.Fatalf("config mount not relabelled with :z: %v", args)
	}
	for _, a := range args {
		if strings.HasSuffix(a, ":Z") || strings.HasSuffix(a, ",Z") {
			t.Fatalf("private :Z relabel used on a user mount: %v", args)
		}
	}
	if containsArg(args, "label=disable") {
		t.Fatalf("relabel mode also disabled labels: %v", args)
	}
}

func TestSELinuxRelabelRefusesHomeAndSystemDirs(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	for _, dir := range []string{home, "/", "/home", "/usr"} {
		if refuseRelabel(dir) == "" {
			t.Fatalf("refuseRelabel(%q) allowed a recursive relabel", dir)
		}
	}
	if reason := refuseRelabel(filepath.Join(home, "src", "project")); reason != "" {
		t.Fatalf("refuseRelabel refused a project dir: %s", reason)
	}
}

func TestSELinuxDisableUsesLabelDisableOnTargetOnly(t *testing.T) {
	r, callerDir, autoHost := selinuxTestRunner(t, selinuxModeDisable)
	runs := stubSELinux(t, true, map[string]string{filepath.Clean(callerDir): "user_home_t"}, `["name=selinux"]`)
	if err := r.launchTargetContainer(context.Background(), "SIGTERM"); err != nil {
		t.Fatal(err)
	}
	args := (*runs)[0]
	idx := -1
	for i := range args {
		if args[i] == "--security-opt" && i+1 < len(args) && args[i+1] == "label=disable" {
			idx = i
		}
	}
	if idx < 0 {
		t.Fatalf("target container missing --security-opt label=disable: %v", args)
	}
	if !containsArg(args, callerDir+":"+callerDir) || !containsArg(args, autoHost+":/root/.claude:rw") {
		t.Fatalf("disable mode relabelled user mounts: %v", args)
	}
}
