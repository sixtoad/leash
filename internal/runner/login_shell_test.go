package runner

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

// The governed command runs under a non-login shell by default, so /etc/profile
// cannot reset the image's ENV PATH (e.g. /usr/local/go/bin in golang images)
// and no ~/.profile read is attempted (#120). A login shell is opt-in.
func TestWorkloadShellFlagDefaultsToNonLogin(t *testing.T) {
	r := &runner{}
	if got := r.workloadShellFlag(); got != "-c" {
		t.Fatalf("default workloadShellFlag = %q, want -c", got)
	}
	r.cfg.loginShell = true
	if got := r.workloadShellFlag(); got != "-lc" {
		t.Fatalf("login-shell workloadShellFlag = %q, want -lc", got)
	}
}

func TestContainerExecCommandLoginShellOptIn(t *testing.T) {
	rt := &identityRecordingRuntime{}
	r := &runner{
		runtime:             rt,
		cfg:                 config{callerDir: "/workspace", targetContainer: "target", loginShell: true},
		targetContainerUser: "agent",
	}
	l := containerLauncher{r: r}
	_ = l.ExecCommand(context.Background(), "bash", "go version", true)
	want := []string{"exec", "-it", "--user", "agent", "-w", "/workspace", "target", "bash", "-lc", "exec go version"}
	if !reflect.DeepEqual(rt.commands[0], want) {
		t.Fatalf("login-shell argv = %v, want %v", rt.commands[0], want)
	}
	if got := r.manualAttachCommand("bash", "id"); !strings.HasSuffix(got, "target bash -lc 'exec id'") {
		t.Fatalf("manual attach under --login-shell = %q", got)
	}
}

func TestNativeWorkloadScriptShellFlag(t *testing.T) {
	cg := "/sys/fs/cgroup/system.slice/leash-native-x.service"
	nonLogin := nativeWorkloadScript(cg, "/wd", "bash", "-c", "claude", "alice", "", "", hardenOpts{})
	if !strings.Contains(nonLogin, "bash -c 'exec claude'") || strings.Contains(nonLogin, "-lc") {
		t.Fatalf("default native script should use a non-login shell: %s", nonLogin)
	}
	login := nativeWorkloadScript(cg, "/wd", "bash", "-lc", "claude", "alice", "", "", hardenOpts{})
	if !strings.Contains(login, "bash -lc 'exec claude'") {
		t.Fatalf("--login-shell native script should use -lc: %s", login)
	}
	// An unset flag falls back to the non-login default rather than emitting
	// `bash  'exec ...'` (which would run the command string as a script path).
	empty := nativeWorkloadScript(cg, "/wd", "bash", "", "claude", "", "", "", hardenOpts{})
	if !strings.Contains(empty, "bash -c 'exec claude'") {
		t.Fatalf("empty shell flag should default to -c: %s", empty)
	}
}

func TestParseArgsLoginShell(t *testing.T) {
	opts, err := parseArgs([]string{"--login-shell", "--", "go", "version"})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if !opts.loginShell {
		t.Fatal("--login-shell should set loginShell")
	}
	off, err := parseArgs([]string{"--", "go", "version"})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if off.loginShell {
		t.Fatal("loginShell must default to false")
	}
}

func TestLoadConfigLoginShell(t *testing.T) {
	clearNetworkEnv(t)
	clearEnv(t, "LEASH_LOGIN_SHELL")
	cfg, _, err := loadConfig(t.TempDir(), options{})
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.loginShell {
		t.Fatal("loginShell must default to false")
	}

	cfg, _, err = loadConfig(t.TempDir(), options{loginShell: true})
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if !cfg.loginShell {
		t.Fatal("--login-shell should enable loginShell")
	}

	setEnv(t, "LEASH_LOGIN_SHELL", "1")
	cfg, _, err = loadConfig(t.TempDir(), options{})
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if !cfg.loginShell {
		t.Fatal("LEASH_LOGIN_SHELL=1 should enable loginShell")
	}
}
