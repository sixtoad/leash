package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/strongdm/leash/internal/configstore"
	"github.com/strongdm/leash/internal/leashd/listen"
)

func TestParseResourceValues(t *testing.T) {
	good := []struct {
		fn    func(string) (string, int64, error)
		in    string
		norm  string
		value int64
	}{
		{parseCPUs, "2", "2", 2_000_000_000},
		{parseCPUs, " 1.5 ", "1.5", 1_500_000_000},
		{parseCPUs, "0.25", "0.25", 250_000_000},
		{parseMemory, "512m", "512m", 512 << 20},
		{parseMemory, "2G", "2g", 2 << 30},
		{parseMemory, "6291456", "6291456", 6 << 20},
		{parseMemory, "8192k", "8192k", 8 << 20},
		{parsePidsLimit, "256", "256", 256},
		{parsePidsLimit, "0010", "10", 10},
	}
	for _, tc := range good {
		norm, v, err := tc.fn(tc.in)
		if err != nil || norm != tc.norm || v != tc.value {
			t.Errorf("parse(%q) = %q, %d, %v; want %q, %d", tc.in, norm, v, err, tc.norm, tc.value)
		}
	}
	bad := map[string]func(string) (string, int64, error){
		"0": parseCPUs, "-1": parseCPUs, "1e3": parseCPUs, "two": parseCPUs, "1.": parseCPUs, "5000": parseCPUs, "": parseCPUs,
		"1m": parseMemory, "5m": parseMemory, "2gb": parseMemory, "-1g": parseMemory, "1.5g": parseMemory, "1t": parseMemory,
		"99999999999999999999g": parseMemory, "4g; rm -rf /": parseMemory,
	}
	for in, fn := range bad {
		if _, _, err := fn(in); err == nil {
			t.Errorf("value %q should be rejected", in)
		}
	}
	for _, in := range []string{"0", "-1", "1.5", "abc", "99999999", "--privileged"} {
		if _, _, err := parsePidsLimit(in); err == nil {
			t.Errorf("pids limit %q should be rejected", in)
		}
	}
}

func clearResourceEnv(t *testing.T) {
	t.Helper()
	clearEnv(t, "LEASH_CPUS")
	clearEnv(t, "LEASH_MEMORY")
	clearEnv(t, "LEASH_PIDS_LIMIT")
}

// Each limit resolves independently: flag > env > config.
func TestResolveResourceLimitsPrecedence(t *testing.T) {
	clearResourceEnv(t)
	file := configstore.ResourceLimits{CPUs: "4", Memory: "8g", PidsLimit: "1000"}

	got, err := resolveResourceLimits(options{}, file)
	if err != nil || got.cpus != "4" || got.memory != "8g" || got.pidsLimit != "1000" {
		t.Fatalf("config layer: %+v, %v", got, err)
	}

	setEnv(t, "LEASH_MEMORY", "2g")
	setEnv(t, "LEASH_PIDS_LIMIT", "500")
	got, err = resolveResourceLimits(options{pidsLimit: "64"}, file)
	if err != nil {
		t.Fatal(err)
	}
	if got.cpus != "4" || got.memory != "2g" || got.pidsLimit != "64" {
		t.Fatalf("precedence wrong: %+v", got)
	}
}

func TestResolveResourceLimitsNoneConfigured(t *testing.T) {
	clearResourceEnv(t)
	if none, err := resolveResourceLimits(options{}, configstore.ResourceLimits{}); err != nil || none.any() {
		t.Fatalf("no limits configured: %+v, %v", none, err)
	}
}

// Garbage at the winning layer fails the run and names its source.
func TestResolveResourceLimitsRejectsGarbage(t *testing.T) {
	clearResourceEnv(t)
	setEnv(t, "LEASH_CPUS", "lots")
	_, err := resolveResourceLimits(options{memory: "1x"}, configstore.ResourceLimits{PidsLimit: "-5"})
	if err == nil {
		t.Fatal("want error")
	}
	for _, want := range []string{"LEASH_CPUS", "invalid cpus", "flag", "invalid memory", "config", "invalid pids limit"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error missing %q: %v", want, err)
		}
	}
}

func TestParseArgsResourceFlags(t *testing.T) {
	opts, err := parseArgs([]string{"--cpus", "1.5", "--memory=2g", "--pids-limit", "256", "--", "make", "test"})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if opts.cpus != "1.5" || opts.memory != "2g" || opts.pidsLimit != "256" {
		t.Fatalf("flags not captured: cpus=%q memory=%q pids=%q", opts.cpus, opts.memory, opts.pidsLimit)
	}
	if _, err := parseArgs([]string{"--memory"}); err == nil {
		t.Fatal("--memory without a value must fail")
	}
	if _, err := parseArgs([]string{"--cpus=", "x"}); err == nil {
		t.Fatal("--cpus= without a value must fail")
	}
}

func TestLoadConfigResourceLimitsByRuntime(t *testing.T) {
	clearNetworkEnv(t)
	clearResourceEnv(t)
	clearEnv(t, "LEASH_RUNTIME")

	cfg, _, err := loadConfig(t.TempDir(), options{runtime: "docker", memory: "1g", pidsLimit: "128"})
	if err != nil {
		t.Fatalf("docker runtime with limits: %v", err)
	}
	if cfg.resources.memory != "1g" || cfg.resources.pids != 128 {
		t.Fatalf("resources not resolved: %+v", cfg.resources)
	}

	_, _, err = loadConfig(t.TempDir(), options{runtime: "docker", cpus: "nope"})
	if err == nil || !strings.Contains(err.Error(), "invalid cpus") {
		t.Fatalf("invalid cpus must fail loadConfig, got %v", err)
	}

	// Native has no target container: refuse, never silently ignore.
	_, _, err = loadConfig(t.TempDir(), options{runtime: nativeRuntimeName, memory: "1g"})
	if err == nil || !strings.Contains(err.Error(), "not supported by the native runtime") {
		t.Fatalf("native runtime with limits must fail, got %v", err)
	}
	if _, _, err := loadConfig(t.TempDir(), options{runtime: nativeRuntimeName}); err != nil {
		t.Fatalf("native without limits: %v", err)
	}
}

func TestResourceLimitsDockerArgsAndReport(t *testing.T) {
	clearResourceEnv(t)
	l, err := resolveResourceLimits(options{cpus: "1.5", memory: "512M", pidsLimit: "256"}, configstore.ResourceLimits{})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"--cpus", "1.5", "--memory", "512m", "--memory-swap", "512m", "--pids-limit", "256"}
	if got := l.dockerArgs(); !reflect.DeepEqual(got, want) {
		t.Fatalf("dockerArgs = %q, want %q", got, want)
	}
	if got := (resourceLimits{}).dockerArgs(); len(got) != 0 {
		t.Fatalf("no limits must add no args, got %q", got)
	}
	wantReport := "event=runner.resource-limits status=applied cpus=1.5 nano_cpus=1500000000 memory=512m memory_bytes=536870912 pids_limit=256"
	if got := l.report(); got != wantReport {
		t.Fatalf("report = %q\nwant     %q", got, wantReport)
	}
	only, _ := resolveResourceLimits(options{pidsLimit: "8"}, configstore.ResourceLimits{})
	if got := only.report(); got != "event=runner.resource-limits status=applied pids_limit=8" {
		t.Fatalf("partial report = %q", got)
	}
}

// inspectRuntime answers the HostConfig read-back used by
// verifyTargetResourceLimits.
type inspectRuntime struct {
	out  string
	err  error
	args []string
}

func (rt *inspectRuntime) Run(ctx context.Context, args ...string) error { return nil }
func (rt *inspectRuntime) Output(_ context.Context, args ...string) (string, error) {
	rt.args = append([]string(nil), args...)
	return rt.out, rt.err
}
func (rt *inspectRuntime) ExecWithInput(context.Context, string, string, io.Reader) error {
	return nil
}
func (rt *inspectRuntime) Cmd(ctx context.Context, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, "true")
}
func (rt *inspectRuntime) Name() string { return "docker" }

func TestVerifyTargetResourceLimits(t *testing.T) {
	clearResourceEnv(t)
	limits, err := resolveResourceLimits(options{cpus: "1.5", memory: "512m", pidsLimit: "256"}, configstore.ResourceLimits{})
	if err != nil {
		t.Fatal(err)
	}
	newRunner := func(rt Runtime) (*runner, *bytes.Buffer) {
		var diag bytes.Buffer
		return &runner{runtime: rt, diagnostics: &diag, cfg: config{targetContainer: "target", resources: limits}}, &diag
	}

	t.Run("applied", func(t *testing.T) {
		rt := &inspectRuntime{out: "1500000000 536870912 256\n"}
		r, diag := newRunner(rt)
		if err := r.verifyTargetResourceLimits(context.Background()); err != nil {
			t.Fatalf("verify: %v", err)
		}
		if want := []string{"inspect", "-f", "{{.HostConfig.NanoCpus}} {{.HostConfig.Memory}} {{.HostConfig.PidsLimit}}", "target"}; !reflect.DeepEqual(rt.args, want) {
			t.Fatalf("inspect args = %q", rt.args)
		}
		if got := strings.TrimSpace(diag.String()); got != limits.report() {
			t.Fatalf("report line = %q, want %q", got, limits.report())
		}
	})

	t.Run("dropped by engine fails closed", func(t *testing.T) {
		r, diag := newRunner(&inspectRuntime{out: "1500000000 0 <nil>\n"})
		err := r.verifyTargetResourceLimits(context.Background())
		if err == nil || !strings.Contains(err.Error(), "memory: requested 512m") || !strings.Contains(err.Error(), "pids-limit: requested 256") {
			t.Fatalf("want mismatch error, got %v", err)
		}
		if strings.Contains(diag.String(), "status=applied") {
			t.Fatal("must not report applied limits on mismatch")
		}
	})

	t.Run("inspect failure fails closed", func(t *testing.T) {
		r, _ := newRunner(&inspectRuntime{err: errors.New("daemon gone")})
		if err := r.verifyTargetResourceLimits(context.Background()); err == nil {
			t.Fatal("want error")
		}
	})

	t.Run("no limits is a no-op", func(t *testing.T) {
		rt := &inspectRuntime{err: errors.New("must not be called")}
		r := &runner{runtime: rt, cfg: config{targetContainer: "target"}}
		if err := r.verifyTargetResourceLimits(context.Background()); err != nil || rt.args != nil {
			t.Fatalf("no-op expected, err=%v args=%q", err, rt.args)
		}
	})
}

// The validated limits reach the target container's `run` argv (and not the
// leash sidecar's).
func TestLaunchTargetContainerPassesResourceLimits(t *testing.T) {
	clearResourceEnv(t)
	limits, err := resolveResourceLimits(options{cpus: "2", memory: "1g", pidsLimit: "128"}, configstore.ResourceLimits{})
	if err != nil {
		t.Fatal(err)
	}
	var (
		mu       sync.Mutex
		commands [][]string
	)
	origRun, origOutput := runCommand, commandOutput
	runCommand = func(_ context.Context, _, _ io.Writer, name string, args ...string) error {
		mu.Lock()
		defer mu.Unlock()
		commands = append(commands, append([]string(nil), args...))
		return nil
	}
	commandOutput = func(_ context.Context, name string, args ...string) (string, error) {
		if len(args) >= 3 && args[0] == "inspect" && strings.Contains(args[2], "{{.Architecture}}") {
			return "amd64\n", nil
		}
		return "", fmt.Errorf("unexpected commandOutput call: %s %s", name, strings.Join(args, " "))
	}
	t.Cleanup(func() { runCommand, commandOutput = origRun, origOutput })

	dir := t.TempDir()
	mk := func(name string) string {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	r := &runner{
		logger:  log.New(ioDiscard{}, "", 0),
		verbose: true,
		cfg: config{
			hostOS: "linux", workDir: mk("work"), shareDir: mk("share"), privateDir: mk("private"),
			logDir: mk("log"), cfgDir: mk("cfg"), callerDir: mk("caller"),
			targetImage: "example/target:latest", leashImage: "example/leash:latest",
			targetContainer: "t", leashContainer: "t-leash", proxyPort: "18000",
			bootstrapTimeout: 30 * time.Second, listenCfg: listen.Default(), resources: limits,
		},
		opts:           options{command: []string{"bash"}},
		selinuxChecked: true,
	}
	if err := r.launchTargetContainer(context.Background(), "SIGTERM"); err != nil {
		t.Fatalf("launch target: %v", err)
	}
	if err := r.launchLeashContainer(context.Background(), "/sys/fs/cgroup/x"); err != nil {
		t.Fatalf("launch leash: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(commands) != 2 {
		t.Fatalf("want 2 runs, got %d", len(commands))
	}
	target, leash := strings.Join(commands[0], " "), strings.Join(commands[1], " ")
	if !strings.Contains(target, "--cpus 2 --memory 1g --memory-swap 1g --pids-limit 128") {
		t.Fatalf("target run args missing limits: %s", target)
	}
	if strings.Contains(leash, "--memory") || strings.Contains(leash, "--pids-limit") || strings.Contains(leash, "--cpus") {
		t.Fatalf("leash sidecar must not get the target limits: %s", leash)
	}
	// #188: every run is fail-closed, so the eBPF LSM refuses packet/raw
	// sockets itself and the target keeps NET_RAW (ping's file capability
	// needs it in the bounding set).
	if strings.Contains(target, "--cap-drop") {
		t.Fatalf("target run args must not drop capabilities: %s", target)
	}
	// Flags must precede the image (the image and its args come last).
	if strings.Index(target, "--pids-limit") > strings.Index(target, "example/target:latest") {
		t.Fatalf("limits must come before the image: %s", target)
	}
}
