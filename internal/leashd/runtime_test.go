package leashd

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"log"

	"github.com/strongdm/leash/internal/policy"
)

const sampleCedarPolicy = `permit (
    principal,
    action in Action::"FileOpen",
    resource
)
when {
    resource in [ Dir::"/tmp" ]
};`

var (
	iptablesOverrideMu sync.Mutex
	logCaptureMu       sync.Mutex
)

// leashEnv serializes the tests that use the process-wide LEASH_DIR and
// LEASH_PRIVATE_DIR: those that point them at their own directories, and
// those whose code writes there (a policy API persisting cedar-runtime.cedar
// into LEASH_DIR). A test that writes there without holding it races another
// test's RemoveAll of its directory (#234).
var leashEnv = &envLock{sem: make(chan struct{}, 1)}

// envLockWait bounds how long a test waits for leashEnv. The holders are short
// tests, so a long wait means the holder is hung or leaked the lock; failing
// then names it, instead of every later test blocking until go test's
// 10-minute timeout.
const envLockWait = 2 * time.Minute

type envLock struct {
	sem    chan struct{}
	mu     sync.Mutex
	holder string
}

// acquire takes the lock for t. The returned release is idempotent and is
// also registered as a cleanup, so a failure anywhere in the test (setup, body
// or another cleanup) can never leak the lock (#234).
func (l *envLock) acquire(t *testing.T) (release func()) {
	t.Helper()
	timer := time.NewTimer(envLockWait)
	defer timer.Stop()
	select {
	case l.sem <- struct{}{}:
	case <-timer.C:
		l.mu.Lock()
		holder := l.holder
		l.mu.Unlock()
		t.Fatalf("waited %s for the LEASH_DIR test lock, still held by %s: that test is hung or leaked the lock\n%s",
			envLockWait, holder, allGoroutines())
	}
	l.mu.Lock()
	l.holder = t.Name()
	l.mu.Unlock()
	var once sync.Once
	release = func() {
		once.Do(func() {
			l.mu.Lock()
			l.holder = ""
			l.mu.Unlock()
			<-l.sem
		})
	}
	t.Cleanup(release)
	return release
}

// allGoroutines returns every goroutine's stack, so a test that gives up
// waiting shows what is blocked.
func allGoroutines() string {
	buf := make([]byte, 1<<20)
	return string(buf[:runtime.Stack(buf, true)])
}

func provisionLeashEnv(t *testing.T) (string, string) {
	t.Helper()

	release := leashEnv.acquire(t)
	base, err := os.MkdirTemp("", "leash-env-")
	if err != nil {
		t.Fatalf("failed to create leash env base: %v", err)
	}
	publicDir := filepath.Join(base, "public")
	privateDir := filepath.Join(base, "private")
	if err := os.MkdirAll(publicDir, 0o755); err != nil {
		t.Fatalf("failed to create public dir: %v", err)
	}
	if err := os.MkdirAll(privateDir, 0o700); err != nil {
		t.Fatalf("failed to create private dir: %v", err)
	}

	prevPublic, hadPublic := os.LookupEnv("LEASH_DIR")
	prevPrivate, hadPrivate := os.LookupEnv("LEASH_PRIVATE_DIR")
	if err := os.Setenv("LEASH_DIR", publicDir); err != nil {
		t.Fatalf("set LEASH_DIR: %v", err)
	}
	if err := os.Setenv("LEASH_PRIVATE_DIR", privateDir); err != nil {
		t.Fatalf("set LEASH_PRIVATE_DIR: %v", err)
	}

	t.Cleanup(func() {
		if hadPublic {
			_ = os.Setenv("LEASH_DIR", prevPublic)
		} else {
			_ = os.Unsetenv("LEASH_DIR")
		}
		if hadPrivate {
			_ = os.Setenv("LEASH_PRIVATE_DIR", prevPrivate)
		} else {
			_ = os.Unsetenv("LEASH_PRIVATE_DIR")
		}
		if err := os.RemoveAll(base); err != nil {
			t.Errorf("cleanup leash env: %v", err)
		}
		release()
	})

	return publicDir, privateDir
}

func TestMain(m *testing.M) {
	base, err := os.MkdirTemp("", "leashd-test-")
	if err != nil {
		panic(err)
	}
	public := filepath.Join(base, "public")
	private := filepath.Join(base, "private")
	if err := os.MkdirAll(public, 0o755); err != nil {
		panic(err)
	}
	if err := os.MkdirAll(private, 0o700); err != nil {
		panic(err)
	}
	if err := os.Setenv("LEASH_DIR", public); err != nil {
		panic(err)
	}
	if err := os.Setenv("LEASH_PRIVATE_DIR", private); err != nil {
		panic(err)
	}
	code := m.Run()
	_ = os.Unsetenv("LEASH_PRIVATE_DIR")
	_ = os.Unsetenv("LEASH_DIR")
	_ = os.RemoveAll(base)
	os.Exit(code)
}

func writePolicyFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.cedar")
	if err := os.WriteFile(path, []byte(content+"\n"), 0o644); err != nil {
		t.Fatalf("failed to write policy file: %v", err)
	}
	return path
}

func createCgroupStub(t *testing.T, withControllers bool) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "cgroup")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("failed to create cgroup dir: %v", err)
	}
	if withControllers {
		controllerFile := filepath.Join(dir, "cgroup.controllers")
		if err := os.WriteFile(controllerFile, []byte(""), 0o644); err != nil {
			t.Fatalf("failed to create cgroup.controllers: %v", err)
		}
	}
	return dir
}

func TestPreFlightNilConfig(t *testing.T) {
	t.Parallel()
	if err := preFlight(nil); err == nil || err.Error() != "runtime configuration required" {
		t.Fatalf("expected runtime configuration error, got %v", err)
	}
}

func TestPreFlightMissingPolicy(t *testing.T) {
	t.Parallel()
	_, _ = provisionLeashEnv(t)
	tempDir := t.TempDir()
	policyPath := filepath.Join(tempDir, "missing.cedar")
	cgroupPath := createCgroupStub(t, true)
	cfg := &runtimeConfig{
		PolicyPath: policyPath,
		ProxyPort:  "18000",
		CgroupPath: cgroupPath,
	}
	if err := preFlight(cfg); err != nil {
		t.Fatalf("expected preFlight to create default policy, got %v", err)
	}
	data, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatalf("expected default policy file to be created: %v", err)
	}
	got := strings.TrimSpace(string(data))
	want := strings.TrimSpace(policy.DefaultCedar())
	if got != want {
		t.Fatalf("default Cedar contents unexpected: got %q want %q", got, want)
	}
}

func TestPreFlightInvalidCedar(t *testing.T) {
	t.Parallel()
	_, _ = provisionLeashEnv(t)
	badCedar := "permit (principal"
	policyPath := writePolicyFile(t, badCedar)
	cgroupPath := createCgroupStub(t, true)
	cfg := &runtimeConfig{
		PolicyPath: policyPath,
		ProxyPort:  "18000",
		CgroupPath: cgroupPath,
	}
	if err := preFlight(cfg); err == nil || !strings.Contains(err.Error(), "invalid Cedar policy") {
		t.Fatalf("expected invalid Cedar error, got %v", err)
	}
}

func TestPreFlightUnreadablePolicy(t *testing.T) {
	t.Parallel()
	_, _ = provisionLeashEnv(t)
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.cedar")
	if err := os.Mkdir(policyPath, 0o755); err != nil {
		t.Fatalf("failed to create directory placeholder: %v", err)
	}
	cgroupPath := createCgroupStub(t, true)
	cfg := &runtimeConfig{
		PolicyPath: policyPath,
		ProxyPort:  "18000",
		CgroupPath: cgroupPath,
	}
	if err := preFlight(cfg); err == nil || !strings.Contains(err.Error(), "invalid Cedar policy") {
		t.Fatalf("expected invalid Cedar error due to unreadable file, got %v", err)
	}
}

func TestPreFlightRequiresPrivateDir(t *testing.T) {
	t.Parallel()

	_, privateDir := provisionLeashEnv(t)
	if err := os.Unsetenv("LEASH_PRIVATE_DIR"); err != nil {
		t.Fatalf("unset LEASH_PRIVATE_DIR: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Setenv("LEASH_PRIVATE_DIR", privateDir); err != nil {
			t.Fatalf("restore LEASH_PRIVATE_DIR: %v", err)
		}
	})

	policyPath := writePolicyFile(t, sampleCedarPolicy)
	cgroupPath := createCgroupStub(t, true)
	cfg := &runtimeConfig{
		PolicyPath: policyPath,
		ProxyPort:  "18000",
		CgroupPath: cgroupPath,
	}

	if err := preFlight(cfg); err == nil || !strings.Contains(err.Error(), "LEASH_PRIVATE_DIR environment variable is required") {
		t.Fatalf("expected LEASH_PRIVATE_DIR requirement error, got %v", err)
	}
}

func TestPreFlightRejectsWorldReadableKey(t *testing.T) {
	t.Parallel()

	_, privateDir := provisionLeashEnv(t)
	keyPath := filepath.Join(privateDir, "ca-key.pem")
	if err := os.WriteFile(keyPath, []byte("dummy"), 0o644); err != nil {
		t.Fatalf("write key: %v", err)
	}

	policyPath := writePolicyFile(t, sampleCedarPolicy)
	cgroupPath := createCgroupStub(t, true)
	cfg := &runtimeConfig{
		PolicyPath: policyPath,
		ProxyPort:  "18000",
		CgroupPath: cgroupPath,
	}

	if err := preFlight(cfg); err == nil || !strings.Contains(err.Error(), "must have permission 0600") {
		t.Fatalf("expected CA key permission error, got %v", err)
	}
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestPreFlightLogsMountSummary(t *testing.T) {
	t.Parallel()

	logCaptureMu.Lock()
	defer logCaptureMu.Unlock()

	_, _ = provisionLeashEnv(t)

	originalWriter := log.Writer()
	// Parallel tests log through the global logger too: read the capture
	// under the same lock its writes take.
	var buf lockedBuffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(originalWriter) })

	policyPath := writePolicyFile(t, sampleCedarPolicy)
	cgroupPath := createCgroupStub(t, true)
	cfg := &runtimeConfig{
		PolicyPath: policyPath,
		ProxyPort:  "18000",
		CgroupPath: cgroupPath,
	}

	if err := preFlight(cfg); err != nil {
		t.Fatalf("preFlight returned error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "leashd_mounts public=") {
		t.Fatalf("mount summary log missing; got %q", output)
	}

	tmpDir := t.TempDir()
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })
	logPath := filepath.Join(tmpDir, "runtime-mount-log.txt")
	if err := os.WriteFile(logPath, []byte(output), 0o644); err != nil {
		t.Fatalf("write runtime mount log: %v", err)
	}
}

func TestEnsureDefaultCedarFileCreatesBaselineWhenMissing(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	cedarPath := filepath.Join(tempDir, "leash.cedar")

	if err := policy.EnsureDefaultCedarFile(cedarPath); err != nil {
		t.Fatalf("EnsureDefaultCedarFile returned error: %v", err)
	}

	data, err := os.ReadFile(cedarPath)
	if err != nil {
		t.Fatalf("expected cedar file to be created: %v", err)
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" || !strings.Contains(trimmed, `Action::"NetworkConnect"`) {
		t.Fatalf("expected default cedar content, got %q", trimmed)
	}
}

func TestPreFlightValidConfig(t *testing.T) {
	t.Parallel()
	_, _ = provisionLeashEnv(t)
	policyPath := writePolicyFile(t, sampleCedarPolicy)
	tempRoot := t.TempDir()
	logPath := filepath.Join(tempRoot, "logs", "events.log")
	cgroupPath := createCgroupStub(t, true)
	cfg := &runtimeConfig{
		PolicyPath: policyPath,
		LogPath:    logPath,
		ProxyPort:  "18000",
		CgroupPath: cgroupPath,
	}
	if err := preFlight(cfg); err != nil {
		t.Fatalf("expected valid preFlight, got %v", err)
	}
	if _, err := os.Stat(logPath); err != nil {
		t.Fatalf("expected log file to be created, got %v", err)
	}
}

func TestPreFlightInvalidCgroup(t *testing.T) {
	t.Parallel()
	_, _ = provisionLeashEnv(t)
	policyPath := writePolicyFile(t, sampleCedarPolicy)
	cgroupDir := createCgroupStub(t, false)
	cfg := &runtimeConfig{
		PolicyPath: policyPath,
		ProxyPort:  "18000",
		CgroupPath: cgroupDir,
	}
	if err := preFlight(cfg); err == nil || !strings.Contains(err.Error(), "cgroup path") {
		t.Fatalf("expected invalid cgroup error, got %v", err)
	}
}

func TestPreFlightInvalidProxyPort(t *testing.T) {
	t.Parallel()
	_, _ = provisionLeashEnv(t)
	policyPath := writePolicyFile(t, sampleCedarPolicy)
	cgroupPath := createCgroupStub(t, true)
	cfg := &runtimeConfig{
		PolicyPath: policyPath,
		ProxyPort:  "not-a-port",
		CgroupPath: cgroupPath,
	}
	if err := preFlight(cfg); err == nil || !strings.Contains(err.Error(), "invalid proxy port") {
		t.Fatalf("expected proxy port error, got %v", err)
	}
}

func TestParseConfigListenEnvDisable(t *testing.T) {
	t.Setenv("LEASH_LISTEN", "")
	cfg, err := parseConfig([]string{"leashd"})
	if err != nil {
		t.Fatalf("parseConfig returned error: %v", err)
	}
	if !cfg.WebDisabled {
		t.Fatalf("expected control UI disabled when LEASH_LISTEN is empty")
	}
	if cfg.WebBind != "" {
		t.Fatalf("expected empty WebBind, got %q", cfg.WebBind)
	}
}

func TestParseConfigListenEnvValue(t *testing.T) {
	t.Setenv("LEASH_LISTEN", ":19003")
	cfg, err := parseConfig([]string{"leashd"})
	if err != nil {
		t.Fatalf("parseConfig returned error: %v", err)
	}
	if cfg.WebBind != ":19003" {
		t.Fatalf("expected WebBind :19003, got %q", cfg.WebBind)
	}
	if cfg.WebDisabled {
		t.Fatalf("expected control UI enabled")
	}
}

func TestParseConfigListenFlagOverridesEnv(t *testing.T) {
	t.Setenv("LEASH_LISTEN", ":19001")
	cfg, err := parseConfig([]string{"leashd", "--listen", "127.0.0.1:19002"})
	if err != nil {
		t.Fatalf("parseConfig returned error: %v", err)
	}
	if cfg.WebBind != "127.0.0.1:19002" {
		t.Fatalf("expected WebBind 127.0.0.1:19002, got %q", cfg.WebBind)
	}
	if cfg.WebDisabled {
		t.Fatalf("expected control UI enabled")
	}
}

// Fail-closed is the only posture: --require-lsm / LEASH_REQUIRE_LSM stay
// accepted as no-ops (Walk passes them), and there is no proxy-only flag.
func TestParseConfigPosture(t *testing.T) {
	t.Setenv("LEASH_REQUIRE_LSM", "")
	if _, err := parseConfig([]string{"leashd"}); err != nil {
		t.Fatalf("parseConfig returned error: %v", err)
	}
	if _, err := parseConfig([]string{"leashd", "--require-lsm"}); err != nil {
		t.Fatalf("--require-lsm must stay accepted: %v", err)
	}
	t.Setenv("LEASH_REQUIRE_LSM", "0")
	if _, err := parseConfig([]string{"leashd"}); err != nil {
		t.Fatalf("LEASH_REQUIRE_LSM must stay accepted: %v", err)
	}
	if _, err := parseConfig([]string{"leashd", "--allow-proxy-only"}); err == nil {
		t.Fatal("--allow-proxy-only is not a leashd flag")
	}
}

func TestPreFlightMissingIptables(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("iptables dependency only enforced on linux")
	}
	policyPath := writePolicyFile(t, sampleCedarPolicy)
	tempRoot := t.TempDir()
	logPath := filepath.Join(tempRoot, "events.log")
	cgroupPath := createCgroupStub(t, true)
	binDir := filepath.Join(t.TempDir(), "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("failed to create bin dir: %v", err)
	}
	mountPath := filepath.Join(binDir, "mount")
	if err := os.WriteFile(mountPath, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("failed to create mount stub: %v", err)
	}
	originalPath := os.Getenv("PATH")
	if err := os.Setenv("PATH", binDir); err != nil {
		t.Fatalf("failed to set PATH: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Setenv("PATH", originalPath)
	})
	cfg := &runtimeConfig{
		PolicyPath: policyPath,
		LogPath:    logPath,
		ProxyPort:  "18000",
		CgroupPath: cgroupPath,
	}

	iptablesOverrideMu.Lock()
	restoreName := iptablesBinaryName
	iptablesBinaryName = "iptables_missing_for_test"
	t.Cleanup(func() {
		iptablesBinaryName = restoreName
		iptablesOverrideMu.Unlock()
	})

	if err := preFlight(cfg); err == nil || !strings.Contains(err.Error(), "iptables") {
		t.Fatalf("expected iptables error, got %v", err)
	}
}
