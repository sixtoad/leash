package runner

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseInjectServiceValid(t *testing.T) {
	svc, err := parseInjectService("plugin=helper,env=HELPER_ADDR,socket=/tmp/helper.sock")
	if err != nil {
		t.Fatalf("valid spec rejected: %v", err)
	}
	if svc.plugin != "helper" || svc.env != "HELPER_ADDR" || svc.socket != "/tmp/helper.sock" {
		t.Fatalf("parsed fields wrong: %+v", svc)
	}
	if svc.config != "" {
		t.Fatalf("config should be empty when omitted, got %q", svc.config)
	}
}

// config is optional and opaque: parseInjectService stores it verbatim without
// interpreting it.
func TestParseInjectServiceConfig(t *testing.T) {
	svc, err := parseInjectService("plugin=helper,env=HELPER_ADDR,socket=/tmp/helper.sock,config=opaque-value-123")
	if err != nil {
		t.Fatalf("valid spec with config rejected: %v", err)
	}
	if svc.config != "opaque-value-123" {
		t.Fatalf("config not stored verbatim, got %q", svc.config)
	}

	// A repeated config= is rejected like any duplicate key.
	if _, err := parseInjectService("plugin=helper,env=X,socket=/tmp/s.sock,config=a,config=b"); err == nil {
		t.Fatal("duplicate config= should be rejected")
	}
}

func TestParseInjectServiceRejectsBadSpecs(t *testing.T) {
	cases := map[string]string{
		"missing plugin":       "env=X,socket=/tmp/s.sock",
		"missing env":          "plugin=p,socket=/tmp/s.sock",
		"missing socket":       "plugin=p,env=X",
		"unknown key":          "plugin=p,env=X,socket=/tmp/s.sock,foo=bar",
		"plugin relative path": "plugin=sub/p,env=X,socket=/tmp/s.sock",
		"relative socket":      "plugin=p,env=X,socket=rel.sock",
		"traversal socket":     "plugin=p,env=X,socket=/tmp/../etc/x.sock",
		"protected run/user":   "plugin=p,env=X,socket=/run/user/1000/bus",
		"protected dbus":       "plugin=p,env=X,socket=/run/dbus/system_bus_socket",
		"protected docker":     "plugin=p,env=X,socket=/var/run/docker.sock",
		"bad env name":         "plugin=p,env=A B,socket=/tmp/s.sock",
	}
	for name, spec := range cases {
		if _, err := parseInjectService(spec); err == nil {
			t.Fatalf("%s: expected error for spec %q", name, spec)
		}
	}
}

// walk resolves and passes the ABSOLUTE path of the plugin it ships, so an
// absolute plugin path must be accepted (bare names and abs paths both valid).
func TestParseInjectServiceAcceptsAbsPluginPath(t *testing.T) {
	svc, err := parseInjectService("plugin=/opt/leash/leash-plugin-secretbroker,env=X,socket=/tmp/s.sock")
	if err != nil {
		t.Fatalf("absolute plugin path should be accepted: %v", err)
	}
	if svc.plugin != "/opt/leash/leash-plugin-secretbroker" {
		t.Fatalf("plugin = %q, want the absolute path preserved", svc.plugin)
	}
}

func TestParseInjectServiceRejectsDuplicateKeys(t *testing.T) {
	cases := map[string]string{
		"dup plugin": "plugin=a,plugin=b,env=X,socket=/tmp/s.sock",
		"dup env":    "plugin=a,env=X,env=Y,socket=/tmp/s.sock",
		"dup socket": "plugin=a,env=X,socket=/tmp/s.sock,socket=/tmp/t.sock",
	}
	for name, spec := range cases {
		if _, err := parseInjectService(spec); err == nil {
			t.Fatalf("%s: expected duplicate-key error for spec %q", name, spec)
		}
	}
}

// A ".." that is only part of a filename segment is legitimate; only a genuine
// ".." path segment is traversal and must be rejected.
func TestValidateInjectSocketDotDotSegmentOnly(t *testing.T) {
	if err := validateInjectSocket("/tmp/a..b/bus"); err != nil {
		t.Fatalf("/tmp/a..b/bus should be accepted, got: %v", err)
	}
	if err := validateInjectSocket("/tmp/../x"); err == nil {
		t.Fatal("/tmp/../x should be rejected as traversal")
	}
}

func TestRemoveStaleSocket(t *testing.T) {
	dir := t.TempDir()

	// Missing path: success (nothing to remove).
	missing := filepath.Join(dir, "missing.sock")
	if err := removeStaleSocket(missing); err != nil {
		t.Fatalf("missing path should be ok, got: %v", err)
	}

	// Existing non-socket (regular file): refused, and the file is left intact.
	reg := filepath.Join(dir, "regular")
	if err := os.WriteFile(reg, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := removeStaleSocket(reg)
	if err == nil || !strings.Contains(err.Error(), "not a socket") {
		t.Fatalf("regular file should be refused with a not-a-socket error, got: %v", err)
	}
	if _, statErr := os.Stat(reg); statErr != nil {
		t.Fatalf("refused regular file must not be deleted: %v", statErr)
	}

	// Existing socket: removed.
	sockPath := filepath.Join(dir, "real.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer ln.Close()
	if err := removeStaleSocket(sockPath); err != nil {
		t.Fatalf("existing socket should be removed, got: %v", err)
	}
	if _, statErr := os.Lstat(sockPath); !os.IsNotExist(statErr) {
		t.Fatalf("socket should have been removed, stat err: %v", statErr)
	}
}

func TestInjectServicesRejectsDuplicatesAcrossSpecs(t *testing.T) {
	t.Run("duplicate socket", func(t *testing.T) {
		r := &runner{opts: options{injectServices: []injectService{
			{plugin: "p", env: "A", socket: "/tmp/dup.sock"},
			{plugin: "p", env: "B", socket: "/tmp/dup.sock"},
		}}}
		err := nativeLauncher{r: r}.injectServices(nil)
		if err == nil || !strings.Contains(err.Error(), "duplicate --inject-service socket") {
			t.Fatalf("expected duplicate-socket error, got: %v", err)
		}
	})
	t.Run("duplicate env", func(t *testing.T) {
		r := &runner{opts: options{injectServices: []injectService{
			{plugin: "p", env: "SAME", socket: "/tmp/a.sock"},
			{plugin: "p", env: "SAME", socket: "/tmp/b.sock"},
		}}}
		err := nativeLauncher{r: r}.injectServices(nil)
		if err == nil || !strings.Contains(err.Error(), "duplicate --inject-service env") {
			t.Fatalf("expected duplicate-env error, got: %v", err)
		}
	})
}

// writeStubInjectPlugin writes an executable helper that binds its socket (from
// LEASH_INJECT_SOCKET) so the fail-closed readiness wait sees it appear, then
// blocks. Returned path is absolute so spawnInjectService resolves it directly.
func writeStubInjectPlugin(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "stub-plugin.sh")
	script := "#!/bin/sh\n" +
		": > \"$LEASH_INJECT_SOCKET\"\n" + // create the socket path so os.Stat succeeds
		"exec sleep 30\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// The container backend spawns each plugin once and builds the docker `-v`/`-e`
// flags that bind the socket dir into the workload container and point the env var
// at it. Uses a stubbed plugin (no real daemon).
func TestSpawnInjectServicesContainerDockerArgs(t *testing.T) {
	dir := t.TempDir()
	plugin := writeStubInjectPlugin(t, dir)
	sock := filepath.Join(dir, "helper.sock")

	r := &runner{opts: options{injectServices: []injectService{
		{plugin: plugin, env: "HELPER_ADDR", socket: sock},
	}}}
	if err := r.spawnInjectServicesContainer(context.Background()); err != nil {
		t.Fatalf("spawnInjectServicesContainer failed: %v", err)
	}
	defer r.teardownInjectedPlugins()

	want := []string{
		"-v", dir + ":" + dir,
		"-e", "HELPER_ADDR=unix:path=" + sock,
	}
	if !reflect.DeepEqual(r.injectedDockerArgs, want) {
		t.Fatalf("injectedDockerArgs mismatch:\n got %q\nwant %q", r.injectedDockerArgs, want)
	}
	// The container path binds the socket into the container (docker args) and does
	// NOT set the workload env directly the way native does.
	if len(r.injectedEnv) != 0 {
		t.Fatalf("container backend must not populate injectedEnv, got %q", r.injectedEnv)
	}
	// The plugin/socket were recorded for teardown.
	if len(r.injectedPlugins) != 1 || len(r.injectedCleanup) != 1 || r.injectedCleanup[0] != sock {
		t.Fatalf("plugin/cleanup not recorded: plugins=%d cleanup=%v", len(r.injectedPlugins), r.injectedCleanup)
	}
}

// Cross-spec duplicate socket/env checks apply on the container path too, before
// anything is spawned.
func TestSpawnInjectServicesContainerRejectsDuplicates(t *testing.T) {
	t.Run("duplicate socket", func(t *testing.T) {
		r := &runner{opts: options{injectServices: []injectService{
			{plugin: "p", env: "A", socket: "/tmp/dup.sock"},
			{plugin: "p", env: "B", socket: "/tmp/dup.sock"},
		}}}
		err := r.spawnInjectServicesContainer(context.Background())
		if err == nil || !strings.Contains(err.Error(), "duplicate --inject-service socket") {
			t.Fatalf("expected duplicate-socket error, got: %v", err)
		}
		if r.injectedDockerArgs != nil {
			t.Fatalf("no docker args should be built on a rejected spec, got %q", r.injectedDockerArgs)
		}
	})
	t.Run("duplicate env", func(t *testing.T) {
		r := &runner{opts: options{injectServices: []injectService{
			{plugin: "p", env: "SAME", socket: "/tmp/a.sock"},
			{plugin: "p", env: "SAME", socket: "/tmp/b.sock"},
		}}}
		err := r.spawnInjectServicesContainer(context.Background())
		if err == nil || !strings.Contains(err.Error(), "duplicate --inject-service env") {
			t.Fatalf("expected duplicate-env error, got: %v", err)
		}
	})
}

// teardownInjectedPlugins (shared by native + container Remove) stops the plugin
// and removes its recorded socket.
func TestTeardownInjectedPluginsRemovesSocket(t *testing.T) {
	dir := t.TempDir()
	plugin := writeStubInjectPlugin(t, dir)
	sock := filepath.Join(dir, "helper.sock")

	r := &runner{opts: options{injectServices: []injectService{
		{plugin: plugin, env: "HELPER_ADDR", socket: sock},
	}}}
	if err := r.spawnInjectServicesContainer(context.Background()); err != nil {
		t.Fatalf("spawnInjectServicesContainer failed: %v", err)
	}
	if _, err := os.Stat(sock); err != nil {
		t.Fatalf("socket should exist after spawn: %v", err)
	}
	r.teardownInjectedPlugins()
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Fatalf("socket should be removed after teardown, stat err: %v", err)
	}
}

func TestParseArgsInjectService(t *testing.T) {
	opts, err := parseArgs([]string{
		"--inject-service", "plugin=helper,env=HELPER_ADDR,socket=/tmp/helper.sock,config=opaque",
		"--", "agy",
	})
	if err != nil {
		t.Fatalf("parseArgs failed: %v", err)
	}
	if len(opts.injectServices) != 1 {
		t.Fatalf("expected one inject-service, got %d", len(opts.injectServices))
	}
	if got := opts.injectServices[0].config; got != "opaque" {
		t.Fatalf("expected opaque config to be captured, got %q", got)
	}
}
