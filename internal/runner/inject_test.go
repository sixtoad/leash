package runner

import (
	"net"
	"os"
	"path/filepath"
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
		"missing plugin":     "env=X,socket=/tmp/s.sock",
		"missing env":        "plugin=p,socket=/tmp/s.sock",
		"missing socket":     "plugin=p,env=X",
		"unknown key":        "plugin=p,env=X,socket=/tmp/s.sock,foo=bar",
		"plugin with path":   "plugin=/usr/bin/p,env=X,socket=/tmp/s.sock",
		"relative socket":    "plugin=p,env=X,socket=rel.sock",
		"traversal socket":   "plugin=p,env=X,socket=/tmp/../etc/x.sock",
		"protected run/user": "plugin=p,env=X,socket=/run/user/1000/bus",
		"protected dbus":     "plugin=p,env=X,socket=/run/dbus/system_bus_socket",
		"protected docker":   "plugin=p,env=X,socket=/var/run/docker.sock",
		"bad env name":       "plugin=p,env=A B,socket=/tmp/s.sock",
	}
	for name, spec := range cases {
		if _, err := parseInjectService(spec); err == nil {
			t.Fatalf("%s: expected error for spec %q", name, spec)
		}
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
