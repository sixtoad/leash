package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBootstrapUsesPublicCert(t *testing.T) {
	t.Parallel()

	expected := filepath.Join(shareRoot, "ca-cert.pem")
	if caCertPath != expected {
		t.Fatalf("unexpected CA certificate path: got %q want %q", caCertPath, expected)
	}
	if !strings.HasPrefix(caCertPath, shareRoot) {
		t.Fatalf("CA certificate path %q must remain under %s", caCertPath, shareRoot)
	}
}

func TestNonRootBootstrapErrorNamesTheCause(t *testing.T) {
	t.Parallel()
	msg := nonRootBootstrapError(1001)
	for _, want := range []string{"leash-error:", "uid 1001", "container root", "--user 0", "containers.conf"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("message %q lacks %q", msg, want)
		}
	}
}
