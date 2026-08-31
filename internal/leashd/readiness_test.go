package leashd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/strongdm/leash/internal/entrypoint"
)

func TestClearReadyMarkersRemovesBootstrapAndEnforcement(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{entrypoint.BootstrapReadyFileName, entrypoint.EnforcementReadyFileName} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("stale\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := clearReadyMarkers(dir); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{entrypoint.BootstrapReadyFileName, entrypoint.EnforcementReadyFileName} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatalf("marker %s survived cleanup: %v", name, err)
		}
	}
}
