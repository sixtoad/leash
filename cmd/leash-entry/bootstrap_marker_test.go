package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// writeMarkerAtomic must not depend on O_EXCL: Docker Desktop's gRPC-FUSE /
// virtio-fs rejects O_EXCL creates with EACCES (#73). A pre-existing temp at the
// deterministic name (e.g. a leftover from a prior run) must be overwritten
// cleanly rather than cause an error — which is exactly what an O_EXCL open
// would do. This guards the regression.
func TestWriteMarkerAtomicToleratesExistingTemp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bootstrap.ready")

	stale := fmt.Sprintf("%s.%d.tmp", path, os.Getpid())
	if err := os.WriteFile(stale, []byte("stale"), 0o644); err != nil {
		t.Fatalf("seed stale temp: %v", err)
	}

	if err := writeMarkerAtomic(path, []byte("ready\n")); err != nil {
		t.Fatalf("writeMarkerAtomic should tolerate an existing temp, got: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read marker: %v", err)
	}
	if string(got) != "ready\n" {
		t.Fatalf("marker content = %q, want %q", got, "ready\n")
	}

	// The temp must be renamed away, not left behind.
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("temp file should be gone after rename, stat err = %v", err)
	}
}
