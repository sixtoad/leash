package leashd

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/strongdm/leash/internal/entrypoint"
	"github.com/strongdm/leash/internal/lsm"
)

// Native/host-mode adapter for leashd. It plugs host-mode readiness signaling
// into the generic lsm settle hook. Kept in its own file so runtime.go (the
// container/upstream path) carries only a single `if cfg.HostMode { enableHostMode() }`.

// enableHostMode logs host-mode operation and installs the enforcement-ready
// hook: once the eBPF LSM settles (all programs attached, or degraded), write
// the marker a native launcher waits on before running the workload
// (fail-closed).
func enableHostMode() {
	log.Printf("leash: host mode (no container) — workload in a systemd scope; enforcement requires CAP_BPF/CAP_NET_ADMIN and an active bpf LSM (see docs/LEASHD-HOST-MODE.md)")
	var once sync.Once
	lsm.SetEnforcementSettledHook(func() {
		once.Do(func() { writeEnforcementReadyMarker(getLeashDirFromEnv()) })
	})
}

// writeEnforcementReadyMarker writes the enforcement-ready marker — the signal a
// native launcher waits on before running the workload. Also called on the
// skip-enforcement path.
func writeEnforcementReadyMarker(dir string) {
	if strings.TrimSpace(dir) == "" {
		return
	}
	path := filepath.Join(dir, entrypoint.EnforcementReadyFileName)
	if err := os.WriteFile(path, []byte("ready\n"), 0o644); err != nil {
		log.Printf("Warning: failed to write enforcement-ready marker %s: %v", path, err)
	}
}
