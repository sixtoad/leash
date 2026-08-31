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

// Readiness adapter for leashd. Both native and container launchers consume the
// same post-attach marker so neither can release a workload during LSM startup.

func enableEnforcementReady() {
	var once sync.Once
	lsm.SetEnforcementSettledHook(func() {
		once.Do(func() { writeEnforcementReadyMarker(getLeashDirFromEnv()) })
	})
}

// enableHostMode logs the additional native/host-mode contract. The common
// readiness hook is installed for every runtime by Main.
func enableHostMode() {
	log.Printf("leash: host mode (no container) — workload in a systemd scope; enforcement requires CAP_BPF/CAP_NET_ADMIN and an active bpf LSM (see docs/LEASHD-HOST-MODE.md)")
}

// writeEnforcementReadyMarker writes the enforcement-ready marker — the signal
// every launcher waits on before running the workload. Also called on the
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
