package leashd

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/strongdm/leash/internal/enforcement"
	"github.com/strongdm/leash/internal/entrypoint"
	"github.com/strongdm/leash/internal/lsm"
)

// Readiness adapter for leashd. Both native and container launchers consume the
// same post-attach marker so neither can release a workload during LSM startup.

func enableEnforcementReady(cfg *runtimeConfig) {
	var once sync.Once
	lsm.SetEnforcementSettledHook(func() {
		once.Do(func() {
			writeEnforcementReadyMarker(getLeashDirFromEnv(), effectiveEnforcement(cfg, lsm.Layer1Degraded()))
		})
	})
}

// effectiveEnforcement states the enforcement level once every LSM attach has
// settled. Layer 1 counts as available only with a scopable cgroup and no
// attach failure; Layer 2 is off in --lsm-only mode.
func effectiveEnforcement(cfg *runtimeConfig, layer1Degraded bool) enforcement.Status {
	if cfg == nil {
		return enforcement.Describe(!layer1Degraded, true, true)
	}
	layer1 := strings.TrimSpace(cfg.CgroupPath) != "" && !layer1Degraded
	return enforcement.Describe(layer1, !cfg.LSMOnly, cfg.RequireLSM)
}

// enableHostMode logs the additional native/host-mode contract. The common
// readiness hook is installed for every runtime by Main.
func enableHostMode() {
	log.Printf("leash: host mode (no container) — workload in a systemd scope; enforcement requires CAP_BPF/CAP_NET_ADMIN and an active bpf LSM (see docs/LEASHD-HOST-MODE.md)")
}

// writeEnforcementReadyMarker writes the enforcement-ready marker — the signal
// every launcher waits on before running the workload. Launchers gate on the
// marker's existence (unchanged); its content is a JSON document stating the
// effective enforcement level (issue #117). Also called on the
// skip-enforcement path.
func writeEnforcementReadyMarker(dir string, status enforcement.Status) {
	log.Printf("leash: effective enforcement: %s (layer1=%s layer2=%s requireLSM=%t)", status.Enforcement, status.Layer1, status.Layer2, status.RequireLSM)
	logPolicyEvent("enforcement.level", map[string]any{
		"enforcement":    status.Enforcement,
		"layer1":         status.Layer1,
		"layer2":         status.Layer2,
		"requireLSM":     status.RequireLSM,
		"allowProxyOnly": status.AllowProxyOnly,
	})
	if strings.TrimSpace(dir) == "" {
		return
	}
	path := filepath.Join(dir, entrypoint.EnforcementReadyFileName)
	data, err := json.Marshal(status)
	if err != nil {
		data = []byte(`{"enforcement":"unknown"}`)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		log.Printf("Warning: failed to write enforcement-ready marker %s: %v", path, err)
	}
}
