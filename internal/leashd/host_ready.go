package leashd

import (
	"encoding/json"
	"fmt"
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
			st := effectiveEnforcement(cfg, lsm.Layer1Degraded(), lsm.Layer1AttachedPrograms())
			// Never publish the release marker for a level the posture forbids
			// (e.g. "none": --allow-proxy-only with the proxy also off, or no
			// LSM program attached under fail-closed). Exiting without the
			// marker keeps every launcher's existence gate closed.
			if err := st.Check(st.RequireLSM); err != nil {
				fmt.Fprintf(os.Stderr, "leash: FATAL: %v\n", err)
				logPolicyEvent("enforcement.level", statusFields(st))
				os.Exit(1)
			}
			writeEnforcementReadyMarker(getLeashDirFromEnv(), st)
		})
	})
}

// effectiveEnforcement states the enforcement level once every LSM attach has
// settled. Layer 1 counts as available only with a scopable cgroup, no attach
// failure and at least one attached program; Layer 2 is off in --lsm-only
// mode.
func effectiveEnforcement(cfg *runtimeConfig, layer1Degraded bool, attachedPrograms int) enforcement.Status {
	layer1 := !layer1Degraded && attachedPrograms > 0
	if cfg == nil {
		return enforcement.Describe(layer1, true, true)
	}
	layer1 = layer1 && strings.TrimSpace(cfg.CgroupPath) != ""
	return enforcement.Describe(layer1, !cfg.LSMOnly, cfg.failClosed())
}

func statusFields(st enforcement.Status) map[string]any {
	return map[string]any{
		"enforcement":    st.Enforcement,
		"layer1":         st.Layer1,
		"layer2":         st.Layer2,
		"requireLSM":     st.RequireLSM,
		"allowProxyOnly": st.AllowProxyOnly,
	}
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
	logPolicyEvent("enforcement.level", statusFields(status))
	if strings.TrimSpace(dir) == "" {
		return
	}
	path := filepath.Join(dir, entrypoint.EnforcementReadyFileName)
	data, err := json.Marshal(status)
	if err != nil {
		data = []byte(`{"enforcement":"unknown"}`)
	}
	if err := writeFileAtomic(path, append(data, '\n'), 0o644); err != nil {
		log.Printf("Warning: failed to write enforcement-ready marker %s: %v", path, err)
	}
}

// writeFileAtomic writes via a temp file in the same directory and renames it
// into place, so a launcher polling for the marker's existence never reads a
// partially written document.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	fail := func(err error) error {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return fail(err)
	}
	if err := tmp.Chmod(perm); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}
