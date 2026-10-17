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
			lsmState, lsmReason := enforcement.ClassifyLSMList(readActiveLSMList())
			st := effectiveEnforcement(cfg, lsm.Layer1Degraded(), lsm.Layer1AttachedPrograms(), lsmState, lsmReason)
			// Never publish the release marker unless Layer 1 is active (no
			// scopable cgroup, an attach failure, no program attached, or bpf
			// not an active LSM). Exiting without the marker keeps every
			// launcher's existence gate closed.
			if err := st.Check(); err != nil {
				fmt.Fprintf(os.Stderr, "leash: FATAL: %v\n", err)
				logPolicyEvent("enforcement.level", statusFields(st))
				os.Exit(1)
			}
			writeEnforcementReadyMarker(getLeashDirFromEnv(), st)
		})
	})
}

// readActiveLSMList reads the kernel's active-LSM list. In container mode the
// leash sidecar mounts securityfs itself (see configureNetwork), so this reads
// the host kernel's list; a read failure is treated as "not confirmed" and
// fails closed under the default posture. Tests substitute a fake.
var readActiveLSMList = func() ([]byte, error) { return os.ReadFile(enforcement.ActiveLSMPath) }

// effectiveEnforcement states the enforcement level once every LSM attach has
// settled. Layer 1 counts as active only with a scopable cgroup, no attach
// failure, at least one attached program AND "bpf" confirmed in the kernel's
// active-LSM list — attach success alone proves nothing (CONFIG_BPF_LSM=y with
// bpf inactive attaches programs that are never invoked). Layer 2 is off in
// --lsm-only mode.
func effectiveEnforcement(cfg *runtimeConfig, layer1Degraded bool, attachedPrograms int, lsmState enforcement.LSMListState, lsmReason string) enforcement.Status {
	reason := ""
	switch {
	case cfg != nil && strings.TrimSpace(cfg.CgroupPath) == "":
		reason = "no scopable cgroup for the workload, so eBPF LSM enforcement cannot be scoped to it"
	case layer1Degraded:
		reason = "an eBPF LSM program failed to attach (see the leashd log)"
	case attachedPrograms <= 0:
		reason = "no eBPF LSM program is attached"
	case lsmState != enforcement.LSMListActive:
		reason = lsmReason
		if reason == "" {
			reason = "the bpf LSM could not be confirmed active"
		}
	}
	layer1 := reason == ""
	st := enforcement.Describe(layer1, cfg == nil || !cfg.LSMOnly)
	st.Reason = reason
	return st
}

func statusFields(st enforcement.Status) map[string]any {
	return map[string]any{
		"enforcement": st.Enforcement,
		"layer1":      st.Layer1,
		"layer2":      st.Layer2,
		"requireLSM":  st.RequireLSM,
		"reason":      st.Reason,
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
	log.Printf("leash: effective enforcement: %s (layer1=%s layer2=%s requireLSM=%t)%s", status.Enforcement, status.Layer1, status.Layer2, status.RequireLSM, reasonNote(status.Reason))
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

func reasonNote(reason string) string {
	if reason == "" {
		return ""
	}
	return ": " + reason
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
