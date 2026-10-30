package leashd

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/strongdm/leash/internal/enforcement"
	"github.com/strongdm/leash/internal/entrypoint"
	"github.com/strongdm/leash/internal/lsm"
)

// Readiness adapter for leashd. Both native and container launchers consume the
// same post-attach marker so neither can release a workload during LSM startup.

func enableEnforcementReady(cfg *runtimeConfig) {
	lsm.SetAuditDropHook(noteAuditDrops)
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
	fields := map[string]any{
		"enforcement": st.Enforcement,
		"layer1":      st.Layer1,
		"layer2":      st.Layer2,
		"requireLSM":  st.RequireLSM,
		"reason":      st.Reason,
	}
	if st.Audit != nil {
		fields["auditRingBufferBytes"] = st.Audit.RingBufferBytes
		fields["auditLossless"] = st.Audit.Lossless
		fields["auditDropped"] = st.Audit.Dropped
	}
	return fields
}

// auditMarker remembers the published enforcement status so audit drops
// counted later (issue #241) can be added to the marker: the marker then says
// whether the run's audit trail is complete, not only how it started.
var auditMarker struct {
	mu            sync.Mutex
	dir           string
	status        *enforcement.Status
	remoteDropped uint64 // drops reported by the enforcer daemon (rootless)
}

// withAuditStatus attaches the audit posture to a status whose Layer 1 is
// active (no LSM object is loaded otherwise).
func withAuditStatus(st enforcement.Status) enforcement.Status {
	if st.Layer1 != enforcement.LayerActive {
		return st
	}
	cfg := lsm.CurrentAuditConfig()
	size := cfg.RingBufferBytes
	if size == 0 {
		size = lsm.DefaultAuditRingBufferBytes
	}
	auditMarker.mu.Lock()
	dropped := lsm.AuditRecordsDropped() + auditMarker.remoteDropped
	auditMarker.mu.Unlock()
	st.Audit = &enforcement.AuditStatus{RingBufferBytes: size, Lossless: cfg.Lossless, Dropped: dropped}
	return st
}

// noteAuditDrops is the lsm audit-drop hook: it rewrites the marker with the
// new total. Before the marker is published there is nothing to update; the
// first write picks up the total itself.
func noteAuditDrops(uint64) {
	auditMarker.mu.Lock()
	defer auditMarker.mu.Unlock()
	if auditMarker.status == nil || auditMarker.status.Audit == nil {
		return
	}
	st := *auditMarker.status
	audit := *st.Audit
	audit.Dropped = lsm.AuditRecordsDropped() + auditMarker.remoteDropped
	st.Audit = &audit
	auditMarker.status = &st
	logPolicyEvent("audit.dropped", map[string]any{"dropped": audit.Dropped, "lossless": audit.Lossless})
	if strings.TrimSpace(auditMarker.dir) == "" {
		return
	}
	writeMarkerFile(auditMarker.dir, st)
}

// noteRemoteAuditLine counts the drops in an audit.dropped record relayed by
// the enforcer daemon, whose counters live in its worker process.
func noteRemoteAuditLine(line string) {
	if !strings.Contains(line, "event=audit.dropped ") {
		return
	}
	for _, field := range strings.Fields(line) {
		if v, ok := strings.CutPrefix(field, "count="); ok {
			n, err := strconv.ParseUint(v, 10, 64)
			if err != nil || n == 0 {
				return
			}
			auditMarker.mu.Lock()
			auditMarker.remoteDropped += n
			auditMarker.mu.Unlock()
			noteAuditDrops(0)
			return
		}
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
	status = withAuditStatus(status)
	auditMarker.mu.Lock()
	auditMarker.dir = dir
	published := status
	auditMarker.status = &published
	auditMarker.mu.Unlock()
	log.Printf("leash: effective enforcement: %s (layer1=%s layer2=%s requireLSM=%t)%s", status.Enforcement, status.Layer1, status.Layer2, status.RequireLSM, reasonNote(status.Reason))
	logPolicyEvent("enforcement.level", statusFields(status))
	if strings.TrimSpace(dir) == "" {
		return
	}
	writeMarkerFile(dir, status)
}

func writeMarkerFile(dir string, status enforcement.Status) {
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
