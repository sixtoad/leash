package lsm

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
)

// Audit-loss accounting (issue #241).
//
// Every LSM program decides first and records second, so enforcement never
// depends on the audit record. When the event ring buffer is full the record
// cannot be reserved; the program then increments a per-CPU counter in the
// object's audit_drops map (bpf/audit_drops.h). The event loop polls those
// counters and turns any increase into an audit.dropped record in the event
// log, a leashd log line, and the process-wide totals below, so an incomplete
// audit trail is never silent.
//
// Lossless audit (AuditConfig.Lossless, LEASH_AUDIT_LOSSLESS=1) is the opt-in
// posture for deployments where an unrecorded operation is worse than a
// refused one: the kernel then denies an operation whose record it cannot
// reserve. It is a run-time posture, not a Cedar construct: policy says what
// is allowed, the posture says what happens when the audit pipe is full.

const (
	auditDropsMapName   = "audit_drops"
	auditConfigMapName  = "audit_config"
	auditConfigLossless = uint32(1) // AUDIT_CONFIG_LOSSLESS

	// EnvAuditRingBufferKB sizes each LSM object's event ring buffer, in KiB.
	EnvAuditRingBufferKB = "LEASH_AUDIT_RINGBUF_KB"
	// EnvAuditLossless turns on the lossless audit posture.
	EnvAuditLossless = "LEASH_AUDIT_LOSSLESS"

	// DefaultAuditRingBufferBytes matches AUDIT_RINGBUF_DEFAULT_BYTES.
	DefaultAuditRingBufferBytes = 1 << 20
	minAuditRingBufferBytes     = 64 << 10
	maxAuditRingBufferBytes     = 256 << 20

	auditDropPollInterval = time.Second
)

// auditSlotKinds names the audit_drops slots of each object, keyed by its
// event ring buffer map. Keep in step with the AUDIT_SLOT_* defines.
var auditSlotKinds = map[string][]string{
	"events":         {"file.open", "file.mutation"},
	"exec_events":    {"proc.exec"},
	"connect_events": {"net.send", "net.socket"},
}

// AuditConfig is the audit posture the LSM objects load with.
type AuditConfig struct {
	// RingBufferBytes sizes each object's event ring buffer; 0 keeps the
	// object's default (DefaultAuditRingBufferBytes).
	RingBufferBytes uint32
	// Lossless denies an operation whose audit record cannot be written.
	Lossless bool
}

var (
	auditConfigMu sync.RWMutex
	auditConfig   AuditConfig
)

// SetAuditConfig sets the audit posture for every LSM object loaded after it.
func SetAuditConfig(cfg AuditConfig) error {
	if cfg.RingBufferBytes != 0 {
		if err := validateRingBufferBytes(cfg.RingBufferBytes); err != nil {
			return err
		}
	}
	auditConfigMu.Lock()
	auditConfig = cfg
	auditConfigMu.Unlock()
	return nil
}

// CurrentAuditConfig returns the audit posture in effect.
func CurrentAuditConfig() AuditConfig {
	auditConfigMu.RLock()
	defer auditConfigMu.RUnlock()
	return auditConfig
}

// ParseAuditRingBufferKB parses a ring buffer size in KiB (0 = default).
func ParseAuditRingBufferKB(v string) (uint32, error) {
	kb, err := strconv.ParseUint(strings.TrimSpace(v), 10, 32)
	if err != nil {
		return 0, fmt.Errorf("audit ring buffer size %q: want a size in KiB", v)
	}
	if kb == 0 {
		return 0, nil
	}
	if kb > maxAuditRingBufferBytes>>10 {
		return 0, fmt.Errorf("audit ring buffer size %d KiB exceeds the %d KiB maximum", kb, maxAuditRingBufferBytes>>10)
	}
	bytes := uint32(kb << 10)
	if err := validateRingBufferBytes(bytes); err != nil {
		return 0, err
	}
	return bytes, nil
}

func validateRingBufferBytes(n uint32) error {
	if n < minAuditRingBufferBytes || n > maxAuditRingBufferBytes {
		return fmt.Errorf("audit ring buffer size %d KiB is outside %d..%d KiB", n>>10, minAuditRingBufferBytes>>10, maxAuditRingBufferBytes>>10)
	}
	if n&(n-1) != 0 {
		return fmt.Errorf("audit ring buffer size %d KiB is not a power of two", n>>10)
	}
	if page := uint32(os.Getpagesize()); page > 0 && n%page != 0 {
		return fmt.Errorf("audit ring buffer size %d KiB is not a multiple of the %d-byte page size", n>>10, page)
	}
	return nil
}

// applyAuditSpec sizes the object's event ring buffer before load.
func applyAuditSpec(spec *ebpf.CollectionSpec, eventMap string) {
	size := CurrentAuditConfig().RingBufferBytes
	if size == 0 || spec == nil {
		return
	}
	if m, ok := spec.Maps[eventMap]; ok && m != nil {
		m.MaxEntries = size
	}
}

// applyAuditConfig writes the lossless flag into a loaded collection, before
// any program attaches. Lossless requested on an object without the config
// map is an error: the posture must never be silently absent.
func applyAuditConfig(coll *ebpf.Collection) error {
	if !CurrentAuditConfig().Lossless {
		return nil
	}
	m := coll.Maps[auditConfigMapName]
	if m == nil {
		return errors.New("lossless audit requested but the LSM object has no audit_config map")
	}
	key, val := uint32(0), auditConfigLossless
	if err := m.Put(&key, &val); err != nil {
		return fmt.Errorf("enable lossless audit: %w", err)
	}
	return nil
}

// Process-wide totals, for the enforcement marker and tests.
var (
	auditDropTotal atomic.Uint64
	auditDropMu    sync.Mutex
	auditDropKinds = map[string]uint64{}
	auditDropHook  func(total uint64)
)

// AuditRecordsDropped is the number of audit records the kernel could not
// write since this process started.
func AuditRecordsDropped() uint64 { return auditDropTotal.Load() }

// AuditRecordsDroppedByKind breaks AuditRecordsDropped down by record kind.
func AuditRecordsDroppedByKind() map[string]uint64 {
	auditDropMu.Lock()
	defer auditDropMu.Unlock()
	out := make(map[string]uint64, len(auditDropKinds))
	for k, v := range auditDropKinds {
		out[k] = v
	}
	return out
}

// SetAuditDropHook registers fn to run (off the event loop's critical path,
// but synchronously after the record is logged) whenever new drops are
// counted, with the new process-wide total.
func SetAuditDropHook(fn func(total uint64)) {
	auditDropMu.Lock()
	auditDropHook = fn
	auditDropMu.Unlock()
}

// auditDropReporter turns increases of one object's audit_drops counters into
// audit.dropped records.
type auditDropReporter struct {
	m      *ebpf.Map
	kinds  []string
	last   []uint64
	logger *SharedLogger
	next   time.Time
}

func newAuditDropReporter(coll *ebpf.Collection, eventMap string, logger *SharedLogger) *auditDropReporter {
	m := coll.Maps[auditDropsMapName]
	kinds := auditSlotKinds[eventMap]
	if m == nil || len(kinds) == 0 {
		return nil
	}
	return &auditDropReporter{m: m, kinds: kinds, last: make([]uint64, len(kinds)), logger: logger}
}

// maybePoll polls at most once per auditDropPollInterval.
func (r *auditDropReporter) maybePoll(now time.Time) {
	if r == nil || now.Before(r.next) {
		return
	}
	r.next = now.Add(auditDropPollInterval)
	r.poll()
}

// poll reads every slot and reports increases.
func (r *auditDropReporter) poll() {
	if r == nil {
		return
	}
	for slot, kind := range r.kinds {
		key := uint32(slot)
		var perCPU []uint64
		if err := r.m.Lookup(&key, &perCPU); err != nil {
			continue
		}
		var sum uint64
		for _, v := range perCPU {
			sum += v
		}
		if sum <= r.last[slot] {
			continue
		}
		delta := sum - r.last[slot]
		r.last[slot] = sum
		reportAuditDrops(r.logger, kind, delta, sum)
	}
}

func reportAuditDrops(logger *SharedLogger, kind string, delta, kindTotal uint64) {
	total := auditDropTotal.Add(delta)
	auditDropMu.Lock()
	auditDropKinds[kind] += delta
	hook := auditDropHook
	auditDropMu.Unlock()

	lossless := CurrentAuditConfig().Lossless
	line := fmt.Sprintf("time=%s event=audit.dropped kind=%s count=%d kind_total=%d total=%d lossless=%t",
		time.Now().Format(time.RFC3339), kind, delta, kindTotal, total, lossless)
	if logger != nil {
		_ = logger.Write(line)
	}
	consequence := "the operations were still decided by policy"
	if lossless {
		consequence = "lossless audit denied those operations"
	}
	fmt.Fprintf(os.Stderr, "leash: audit: %d %s record(s) dropped (ring buffer full; %d dropped in total); %s. Raise %s to enlarge the ring buffer.\n",
		delta, kind, total, consequence, EnvAuditRingBufferKB)
	if hook != nil {
		hook(total)
	}
}
