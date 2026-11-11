package runner

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const lifecycleSchema = "warren.run-telemetry/v1"
const lifecycleDefaultCap int64 = 256 << 20
const lifecycleLossReserve int64 = 2048
const lifecycleSecretEnv = "LEASH_TELEMETRY_SECRET_VALUES"
const lifecyclePipeEnv = "LEASH_TELEMETRY_PIPE"

type lifecycleTelemetry struct {
	mu                   sync.Mutex
	out                  io.Writer
	run                  string
	redactor             *lifecycleRedactor
	limit, used, dropped int64
	eventDropped         int64
	disabled, exported   bool
	queue                []lifecycleRecord
	pendingBytes         int64
	queueLimit           int64
	wake, closing, done  chan struct{}
	finishing, expired   bool
	writeFailed          bool
	unavailable          bool
	closeOutput          func() error
}

func (r *runner) initLifecycleTelemetry() {
	if r.lifecycleInitialized {
		return
	}
	r.lifecycleInitialized = true
	// This host-only input must never be inherited by plugins or workloads.
	extra := os.Getenv(lifecycleSecretEnv)
	pipePath := os.Getenv(lifecyclePipeEnv)
	_ = os.Unsetenv(lifecycleSecretEnv)
	_ = os.Unsetenv(lifecyclePipeEnv)
	_ = os.Unsetenv("LEASH_TELEMETRY_FD")
	filtered := r.opts.envVars[:0]
	for _, item := range r.opts.envVars {
		key, _, _ := strings.Cut(item, "=")
		if key != lifecycleSecretEnv && key != lifecyclePipeEnv && key != "LEASH_TELEMETRY_FD" {
			filtered = append(filtered, item)
		}
	}
	r.opts.envVars = filtered
	if os.Getenv("LEASH_TELEMETRY_RUN_ID") == "" {
		return
	}
	out, err := openLifecycleOutput(pipePath)
	if err != nil {
		return // optional output never falls back to the workload's stderr
	}
	t, err := newLifecycleTelemetry(out, extra)
	if err != nil {
		_ = out.Close()
		return
	}
	t.closeOutput = out.Close
	r.lifecycleTelemetry = t
}

func newLifecycleTelemetry(out io.Writer, extra string) (*lifecycleTelemetry, error) {
	limit := lifecycleDefaultCap
	if raw := os.Getenv("LEASH_TELEMETRY_MAX_FILE_BYTES"); raw != "" {
		value, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || value < 4096 {
			return nil, fmt.Errorf("invalid telemetry cap")
		}
		limit = value
	}
	id := os.Getenv("LEASH_TELEMETRY_RUN_ID")
	if len(id) > 256 {
		return nil, fmt.Errorf("invalid telemetry identity")
	}
	redactor, err := newLifecycleRedactor(extra)
	if err != nil {
		return nil, err
	}
	t := &lifecycleTelemetry{out: out, run: redactor.text(id), redactor: redactor, limit: limit,
		queueLimit: lifecycleQueueBytes, wake: make(chan struct{}, 1), closing: make(chan struct{}), done: make(chan struct{})}
	go t.outputLoop()
	return t, nil
}

func (t *lifecycleTelemetry) phase(name string) func(error) {
	start := time.Now()
	return func(err error) {
		end, status := time.Now(), "ok"
		if err != nil {
			status = "error"
		}
		t.emit(map[string]any{"type": "phase", "name": name, "start": lifecycleTime(start),
			"end": lifecycleTime(end), "duration_ms": end.Sub(start).Milliseconds(), "status": status}, 0)
	}
}

func lifecycleTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

func (t *lifecycleTelemetry) encode(record map[string]any) []byte {
	record["schema"], record["source"], record["run"] = lifecycleSchema, "leash", t.run
	record["agent"], record["dispatch_id"] = nil, nil
	record["timestamp"] = lifecycleTime(time.Now())
	data, _ := json.Marshal(record) // callers supply only scalars and redacted strings
	return append(data, '\n')
}

// sourceBytes counts discarded audit bytes, independently of JSON escaping.
func (t *lifecycleTelemetry) emit(record map[string]any, sourceBytes int64) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.disabled {
		if sourceBytes == 0 {
			t.eventDropped += int64(len(t.encode(record)))
		} else {
			t.dropped += sourceBytes
		}
		return false
	}
	data := t.encode(record)
	if t.used+int64(len(data)) > t.limit-lifecycleLossReserve {
		if sourceBytes == 0 {
			t.eventDropped += int64(len(data))
		} else {
			t.dropped += sourceBytes
		}
		return false
	}
	item := lifecycleRecord{data: data, sourceBytes: sourceBytes}
	if t.finishing || t.pendingBytes+int64(len(data)) > t.queueLimit {
		t.dropRecord(item)
		t.disabled = true
		return false
	}
	t.queue = append(t.queue, item)
	t.used += int64(len(data))
	t.pendingBytes += int64(len(data))
	t.notify()
	return true
}

func (t *lifecycleTelemetry) loss(n int64) {
	t.mu.Lock()
	t.dropped += n
	t.mu.Unlock()
}

func (t *lifecycleTelemetry) finishAudit() {
	t.mu.Lock()
	if t.expired {
		t.mu.Unlock()
		return
	}
	if !t.finishing {
		t.finishing = true
		close(t.closing)
	}
	t.mu.Unlock()
	timer := time.NewTimer(lifecycleDrainTimeout)
	defer timer.Stop()
	select {
	case <-t.done:
	case <-timer.C:
		t.mu.Lock()
		t.expired, t.disabled = true, true
		t.dropQueue()
		t.mu.Unlock()
	}
}

// Called only by the output worker, after it has accounted for all queued
// writes. A stalled in-flight write is unconfirmed until that write returns.
func (t *lifecycleTelemetry) lossFooter() []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	var footer []byte
	for _, loss := range []struct {
		file, location string
		bytes          int64
	}{
		{"leash-audit.ndjson", "audit_export", t.dropped},
		{"leash-events.ndjson", "record_limit", t.eventDropped},
	} {
		if loss.bytes == 0 {
			continue
		}
		data := t.encode(map[string]any{"type": "truncation", "file": loss.file,
			"bytes_dropped": loss.bytes, "location": loss.location, "status": "truncated"})
		if t.used+int64(len(data)) <= t.limit {
			footer = append(footer, data...)
			t.used += int64(len(data))
		}
	}
	status := "complete"
	if !t.exported || t.unavailable || t.dropped != 0 || t.eventDropped != 0 || t.expired || t.writeFailed {
		status = "incomplete"
	}
	end := t.encode(map[string]any{"type": "leash_export", "status": status,
		"source_bytes_dropped": t.dropped, "event_bytes_dropped": t.eventDropped})
	if t.used+int64(len(end)) <= t.limit {
		footer = append(footer, end...)
		t.used += int64(len(end))
	}
	return footer
}
