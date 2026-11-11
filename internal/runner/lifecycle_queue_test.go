package runner

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type lifecycleBlockedWriter struct {
	bytes.Buffer
	entered, release chan struct{}
}

func (w *lifecycleBlockedWriter) Write(p []byte) (int, error) {
	select {
	case w.entered <- struct{}{}:
	default:
	}
	<-w.release
	return w.Buffer.Write(p)
}

func TestLifecycleBlockedWriterPreservesFinishResult(t *testing.T) {
	original := errors.New("original workload failure")
	for _, result := range []struct {
		code int
		err  error
	}{{0, nil}, {23, nil}, {0, original}} {
		w := &lifecycleBlockedWriter{entered: make(chan struct{}, 1), release: make(chan struct{})}
		sink := lifecycleTestSink(t, w)
		r := &runner{cfg: config{workDir: t.TempDir(), workDirIsTemp: true}, lifecycleTelemetry: sink}
		start := time.Now()
		err := r.finishLifecycle(context.Background(), result.code, result.err)
		elapsed := time.Since(start)
		// A second close must not restart the optional drain budget.
		second := time.Now()
		sink.finishAudit()
		repeated := time.Since(second)
		close(w.release)
		select {
		case <-sink.done:
		case <-time.After(2 * time.Second):
			t.Fatal("isolated writer did not retire after release")
		}
		if elapsed > 1500*time.Millisecond || repeated > 100*time.Millisecond {
			t.Fatalf("optional output stalled teardown: first=%v repeat=%v", elapsed, repeated)
		}
		if result.err != nil && err != result.err || result.code == 0 && result.err == nil && err != nil {
			t.Fatalf("original result changed: %v", err)
		}
		if result.code != 0 {
			var exit *ExitCodeError
			if !errors.As(err, &exit) || exit.code != result.code {
				t.Fatalf("exit changed: %v", err)
			}
		}
	}
}

func TestLifecycleQueuePressureAccountsSourceAndUnreadTail(t *testing.T) {
	w := &lifecycleBlockedWriter{entered: make(chan struct{}, 1), release: make(chan struct{})}
	sink := lifecycleTestSink(t, w)
	sink.queueLimit = 4096
	sink.phase("attach")(nil)
	<-w.entered
	line := `{"event":"deny","token":"tiny","path":"/work/main.go"}` + "\n"
	input := strings.Repeat(line, 1000)
	sink.readAudit(strings.NewReader(input), int64(len(input)))
	close(w.release)
	sink.finishAudit()
	var kept, lost int64
	for _, record := range lifecycleRecords(t, w.String()) {
		if record["type"] == "leash_audit" {
			kept += int64(len(line))
		}
		if record["type"] == "truncation" && record["file"] == "leash-audit.ndjson" {
			lost += int64(record["bytes_dropped"].(float64))
		}
	}
	if kept == 0 || lost == 0 || kept+lost != int64(len(input)) || strings.Contains(w.String(), "tiny") {
		t.Fatalf("queue accounting/privacy: kept=%d lost=%d input=%d", kept, lost, len(input))
	}
}

type lifecycleCountingWriter struct {
	bytes.Buffer
	writes int
}

func (w *lifecycleCountingWriter) Write(p []byte) (int, error) {
	w.writes++
	return w.Buffer.Write(p)
}

func TestLifecycleAuditReplayRetains17240Records(t *testing.T) {
	w := &lifecycleCountingWriter{}
	sink := lifecycleTestSink(t, w)
	line := "event=file.open decision=deny path=/work/source.go\n"
	input := strings.Repeat(line, 17240)
	sink.readAudit(strings.NewReader(input), int64(len(input)))
	sink.finishAudit()
	if records := lifecycleRecords(t, w.String()); len(records) != 17241 || records[len(records)-1]["type"] != "leash_export" || sink.dropped != 0 {
		t.Fatalf("incomplete normal replay: records=%d loss=%d", len(records), sink.dropped)
	}
	if w.writes >= 17240 {
		t.Fatalf("audit writes were not batched: %d", w.writes)
	}
}

func TestLifecycleDisabledEventsRetainExactLoss(t *testing.T) {
	var out bytes.Buffer
	sink := lifecycleTestSink(t, &out)
	sink.queueLimit = 1
	makeEvent := func() map[string]any {
		return map[string]any{"type": "phase", "name": "cleanup", "status": "ok"}
	}
	expected := int64(2 * len(sink.encode(makeEvent())))
	sink.emit(makeEvent(), 0)
	sink.emit(makeEvent(), 0)
	sink.exported = true
	sink.finishAudit()
	records := lifecycleRecords(t, out.String())
	terminal := records[len(records)-1]
	if terminal["status"] != "incomplete" || terminal["event_bytes_dropped"] != float64(expected) {
		t.Fatalf("rejected events not fully counted: %v; want %d bytes", terminal, expected)
	}
}
