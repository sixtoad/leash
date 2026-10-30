package lsm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseAuditRingBufferKB(t *testing.T) {
	cases := []struct {
		in   string
		want uint32
		ok   bool
	}{
		{"0", 0, true},
		{"64", 64 << 10, true},
		{"1024", 1 << 20, true},
		{" 4096 ", 4 << 20, true},
		{"262144", 256 << 20, true},
		{"32", 0, false},     // below the minimum
		{"100", 0, false},    // not a power of two
		{"524288", 0, false}, // above the maximum
		{"-1", 0, false},     // not a size
		{"1MiB", 0, false},   // not a number of KiB
		{"99999999999", 0, false},
	}
	for _, tc := range cases {
		got, err := ParseAuditRingBufferKB(tc.in)
		if (err == nil) != tc.ok || got != tc.want {
			t.Errorf("ParseAuditRingBufferKB(%q) = %d, %v; want %d ok=%v", tc.in, got, err, tc.want, tc.ok)
		}
	}
}

// A counted drop becomes an audit.dropped record, the process totals and a
// hook call: audit loss is never silent (#241).
func TestReportAuditDrops(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "events.log")
	logger, err := NewSharedLogger(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()

	var hooked uint64
	SetAuditDropHook(func(total uint64) { hooked = total })
	defer SetAuditDropHook(nil)

	before := AuditRecordsDropped()
	beforeKind := AuditRecordsDroppedByKind()["file.open"]
	reportAuditDrops(logger, "file.open", 7, 7)
	reportAuditDrops(logger, "file.open", 3, 10)

	if got := AuditRecordsDropped() - before; got != 10 {
		t.Fatalf("AuditRecordsDropped grew by %d, want 10", got)
	}
	if got := AuditRecordsDroppedByKind()["file.open"] - beforeKind; got != 10 {
		t.Fatalf("file.open drops grew by %d, want 10", got)
	}
	if hooked != before+10 {
		t.Fatalf("hook saw total %d, want %d", hooked, before+10)
	}
	data, _ := os.ReadFile(logPath)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 ||
		!strings.Contains(lines[0], "event=audit.dropped kind=file.open count=7 kind_total=7") ||
		!strings.Contains(lines[1], "event=audit.dropped kind=file.open count=3 kind_total=10") {
		t.Fatalf("audit.dropped records = %q", lines)
	}
}

// Writes are visible at once and the file is synced off the write path,
// so a slow disk never stalls the eBPF event loop (#241).
func TestSharedLoggerDefersSync(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "events.log")
	logger, err := NewSharedLogger(logPath)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		if err := logger.Write("event=x"); err != nil {
			t.Fatal(err)
		}
	}
	data, _ := os.ReadFile(logPath)
	if n := strings.Count(string(data), "event=x\n"); n != 100 {
		t.Fatalf("%d lines visible right after writing, want 100", n)
	}
	logger.mutex.Lock()
	pending := logger.syncPending
	logger.mutex.Unlock()
	if !pending {
		t.Fatal("a deferred sync must be scheduled after a write")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		logger.mutex.Lock()
		pending = logger.syncPending
		logger.mutex.Unlock()
		if !pending {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("deferred sync never ran")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := logger.Close(); err != nil {
		t.Fatal(err)
	}
	if err := logger.Write("event=late"); err != nil {
		t.Fatalf("write after close: %v", err)
	}
}
