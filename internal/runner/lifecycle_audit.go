package runner

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const lifecycleMaxLine = 4 << 20
const lifecycleExportTimeout = 30 * time.Second

func (r *runner) exportLifecycleAudit() {
	t := r.lifecycleTelemetry
	if t == nil {
		return
	}
	t.mu.Lock()
	if t.exported {
		t.mu.Unlock()
		return
	}
	t.exported = true
	t.mu.Unlock()
	defer t.finishAudit()
	path := filepath.Join(r.cfg.logDir, "events.log")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		t.auditError("audit_source_unavailable")
		return
	}
	f, err := openLifecycleAudit(path, info)
	if err != nil {
		t.auditError("audit_source_unreadable")
		return
	}
	defer f.Close()
	// Snapshot the size: kept containers or failed teardown may still append.
	// Export is bounded even if the legacy audit producer is still running.
	t.readAudit(io.LimitReader(f, info.Size()), info.Size())
}

func (t *lifecycleTelemetry) auditError(reason string) {
	t.mu.Lock()
	t.unavailable = true
	t.mu.Unlock()
	t.emit(map[string]any{"type": "error", "status": "unavailable", "file": "leash-audit.ndjson", "reason": reason}, 0)
}

func (t *lifecycleTelemetry) readAudit(source io.Reader, size int64) {
	deadline := time.Now().Add(lifecycleExportTimeout)
	reader := bufio.NewReaderSize(source, 64<<10)
	var line []byte
	var offset, consumed, lineBytes int64
	oversized, privateKey := false, false
	for consumed < size {
		// Bound scanning as well as retained output. Never publish a partial line.
		if consumed >= t.limit || !t.accepting() || time.Now().After(deadline) {
			t.loss(size - offset)
			return
		}
		part, err := reader.ReadSlice('\n')
		consumed += int64(len(part))
		lineBytes += int64(len(part))
		if !oversized && len(line)+len(part) <= lifecycleMaxLine {
			line = append(line, part...)
		} else {
			oversized = true
			line = nil
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if len(part) == 0 || part[len(part)-1] != '\n' {
			// A snapshot can end inside a secret while its producer is still
			// writing. Withhold that whole record instead of scrubbing a prefix.
			t.loss(size - offset)
			if err != nil && !errors.Is(err, io.EOF) {
				t.auditError("audit_read_failed")
			}
			return
		}
		if oversized {
			t.loss(lineBytes)
			// A withheld line may begin a private key: suppress following lines
			// until a key terminator, rather than risk exporting its body.
			privateKey = true
		} else {
			text := string(line)
			begin := strings.Contains(text, "-----BEGIN ") && strings.Contains(text, "PRIVATE KEY-----")
			end := strings.Contains(text, "-----END ") && strings.Contains(text, "PRIVATE KEY-----")
			if privateKey || begin {
				text = lifecycleRedacted
			}
			privateKey = (privateKey || begin) && !end
			record := map[string]any{"type": "leash_audit", "source_offset_bytes": offset}
			var payload any
			if json.Unmarshal([]byte(text), &payload) == nil {
				record["payload"] = t.redactor.scrub(payload)
			} else {
				record["message"] = t.redactor.text(strings.TrimSuffix(text, "\n"))
			}
			if !t.emit(record, lineBytes) {
				t.loss(size - consumed)
				return
			}
		}
		offset, lineBytes, line, oversized = consumed, 0, nil, false
		if err != nil {
			if !errors.Is(err, io.EOF) {
				t.auditError("audit_read_failed")
			}
			return
		}
	}
}
