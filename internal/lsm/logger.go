package lsm

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// logSyncDelay bounds how long a written audit line may sit in the page cache
// before it is fsynced. Syncing on every line (the old behaviour) put a disk
// flush on the eBPF event loop's critical path: on a loaded host each record
// cost milliseconds, the reader fell behind, and the kernel ring buffer
// overflowed and dropped records (issue #241). Readers of the log never need
// the sync -- a written line is visible immediately -- it only bounds what a
// power loss can take.
const logSyncDelay = 200 * time.Millisecond

// LogBroadcaster is an interface for broadcasting log entries
type LogBroadcaster interface {
	BroadcastLog(logEntry string)
}

// SharedLogger provides a single append-only log file with cross-component synchronization.
type SharedLogger struct {
	path        string
	file        *os.File
	mutex       sync.Mutex
	broadcaster LogBroadcaster
	syncPending bool // a deferred fsync is scheduled
}

func NewSharedLogger(path string) (*SharedLogger, error) {
	logger := &SharedLogger{path: path}
	if strings.TrimSpace(path) == "" {
		return logger, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file '%s': %w", path, err)
	}
	logger.file = f
	return logger, nil
}

func (l *SharedLogger) Path() string { return l.path }

// SetBroadcaster sets the log broadcaster for real-time log streaming
func (l *SharedLogger) SetBroadcaster(broadcaster LogBroadcaster) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.broadcaster = broadcaster
}

// Write writes a full log entry line in a thread-safe way.
// Automatically adds a newline if the entry doesn't end with one.
func (l *SharedLogger) Write(entry string) error {
	if l == nil {
		return fmt.Errorf("logger is not initialized")
	}
	l.mutex.Lock()
	defer l.mutex.Unlock()

	// Ensure entry ends with newline
	if len(entry) > 0 && entry[len(entry)-1] != '\n' {
		entry += "\n"
	}

	// Write to file when configured
	if l.file != nil {
		if _, err := l.file.WriteString(entry); err != nil {
			return err
		}
	}

	// Broadcast to websocket clients (if broadcaster is set)
	if l.broadcaster != nil {
		// Remove the newline for broadcasting
		broadcastEntry := entry
		if len(broadcastEntry) > 0 && broadcastEntry[len(broadcastEntry)-1] == '\n' {
			broadcastEntry = broadcastEntry[:len(broadcastEntry)-1]
		}
		l.broadcaster.BroadcastLog(broadcastEntry)
	}

	if l.file != nil && !l.syncPending {
		l.syncPending = true
		time.AfterFunc(logSyncDelay, l.syncDeferred)
	}
	return nil
}

// syncDeferred flushes the file outside the mutex, so writers are never held
// behind a disk flush.
func (l *SharedLogger) syncDeferred() {
	l.mutex.Lock()
	f := l.file
	l.syncPending = false
	l.mutex.Unlock()
	if f != nil {
		_ = f.Sync()
	}
}

func (l *SharedLogger) Close() error {
	if l == nil {
		return nil
	}
	l.mutex.Lock()
	f := l.file
	l.file = nil
	l.mutex.Unlock()
	if f == nil {
		return nil
	}
	_ = f.Sync()
	return f.Close()
}
