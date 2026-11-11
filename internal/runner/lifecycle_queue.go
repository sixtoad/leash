package runner

import (
	"bytes"
	"time"
)

const lifecycleQueueBytes int64 = 64 << 20
const lifecycleBatchBytes = 256 << 10
const lifecycleBatchRecords = 512
const lifecycleDrainTimeout = time.Second

type lifecycleRecord struct {
	data        []byte
	sourceBytes int64
}

// Queue state is protected by mu, but the optional worker never holds it
// across I/O. There is one worker, including after a timed-out close.
func (t *lifecycleTelemetry) notify() {
	select {
	case t.wake <- struct{}{}:
	default:
	}
}

func (t *lifecycleTelemetry) dropRecord(record lifecycleRecord) {
	if record.sourceBytes != 0 {
		t.dropped += record.sourceBytes
	} else {
		t.eventDropped += int64(len(record.data))
	}
}

func (t *lifecycleTelemetry) dropQueue() {
	for _, record := range t.queue {
		t.dropRecord(record)
		t.pendingBytes -= int64(len(record.data))
	}
	t.queue = nil
}

func (t *lifecycleTelemetry) accepting() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return !t.disabled && !t.finishing
}

func (t *lifecycleTelemetry) takeBatch() ([]lifecycleRecord, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	n, size := 0, 0
	for n < len(t.queue) && n < lifecycleBatchRecords {
		if n > 0 && size+len(t.queue[n].data) > lifecycleBatchBytes {
			break
		}
		size += len(t.queue[n].data)
		n++
	}
	batch := append([]lifecycleRecord(nil), t.queue[:n]...)
	clear(t.queue[:n])
	t.queue = t.queue[n:]
	return batch, t.finishing
}

func (t *lifecycleTelemetry) outputLoop() {
	defer close(t.done)
	defer func() {
		if t.closeOutput != nil {
			_ = t.closeOutput()
		}
	}()
	for {
		select {
		case <-t.wake:
		case <-t.closing:
		}
		t.mu.Lock()
		coalesce := !t.finishing && t.pendingBytes < lifecycleBatchBytes && len(t.queue) < lifecycleBatchRecords
		t.mu.Unlock()
		if coalesce {
			timer := time.NewTimer(25 * time.Millisecond)
			select {
			case <-timer.C:
			case <-t.closing:
			}
			timer.Stop()
		}
		batch, finishing := t.takeBatch()
		if len(batch) == 0 {
			if finishing {
				t.writeFooter()
				return
			}
			continue
		}
		var buf bytes.Buffer
		for _, record := range batch {
			buf.Write(record.data)
		}
		n, err := t.out.Write(buf.Bytes()) // deliberately outside every state lock
		t.mu.Lock()
		offset := 0
		for _, record := range batch {
			offset += len(record.data)
			t.pendingBytes -= int64(len(record.data))
			if offset > n {
				// A partial record is unusable, so count its entire source record.
				t.dropRecord(record)
			}
		}
		failed := err != nil || n != buf.Len()
		if failed {
			t.disabled, t.writeFailed = true, true
			t.dropQueue()
		}
		more := len(t.queue) > 0
		t.mu.Unlock()
		if failed {
			// Never warn through shared stderr. Walk detects the missing terminal
			// marker and records incomplete delivery on its independent sink.
			return
		}
		if more {
			t.notify()
		}
	}
}

func (t *lifecycleTelemetry) writeFooter() {
	if data := t.lossFooter(); len(data) != 0 {
		n, err := t.out.Write(data)
		if err != nil || n != len(data) {
			t.mu.Lock()
			t.disabled, t.writeFailed = true, true
			t.mu.Unlock()
		}
	}
}
