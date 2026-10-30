//go:build unix

package enforcerd

import (
	"bufio"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"
)

// answeringClient is a client whose daemon answers every request with
// result and hands each request to seen.
func answeringClient(t *testing.T, result Message, seen chan<- Request) *Client {
	t.Helper()
	a, b := net.Pipe()
	go func() {
		defer b.Close()
		sc := bufio.NewScanner(b)
		for sc.Scan() {
			var req Request
			_ = json.Unmarshal(sc.Bytes(), &req)
			select {
			case seen <- req:
			default:
			}
			m := result
			m.V = ProtocolVersion
			data, _ := json.Marshal(m)
			if _, err := b.Write(append(data, '\n')); err != nil {
				return
			}
		}
	}()
	c := NewClient(a, nil)
	c.timeout = 5 * time.Second
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// The audit posture travels with the attach, and lossless audit that the
// daemon does not confirm (an older daemon ignores the field) is refused:
// the posture must never be silently absent (#241).
func TestAttachCarriesAuditPosture(t *testing.T) {
	seen := make(chan Request, 4)
	c := answeringClient(t, Message{Type: TypeResult, OK: true, Programs: 3, AuditLossless: true}, seen)
	c.SetAudit(4096, true)
	if _, programs, err := c.Attach("/sys/fs/cgroup/x", "", nil); err != nil || programs != 3 {
		t.Fatalf("attach with confirmed lossless audit: programs=%d err=%v", programs, err)
	}
	req := <-seen
	if req.Op != OpAttach || req.AuditRingBufferKB != 4096 || !req.AuditLossless {
		t.Fatalf("attach request = %+v, want the audit posture", req)
	}

	c = answeringClient(t, Message{Type: TypeResult, OK: true, Programs: 3}, nil)
	c.SetAudit(0, true)
	_, _, err := c.Attach("/sys/fs/cgroup/x", "", nil)
	if err == nil || !strings.Contains(err.Error(), "lossless audit") {
		t.Fatalf("attach without lossless confirmation: %v, want a refusal", err)
	}

	c = answeringClient(t, Message{Type: TypeResult, OK: true, Programs: 3}, nil)
	if _, _, err := c.Attach("/sys/fs/cgroup/x", "", nil); err != nil {
		t.Fatalf("attach without lossless audit: %v", err)
	}
}
