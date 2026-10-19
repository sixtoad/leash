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

// endingConn is the client's side of a daemon that answers every request
// with a result immediately followed by the session's end. A request write
// returns only once the client has read both, so the result and the end are
// both pending when the client waits for its answer: the order the daemon
// sent them in must win, not a select's random pick.
type endingConn struct {
	net.Conn
	c *Client
}

func (e *endingConn) Write(p []byte) (int, error) {
	n, err := e.Conn.Write(p)
	if err != nil {
		return n, err
	}
	select {
	case <-e.c.Ended():
	case <-time.After(5 * time.Second):
	}
	return n, nil
}

func newEndingClient(t *testing.T, answer Message) *Client {
	t.Helper()
	a, b := net.Pipe()
	go func() {
		defer b.Close()
		sc := bufio.NewScanner(b)
		for sc.Scan() {
			for _, m := range []Message{answer, {Type: TypeEnded, Error: "the session worker exited"}} {
				m.V = ProtocolVersion
				data, _ := json.Marshal(m)
				if _, err := b.Write(append(data, '\n')); err != nil {
					return
				}
			}
		}
	}()
	e := &endingConn{Conn: a}
	c := NewClient(e, nil)
	e.c = c
	c.timeout = 5 * time.Second
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// A result the daemon sent before ending the session is the request's
// answer: a failed attach reports the worker's reason (not "session ended"),
// and a detach that succeeded (its worker then exits) is not an error.
func TestResultSentBeforeEndIsTheAnswer(t *testing.T) {
	for i := 0; i < 64; i++ {
		c := newEndingClient(t, Message{Type: TypeResult, Error: "an eBPF LSM program failed to attach"})
		if _, _, err := c.Attach("/sys/fs/cgroup/x", "", nil); err == nil || !strings.Contains(err.Error(), "failed to attach") {
			t.Fatalf("attach #%d: %v, want the worker's failure reason", i, err)
		}
		c = newEndingClient(t, Message{Type: TypeResult, OK: true})
		if err := c.Detach(); err != nil {
			t.Fatalf("detach #%d: %v, want success", i, err)
		}
	}
}
