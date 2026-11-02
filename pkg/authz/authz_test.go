package authz

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// fakeServer accepts connections on a Unix socket and hands each one, with
// its 1-based index, to handle.
type fakeServer struct {
	path  string
	ln    net.Listener
	conns atomic.Int32
}

func startFake(t *testing.T, handle func(n int, conn net.Conn, rd *bufio.Reader)) *fakeServer {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "lzc") // short path for sun_path on macOS
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	fs := &fakeServer{path: filepath.Join(dir, "authz.sock")}
	fs.ln, err = net.Listen("unix", fs.path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fs.ln.Close() })
	go func() {
		for {
			conn, err := fs.ln.Accept()
			if err != nil {
				return
			}
			n := int(fs.conns.Add(1))
			go func() {
				defer func() { _ = conn.Close() }()
				handle(n, conn, bufio.NewReader(conn))
			}()
		}
	}()
	return fs
}

// answer reads one request and replies with decision and reason, echoing the
// request id. It reports false if no request arrived.
func answer(conn net.Conn, rd *bufio.Reader, decision, reason string) bool {
	line, err := rd.ReadBytes('\n')
	if err != nil {
		return false
	}
	var req Request
	if json.Unmarshal(line, &req) != nil {
		return false
	}
	out, _ := json.Marshal(Response{V: ProtocolVersion, ID: req.ID, Decision: decision, Reason: reason})
	_, err = conn.Write(append(out, '\n'))
	return err == nil
}

func testReq() Request {
	return Request{Action: UID("Secret::Action", "Read"), Resource: UID("Secret::Item", "gemini")}
}

// A kept connection that the server closed while idle (e.g. a leashd
// restart) is retried once on a fresh dial, and the answer comes from the
// fresh connection.
func TestCheckRetriesOnceWhenReusedConnectionWasClosed(t *testing.T) {
	firstClosed := make(chan struct{})
	fs := startFake(t, func(n int, conn net.Conn, rd *bufio.Reader) {
		if n == 1 {
			answer(conn, rd, DecisionAllow, ReasonMatchedPermit)
			_ = conn.Close()
			close(firstClosed)
			return
		}
		for answer(conn, rd, DecisionDeny, ReasonMatchedForbid) {
		}
	})
	c := New(fs.path, WithTimeout(2*time.Second))
	defer func() { _ = c.Close() }()
	ctx := context.Background()

	if d := c.Check(ctx, testReq()); !d.Allowed() || d.Reason != ReasonMatchedPermit {
		t.Fatalf("first check: %+v", d)
	}
	<-firstClosed
	time.Sleep(20 * time.Millisecond) // let the close reach the client's socket
	req := testReq()
	req.ID = "second"
	d := c.Check(ctx, req)
	if d.Err != nil {
		t.Fatalf("second check on a server-closed connection was not retried: %v", d.Err)
	}
	if d.Allowed() || d.Decision != DecisionDeny || d.Reason != ReasonMatchedForbid || d.ID != "second" {
		t.Fatalf("second check: want the fresh connection's deny, got %+v", d)
	}
	if n := fs.conns.Load(); n != 2 {
		t.Fatalf("connections: got %d, want 2", n)
	}
	// The fresh connection is kept for later checks.
	if d := c.Check(ctx, testReq()); d.Err != nil || d.Reason != ReasonMatchedForbid {
		t.Fatalf("third check: %+v", d)
	}
	if n := fs.conns.Load(); n != 2 {
		t.Fatalf("connections after third check: got %d, want 2", n)
	}
}

// A failure on a freshly dialed connection is not retried: the server
// closing a brand-new connection is an answer, not a stale connection.
func TestCheckDoesNotRetryAFreshConnection(t *testing.T) {
	fs := startFake(t, func(n int, conn net.Conn, rd *bufio.Reader) {
		if n == 1 {
			_, _ = rd.ReadBytes('\n')
			return // close without answering
		}
		for answer(conn, rd, DecisionAllow, ReasonMatchedPermit) {
		}
	})
	c := New(fs.path, WithTimeout(2*time.Second))
	defer func() { _ = c.Close() }()
	d := c.Check(context.Background(), testReq())
	if d.Err == nil || d.Allowed() {
		t.Fatalf("fresh connection closed by the server must fail closed without a retry, got %+v", d)
	}
}

// A reused connection that dies after part of the reply arrived is not
// retried: the server had started answering.
func TestCheckDoesNotRetryAfterPartialReply(t *testing.T) {
	fs := startFake(t, func(n int, conn net.Conn, rd *bufio.Reader) {
		if n == 1 {
			answer(conn, rd, DecisionAllow, ReasonMatchedPermit)
			if _, err := rd.ReadBytes('\n'); err == nil {
				_, _ = conn.Write([]byte(`{"v":1,"id":`))
			}
			return
		}
		for answer(conn, rd, DecisionAllow, ReasonMatchedPermit) {
		}
	})
	c := New(fs.path, WithTimeout(2*time.Second))
	defer func() { _ = c.Close() }()
	ctx := context.Background()
	if d := c.Check(ctx, testReq()); !d.Allowed() {
		t.Fatalf("first check: %+v", d)
	}
	if d := c.Check(ctx, testReq()); d.Err == nil || d.Allowed() {
		t.Fatalf("partial reply must fail closed without a retry, got %+v", d)
	}
	if n := fs.conns.Load(); n != 1 {
		t.Fatalf("connections: got %d, want 1 (no retry)", n)
	}
}
