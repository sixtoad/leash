//go:build unix

package enforcerd

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeWorker speaks the worker side of the protocol over a pipe.
type fakeWorker struct {
	net.Conn          // the daemon's end
	peer     net.Conn // the worker's end
	mu       sync.Mutex
	reqs     []Request
	done     chan struct{}
	once     sync.Once
	// failAttach makes the attach result an error.
	failAttach string
	// dieBeforeAttach makes the worker exit without answering.
	dieBeforeAttach bool
}

func newFakeWorker() *fakeWorker {
	a, b := net.Pipe()
	return &fakeWorker{Conn: a, peer: b, done: make(chan struct{})}
}

func (w *fakeWorker) send(m Message) {
	m.V = ProtocolVersion
	data, _ := json.Marshal(m)
	_, _ = w.peer.Write(append(data, '\n'))
}

func (w *fakeWorker) run() {
	defer w.exit("")
	sc := bufio.NewScanner(w.peer)
	sc.Buffer(make([]byte, 64*1024), MaxLineBytes)
	for sc.Scan() {
		var r Request
		_ = json.Unmarshal(sc.Bytes(), &r)
		w.mu.Lock()
		w.reqs = append(w.reqs, r)
		w.mu.Unlock()
		switch r.Op {
		case OpAttach:
			if w.dieBeforeAttach {
				return
			}
			if w.failAttach != "" {
				w.send(Message{Type: TypeResult, Error: w.failAttach})
				return
			}
			w.send(Message{Type: TypeEvent, Line: "event=file.open path=/etc/x decision=denied"})
			w.send(Message{Type: TypeResult, OK: true, Programs: 3})
		case OpUpdate:
			w.send(Message{Type: TypeResult, OK: true})
		case OpDetach:
			w.send(Message{Type: TypeResult, OK: true})
			w.send(Message{Type: TypeEnded, Error: "detached by the client"})
			return
		}
	}
}

func (w *fakeWorker) exit(reason string) {
	w.once.Do(func() {
		if reason != "" {
			w.send(Message{Type: TypeEnded, Error: reason})
		}
		_ = w.peer.Close()
		close(w.done)
	})
}

func (w *fakeWorker) Kill()       { w.exit("killed") }
func (w *fakeWorker) Wait() error { <-w.done; return nil }
func (w *fakeWorker) requests() []Request {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]Request(nil), w.reqs...)
}

type fakeSystem struct {
	mu        sync.Mutex
	uid, pid  int
	cgroups   map[int]string // pid -> cgroup path relative to the root
	groups    map[int]bool
	validated []string
	workers   []*fakeWorker
	nextFail  string
	nextDie   bool
	audit     bytes.Buffer
}

func (f *fakeSystem) config() Config {
	return Config{
		Version:    "test",
		CgroupRoot: "/sys/fs/cgroup",
		PeerCred: func(net.Conn) (int, int, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			return f.uid, f.pid, nil
		},
		ProcCgroup: func(pid int) ([]byte, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			cg, ok := f.cgroups[pid]
			if !ok {
				return nil, errors.New("no such process")
			}
			return []byte("0::" + cg + "\n"), nil
		},
		ResolveOwner: func(uid int) (int, error) {
			if uid >= 100000 {
				return 1001, nil // a subordinate uid of 1001
			}
			return uid, nil
		},
		InGroup: func(uid int) (bool, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			return f.groups[uid], nil
		},
		ValidateCgroup: func(root string, owner int, path string, _ func(int) (int, error)) (uint64, error) {
			f.mu.Lock()
			f.validated = append(f.validated, path)
			f.mu.Unlock()
			if owner == 0 {
				return 0, errors.New("root does not need the enforcer daemon")
			}
			if !strings.HasPrefix(path, fmt.Sprintf("/sys/fs/cgroup/user.slice/user-%d.slice/user@%d.service/", owner, owner)) {
				return 0, errors.New("not inside your delegated cgroup subtree")
			}
			return 4242, nil
		},
		SpawnWorker: func(string) (Worker, error) {
			w := newFakeWorker()
			f.mu.Lock()
			w.failAttach, w.dieBeforeAttach = f.nextFail, f.nextDie
			f.nextFail, f.nextDie = "", false
			f.workers = append(f.workers, w)
			f.mu.Unlock()
			go w.run()
			return w, nil
		},
		LSMStatus: func() (string, string) { return "active", "" },
		Audit:     &syncWriter{w: &f.audit, mu: &f.mu},
		Limits:    Limits{MaxConns: 8, MaxConnsPerUID: 8, MaxSessions: 4, MaxSessionsPerUID: 2, RequestsPerSecond: 1000, RequestBurst: 1000, AttachTimeout: 5 * time.Second},
		Logf:      func(string, ...any) {},
	}
}

type syncWriter struct {
	w  *bytes.Buffer
	mu *sync.Mutex
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

const (
	userCg   = "/user.slice/user-1001.slice/user@1001.service/user.slice/libpod-leash.scope/container"
	targetCg = "/user.slice/user-1001.slice/user@1001.service/user.slice/libpod-target.scope/container"
)

func newTestServer(t *testing.T) (*Server, *fakeSystem) {
	t.Helper()
	f := &fakeSystem{uid: 1001, pid: 10, cgroups: map[int]string{10: userCg}, groups: map[int]bool{1001: true, 1002: true}}
	s, err := NewServer(f.config())
	if err != nil {
		t.Fatal(err)
	}
	return s, f
}

// dial connects a client to the server through a pipe, as (uid, pid).
func dial(t *testing.T, s *Server, f *fakeSystem, uid, pid int) (*Client, func() []string) {
	t.Helper()
	f.mu.Lock()
	f.uid, f.pid = uid, pid
	f.mu.Unlock()
	a, b := net.Pipe()
	done := make(chan struct{})
	go func() {
		close(done)
		s.handle(b)
	}()
	<-done
	var mu sync.Mutex
	var events []string
	c := NewClient(a, func(l string) { mu.Lock(); events = append(events, l); mu.Unlock() })
	c.timeout = 5 * time.Second
	t.Cleanup(func() { _ = c.Close() })
	return c, func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), events...) }
}

func (f *fakeSystem) auditText() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.audit.String()
}

func (f *fakeSystem) worker(i int) *fakeWorker {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.workers[i]
}

func (f *fakeSystem) workerCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.workers)
}

func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestStatusReportsCallerAndKernel(t *testing.T) {
	s, f := newTestServer(t)
	c, _ := dial(t, s, f, 1001, 10)
	st, err := c.Status()
	if err != nil {
		t.Fatal(err)
	}
	if st.UID != 1001 || st.BPFLSM != "active" || st.Protocol != ProtocolVersion || st.Sessions != 0 {
		t.Fatalf("status = %+v", st)
	}
}

func TestAttachUpdateDetachLifecycle(t *testing.T) {
	s, f := newTestServer(t)
	c, events := dial(t, s, f, 1001, 10)
	session, programs, err := c.Attach("/sys/fs/cgroup"+targetCg, "permit (principal, action, resource);", map[string][]string{"example.com": {"93.184.215.14"}})
	if err != nil {
		t.Fatal(err)
	}
	if session == "" || programs != 3 {
		t.Fatalf("attach = %q, %d", session, programs)
	}
	if s.Sessions() != 1 {
		t.Fatalf("sessions = %d", s.Sessions())
	}
	waitFor(t, func() bool { return len(events()) == 1 }, "the worker's event")
	if err := c.Update("forbid (principal, action, resource);", nil); err != nil {
		t.Fatal(err)
	}
	if err := c.Detach(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return c.Err() != nil }, "the session end")
	if !errors.Is(c.Err(), ErrSessionEnded) || !strings.Contains(c.Err().Error(), "detached by the client") {
		t.Fatalf("end reason = %v", c.Err())
	}
	waitFor(t, func() bool { return s.Sessions() == 0 }, "the session to be removed")

	reqs := f.worker(0).requests()
	if len(reqs) != 3 || reqs[0].Op != OpAttach || reqs[1].Op != OpUpdate || reqs[2].Op != OpDetach {
		t.Fatalf("worker requests = %+v", reqs)
	}
	if reqs[0].CgroupID != 4242 || reqs[0].Cgroup != "/sys/fs/cgroup"+targetCg || reqs[0].Hosts["example.com"][0] != "93.184.215.14" {
		t.Fatalf("attach forwarded = %+v", reqs[0])
	}
	audit := f.auditText()
	for _, want := range []string{`"event":"attach"`, `"result":"ok"`, `"event":"session-end"`, `"policySha256":"`} {
		if !strings.Contains(audit, want) {
			t.Errorf("audit log lacks %s:\n%s", want, audit)
		}
	}
	if strings.Contains(audit, "permit (principal") {
		t.Error("the audit log must record the policy hash, not its text")
	}
}

// The daemon sets the cgroup id it validated; a client cannot choose it.
func TestClientCannotChooseCgroupID(t *testing.T) {
	s, f := newTestServer(t)
	a, b := net.Pipe()
	go s.handle(b)
	sc := bufio.NewScanner(a)
	req, _ := json.Marshal(Request{V: 1, Op: OpAttach, Cgroup: "/sys/fs/cgroup" + targetCg, CgroupID: 1})
	_, _ = a.Write(append(req, '\n'))
	if !sc.Scan() {
		t.Fatal("no answer")
	}
	waitFor(t, func() bool { return f.workerCount() == 1 }, "a worker")
	waitFor(t, func() bool { return len(f.worker(0).requests()) == 1 }, "the forwarded attach")
	if got := f.worker(0).requests()[0].CgroupID; got != 4242 {
		t.Fatalf("worker got cgroup id %d, want the validated 4242", got)
	}
	_ = a.Close()
}

func TestRefusals(t *testing.T) {
	cases := []struct {
		name  string
		setup func(f *fakeSystem)
		uid   int
		pid   int
		cg    string
		want  string
	}{
		{"not in the leash group", nil, 1003, 10, targetCg, `not a member of the "leash" group`},
		{"unknown peer pid", nil, 1001, 0, targetCg, "peer pid unknown"},
		{"peer cgroup unreadable", nil, 1001, 99, targetCg, "cgroup of peer pid 99"},
		{"another user's cgroup", func(f *fakeSystem) { f.cgroups[20] = "/user.slice/user-1002.slice/session-1.scope" }, 1002, 20, targetCg, "not inside your delegated cgroup subtree"},
		{"root", func(f *fakeSystem) { f.groups[0] = true; f.cgroups[30] = "/user.slice/session-2.scope" }, 0, 30, targetCg, "root does not need"},
		{"caller inside the target", func(f *fakeSystem) { f.cgroups[40] = targetCg + "/sub" }, 1001, 40, targetCg, "inside the cgroup it asks to govern"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, f := newTestServer(t)
			if tc.setup != nil {
				tc.setup(f)
			}
			c, _ := dial(t, s, f, tc.uid, tc.pid)
			_, _, err := c.Attach("/sys/fs/cgroup"+tc.cg, "", nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("attach = %v, want an error containing %q", err, tc.want)
			}
			if f.workerCount() != 0 {
				t.Fatal("a refused attach must not start a worker")
			}
			if !strings.Contains(f.auditText(), `"result":"refused"`) {
				t.Fatalf("refusal not audited:\n%s", f.auditText())
			}
		})
	}
}

// A process inside a governed cgroup cannot use the daemon at all: not at
// connect, and not on a connection it opened before the session existed.
func TestGovernedWorkloadIsRefused(t *testing.T) {
	s, f := newTestServer(t)
	f.mu.Lock()
	f.cgroups[50] = "/user.slice/user-1001.slice/session-3.scope"
	f.mu.Unlock()
	early, _ := dial(t, s, f, 1001, 50)
	if _, err := early.Status(); err != nil {
		t.Fatal(err)
	}
	c, _ := dial(t, s, f, 1001, 10)
	if _, _, err := c.Attach("/sys/fs/cgroup"+targetCg, "", nil); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.cgroups[60] = targetCg + "/nested"
	f.cgroups[50] = targetCg // the early peer moved into the workload
	f.mu.Unlock()
	w, _ := dial(t, s, f, 1001, 60)
	if _, err := w.Status(); err == nil || !strings.Contains(err.Error(), "inside a governed workload") {
		t.Fatalf("workload connection: %v", err)
	}
	if _, err := early.Status(); err == nil || !strings.Contains(err.Error(), "inside a governed workload") {
		t.Fatalf("early connection after moving into the workload: %v", err)
	}
	// A subordinate uid of the owner inside the workload is refused the same way.
	w2, _ := dial(t, s, f, 165536, 60)
	if _, err := w2.Status(); err == nil || !strings.Contains(err.Error(), "inside a governed workload") {
		t.Fatalf("subordinate uid in the workload: %v", err)
	}
}

func TestOverlappingAndLimitedSessions(t *testing.T) {
	s, f := newTestServer(t)
	c1, _ := dial(t, s, f, 1001, 10)
	if _, _, err := c1.Attach("/sys/fs/cgroup"+targetCg, "", nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c1.Attach("/sys/fs/cgroup/user.slice/user-1001.slice/user@1001.service/user.slice/b.scope", "", nil); err == nil || !strings.Contains(err.Error(), "already carries session") {
		t.Fatalf("second attach on one connection: %v", err)
	}
	for _, cg := range []string{targetCg, targetCg + "/sub", filepath.Dir(targetCg)} {
		c, _ := dial(t, s, f, 1001, 10)
		if _, _, err := c.Attach("/sys/fs/cgroup"+cg, "", nil); err == nil || !strings.Contains(err.Error(), "overlaps") {
			t.Fatalf("attach %s overlapping a session: %v", cg, err)
		}
	}
	c2, _ := dial(t, s, f, 1001, 10)
	if _, _, err := c2.Attach("/sys/fs/cgroup/user.slice/user-1001.slice/user@1001.service/user.slice/b.scope/container", "", nil); err != nil {
		t.Fatal(err)
	}
	c3, _ := dial(t, s, f, 1001, 10)
	if _, _, err := c3.Attach("/sys/fs/cgroup/user.slice/user-1001.slice/user@1001.service/user.slice/c.scope/container", "", nil); err == nil || !strings.Contains(err.Error(), "too many sessions for uid 1001") {
		t.Fatalf("third session: %v", err)
	}
}

// A client that disconnects without detaching leaves the enforcement
// attached (fail closed) until the worker ends (its cgroup went away).
func TestDisconnectKeepsEnforcement(t *testing.T) {
	s, f := newTestServer(t)
	c, _ := dial(t, s, f, 1001, 10)
	if _, _, err := c.Attach("/sys/fs/cgroup"+targetCg, "", nil); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	time.Sleep(50 * time.Millisecond)
	if s.Sessions() != 1 {
		t.Fatalf("sessions after disconnect = %d, want 1 (enforcement kept)", s.Sessions())
	}
	waitFor(t, func() bool { return strings.Contains(f.auditText(), `"event":"disconnect"`) }, "the disconnect audit")
	f.worker(0).exit("the workload's cgroup was removed")
	waitFor(t, func() bool { return s.Sessions() == 0 }, "the session to end with its cgroup")
}

func TestWorkerFailures(t *testing.T) {
	s, f := newTestServer(t)
	f.nextFail = "an eBPF LSM program failed to attach"
	c, _ := dial(t, s, f, 1001, 10)
	if _, _, err := c.Attach("/sys/fs/cgroup"+targetCg, "", nil); err == nil || !strings.Contains(err.Error(), "failed to attach") {
		t.Fatalf("attach with a failing worker: %v", err)
	}
	waitFor(t, func() bool { return s.Sessions() == 0 }, "the failed session to go")

	f.nextDie = true
	c2, _ := dial(t, s, f, 1001, 10)
	if _, _, err := c2.Attach("/sys/fs/cgroup"+targetCg, "", nil); err == nil {
		t.Fatal("a worker that exits before attaching must fail the attach")
	}
	waitFor(t, func() bool { return c2.Err() != nil }, "the session end")
}

// Losing the session (the worker or the daemon went away) is reported to the
// client, which must fail closed.
func TestSessionLossIsReported(t *testing.T) {
	s, f := newTestServer(t)
	c, _ := dial(t, s, f, 1001, 10)
	if _, _, err := c.Attach("/sys/fs/cgroup"+targetCg, "", nil); err != nil {
		t.Fatal(err)
	}
	f.worker(0).exit("worker crashed")
	select {
	case <-c.Ended():
	case <-time.After(5 * time.Second):
		t.Fatal("session loss not reported")
	}
	if err := c.Update("", nil); err == nil {
		t.Fatal("update after the session ended must fail")
	}
}

func TestRequestValidation(t *testing.T) {
	big := strings.Repeat("x", MaxPolicyBytes+1)
	hosts := map[string][]string{}
	for i := 0; i <= MaxHosts; i++ {
		hosts[fmt.Sprintf("h%d.example", i)] = []string{"1.2.3.4"}
	}
	manyIPs := map[string][]string{"a.example": make([]string, MaxIPsPerHost+1)}
	for _, tc := range []struct {
		req  Request
		want string
	}{
		{Request{V: 2, Op: OpStatus}, "unsupported protocol version"},
		{Request{V: 1, Op: "grant"}, "unknown op"},
		{Request{V: 1, Op: OpAttach}, "cgroup is required"},
		{Request{V: 1, Op: OpUpdate, Policy: big}, "byte limit"},
		{Request{V: 1, Op: OpUpdate, Hosts: hosts}, "resolved hosts"},
		{Request{V: 1, Op: OpUpdate, Hosts: manyIPs}, "addresses"},
	} {
		if err := tc.req.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("Validate(%+v) = %v, want %q", tc.req.Op, err, tc.want)
		}
	}
}

func TestRateLimit(t *testing.T) {
	s, f := newTestServer(t)
	s.cfg.Limits.RequestsPerSecond, s.cfg.Limits.RequestBurst = 0.001, 2
	c, _ := dial(t, s, f, 1001, 10)
	for i := 0; i < 2; i++ {
		if _, err := c.Status(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.Status(); err == nil || !strings.Contains(err.Error(), "rate limited") {
		t.Fatalf("third request: %v", err)
	}
}

func TestConnectionLimits(t *testing.T) {
	s, f := newTestServer(t)
	s.cfg.Limits.MaxConnsPerUID = 4
	var cs []*Client
	for i := 0; i < 4; i++ {
		c, _ := dial(t, s, f, 1001, 10)
		if _, err := c.Status(); err != nil {
			t.Fatal(err)
		}
		cs = append(cs, c)
	}
	c, _ := dial(t, s, f, 1001, 10)
	if _, err := c.Status(); err == nil || !strings.Contains(err.Error(), "too many connections") {
		t.Fatalf("fifth connection: %v", err)
	}
	_ = cs
}
