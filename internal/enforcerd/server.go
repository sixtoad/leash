//go:build unix

package enforcerd

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"path/filepath"
	"sync"
	"time"
)

// Worker is one session's worker process: it speaks the protocol on its
// ReadWriteCloser (attach first, then update/detach) and exits when the
// session ends.
type Worker interface {
	io.ReadWriteCloser
	// Kill stops the worker (its programs detach when it exits).
	Kill()
	// Wait returns when the worker has exited.
	Wait() error
}

// Limits bound what one caller can make the daemon do.
type Limits struct {
	MaxConns          int           // concurrent connections, all callers
	MaxConnsPerUID    int           // concurrent connections per caller
	MaxSessions       int           // attached sessions, all callers
	MaxSessionsPerUID int           // attached sessions per caller
	RequestsPerSecond float64       // per connection, token bucket refill
	RequestBurst      int           // per connection, token bucket size
	AttachTimeout     time.Duration // how long a worker may take to attach
}

// DefaultLimits are the daemon's limits.
var DefaultLimits = Limits{
	MaxConns:          256,
	MaxConnsPerUID:    32,
	MaxSessions:       128,
	MaxSessionsPerUID: 16,
	RequestsPerSecond: 5,
	RequestBurst:      20,
	AttachTimeout:     90 * time.Second,
}

// Config is the server's view of the system; every field that touches the
// system is replaceable so the authorization logic is testable without
// privilege.
type Config struct {
	Version    string
	CgroupRoot string
	// PeerCred returns the connecting process's uid and pid (SO_PEERCRED).
	PeerCred func(net.Conn) (uid, pid int, err error)
	// ProcCgroup reads /proc/<pid>/cgroup.
	ProcCgroup func(pid int) ([]byte, error)
	// ResolveOwner maps a peer uid to the account it belongs to (itself, or
	// the owner of the subordinate uid range it falls in).
	ResolveOwner func(uid int) (int, error)
	// InGroup reports whether an account is a member of GroupName.
	InGroup func(uid int) (bool, error)
	// ValidateCgroup checks that owner may target a cgroup and returns its id
	// (resolve maps a uid to its owning account, as ResolveOwner).
	ValidateCgroup func(root string, owner int, path string, resolve func(int) (int, error)) (uint64, error)
	// SpawnWorker starts a session worker.
	SpawnWorker func(session string) (Worker, error)
	// LSMStatus reports whether "bpf" is an active LSM.
	LSMStatus func() (state, reason string)
	// Audit receives one JSON line per security-relevant event.
	Audit  io.Writer
	Limits Limits
	Logf   func(format string, args ...any)
}

// Server is the daemon.
type Server struct {
	cfg      Config
	mu       sync.Mutex
	conns    int
	connsBy  map[int]int
	sessions map[string]*session
	auditMu  sync.Mutex
}

type session struct {
	id     string
	peer   peer
	owner  int
	cgroup string
	worker Worker
}

// NewServer validates cfg and returns a server.
func NewServer(cfg Config) (*Server, error) {
	if cfg.PeerCred == nil || cfg.ProcCgroup == nil || cfg.ResolveOwner == nil || cfg.InGroup == nil || cfg.SpawnWorker == nil {
		return nil, errors.New("enforcerd: incomplete server configuration")
	}
	if cfg.CgroupRoot == "" {
		cfg.CgroupRoot = CgroupRoot
	}
	if cfg.ValidateCgroup == nil {
		cfg.ValidateCgroup = ValidateTargetCgroup
	}
	if cfg.LSMStatus == nil {
		cfg.LSMStatus = func() (string, string) { return "unknown", "" }
	}
	if cfg.Limits == (Limits{}) {
		cfg.Limits = DefaultLimits
	}
	if cfg.Audit == nil {
		cfg.Audit = io.Discard
	}
	if cfg.Logf == nil {
		cfg.Logf = log.Printf
	}
	return &Server{cfg: cfg, connsBy: map[int]int{}, sessions: map[string]*session{}}, nil
}

// Serve accepts connections until ln is closed.
func (s *Server) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			return err
		}
		go s.handle(conn)
	}
}

// Sessions returns the number of attached sessions.
func (s *Server) Sessions() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

// KillAll stops every session's worker (daemon shutdown).
func (s *Server) KillAll() {
	s.mu.Lock()
	var ws []Worker
	for _, se := range s.sessions {
		ws = append(ws, se.worker)
	}
	s.mu.Unlock()
	for _, w := range ws {
		w.Kill()
	}
}

type auditRecord struct {
	Time       string `json:"time"`
	Event      string `json:"event"`
	PeerUID    int    `json:"peerUid"`
	Owner      int    `json:"owner,omitempty"`
	PeerPID    int    `json:"peerPid"`
	PeerCgroup string `json:"peerCgroup,omitempty"`
	Op         string `json:"op,omitempty"`
	Cgroup     string `json:"cgroup,omitempty"`
	Session    string `json:"session,omitempty"`
	PolicySHA  string `json:"policySha256,omitempty"`
	Hosts      int    `json:"hosts,omitempty"`
	Result     string `json:"result"`
	Reason     string `json:"reason,omitempty"`
}

func (s *Server) audit(r auditRecord) {
	r.Time = time.Now().UTC().Format(time.RFC3339Nano)
	data, _ := json.Marshal(r)
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	_, _ = s.cfg.Audit.Write(append(data, '\n'))
	s.cfg.Logf("audit %s", data)
}

// peer is an authenticated connection.
type peer struct {
	uid, pid, owner int
	cgroup          string // absolute cgroup directory of the peer process
}

// clientConn is a client connection with one writer goroutine fed by a
// queue, so a slow client never stalls the session relay: enforcement events
// are dropped (and counted) when the queue is full; results and the session
// end are never dropped while the connection is open.
type clientConn struct {
	net.Conn
	q         chan Message
	done      chan struct{}
	closeOnce sync.Once
	mu        sync.Mutex
	dropped   int
}

const clientQueue = 4096

func newClientConn(raw net.Conn) *clientConn {
	c := &clientConn{Conn: raw, q: make(chan Message, clientQueue), done: make(chan struct{})}
	go c.writer()
	return c
}

func (c *clientConn) writer() {
	for {
		select {
		case <-c.done:
			return
		case m := <-c.q:
			c.mu.Lock()
			dropped := c.dropped
			c.dropped = 0
			c.mu.Unlock()
			if dropped > 0 && !c.write(Message{Type: TypeEvent, Line: fmt.Sprintf("leash-enforcerd: %d enforcement event(s) dropped: the client did not keep up (enforcement is unaffected)", dropped)}) {
				return
			}
			if !c.write(m) {
				return
			}
		}
	}
}

func (c *clientConn) write(m Message) bool {
	m.V = ProtocolVersion
	data, err := json.Marshal(m)
	if err != nil {
		return true
	}
	_ = c.SetWriteDeadline(time.Now().Add(30 * time.Second))
	if _, err := c.Write(append(data, '\n')); err != nil {
		c.markClosed()
		return false
	}
	return true
}

func (c *clientConn) send(m Message) {
	if m.Type == TypeEvent {
		select {
		case c.q <- m:
		case <-c.done:
		default:
			c.mu.Lock()
			c.dropped++
			c.mu.Unlock()
		}
		return
	}
	select {
	case c.q <- m:
	case <-c.done:
	}
}

// flush waits (bounded) until queued messages are written, so a refusal
// reaches the client before the connection closes.
func (c *clientConn) flush() {
	deadline := time.Now().Add(5 * time.Second)
	for len(c.q) > 0 && time.Now().Before(deadline) {
		select {
		case <-c.done:
			return
		case <-time.After(10 * time.Millisecond):
		}
	}
	time.Sleep(10 * time.Millisecond)
}

func (c *clientConn) markClosed() {
	c.closeOnce.Do(func() { close(c.done) })
}

// peerCgroup returns the absolute cgroup directory of pid.
func (s *Server) peerCgroup(pid int) (string, error) {
	data, err := s.cfg.ProcCgroup(pid)
	if err != nil {
		return "", err
	}
	rel, err := procCgroupPath(data)
	if err != nil {
		return "", err
	}
	return filepath.Join(s.cfg.CgroupRoot, rel), nil
}

// governedBy returns the session whose cgroup contains dir, if any.
func (s *Server) governedBy(dir string) *session {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, se := range s.sessions {
		if within(dir, se.cgroup) {
			return se
		}
	}
	return nil
}

func (s *Server) authenticate(conn net.Conn) (peer, error) {
	uid, pid, err := s.cfg.PeerCred(conn)
	if err != nil {
		return peer{uid: -1}, fmt.Errorf("cannot read peer credentials: %v", err)
	}
	p := peer{uid: uid, pid: pid, owner: -1}
	if pid <= 0 {
		return p, errors.New("peer pid unknown (the caller is outside the daemon's pid namespace)")
	}
	owner, err := s.cfg.ResolveOwner(uid)
	if err != nil {
		return p, err
	}
	p.owner = owner
	ok, err := s.cfg.InGroup(owner)
	if err != nil {
		return p, fmt.Errorf("group membership of uid %d: %v", owner, err)
	}
	if !ok {
		return p, fmt.Errorf("uid %d is not a member of the %q group (sudo usermod -aG %s <user>, then log in again)", owner, GroupName, GroupName)
	}
	cg, err := s.peerCgroup(pid)
	if err != nil {
		return p, fmt.Errorf("cgroup of peer pid %d: %v", pid, err)
	}
	p.cgroup = cg
	if se := s.governedBy(cg); se != nil {
		return p, fmt.Errorf("connection from inside a governed workload (cgroup %s, session %s) refused", cg, se.id)
	}
	return p, nil
}

func (s *Server) acquireConn(owner int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conns >= s.cfg.Limits.MaxConns {
		return errors.New("too many connections")
	}
	if s.connsBy[owner] >= s.cfg.Limits.MaxConnsPerUID {
		return fmt.Errorf("too many connections for uid %d", owner)
	}
	s.conns++
	s.connsBy[owner]++
	return nil
}

func (s *Server) releaseConn(owner int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.conns--
	if s.connsBy[owner]--; s.connsBy[owner] <= 0 {
		delete(s.connsBy, owner)
	}
}

type bucket struct {
	tokens float64
	last   time.Time
	rate   float64
	burst  float64
}

func (b *bucket) allow(now time.Time) bool {
	if b.last.IsZero() {
		b.last = now
		b.tokens = b.burst
	}
	b.tokens += now.Sub(b.last).Seconds() * b.rate
	if b.tokens > b.burst {
		b.tokens = b.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (s *Server) handle(raw net.Conn) {
	c := newClientConn(raw)
	defer func() {
		c.flush()
		c.markClosed()
		_ = raw.Close()
	}()
	p, err := s.authenticate(raw)
	if err != nil {
		s.audit(auditRecord{Event: "connect", PeerUID: p.uid, Owner: p.owner, PeerPID: p.pid, PeerCgroup: p.cgroup, Result: "refused", Reason: err.Error()})
		c.send(Message{Type: TypeResult, Error: "enforcer daemon: " + err.Error()})
		return
	}
	if err := s.acquireConn(p.owner); err != nil {
		s.audit(auditRecord{Event: "connect", PeerUID: p.uid, Owner: p.owner, PeerPID: p.pid, PeerCgroup: p.cgroup, Result: "refused", Reason: err.Error()})
		c.send(Message{Type: TypeResult, Error: "enforcer daemon: " + err.Error()})
		return
	}
	defer s.releaseConn(p.owner)

	var sess *session
	detachRequested := false
	rate := &bucket{rate: s.cfg.Limits.RequestsPerSecond, burst: float64(s.cfg.Limits.RequestBurst)}
	sc := bufio.NewScanner(raw)
	sc.Buffer(make([]byte, 64*1024), MaxLineBytes)
	for sc.Scan() {
		var req Request
		rec := auditRecord{Event: "request", PeerUID: p.uid, Owner: p.owner, PeerPID: p.pid, PeerCgroup: p.cgroup}
		if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
			rec.Result, rec.Reason = "refused", "malformed request"
			s.audit(rec)
			c.send(Message{Type: TypeResult, Error: "malformed request"})
			return
		}
		rec.Op, rec.Cgroup = req.Op, req.Cgroup
		if req.Policy != "" {
			sum := sha256.Sum256([]byte(req.Policy))
			rec.PolicySHA = hex.EncodeToString(sum[:])
		}
		rec.Hosts = len(req.Hosts)
		if sess != nil {
			rec.Session = sess.id
		}
		refuse := func(msg string) {
			rec.Result, rec.Reason = "refused", msg
			s.audit(rec)
			c.send(Message{Type: TypeResult, Error: msg})
		}
		if !rate.allow(time.Now()) {
			refuse("rate limited")
			continue
		}
		// Re-check on every request: a connection opened before a session
		// existed, or by a process that later moved into a governed cgroup,
		// must not act from inside a governed workload.
		if cg, err := s.peerCgroup(p.pid); err != nil {
			refuse(fmt.Sprintf("cgroup of peer pid %d: %v", p.pid, err))
			return
		} else if se := s.governedBy(cg); se != nil {
			refuse(fmt.Sprintf("request from inside a governed workload (cgroup %s, session %s) refused", cg, se.id))
			return
		}
		if err := req.Validate(); err != nil {
			refuse(err.Error())
			continue
		}
		switch req.Op {
		case OpStatus:
			state, reason := s.cfg.LSMStatus()
			n := 0
			s.mu.Lock()
			for _, se := range s.sessions {
				if se.owner == p.owner {
					n++
				}
			}
			s.mu.Unlock()
			rec.Result = "ok"
			s.audit(rec)
			c.send(Message{Type: TypeResult, OK: true, Status: &Status{Version: s.cfg.Version, Protocol: ProtocolVersion, BPFLSM: state, BPFLSMReason: reason, UID: p.owner, Sessions: n}})
		case OpAttach:
			if sess != nil {
				refuse("this connection already carries session " + sess.id)
				continue
			}
			se, err := s.attach(p, req, c)
			if err != nil {
				refuse(err.Error())
				continue
			}
			sess = se
			rec.Session, rec.Result = se.id, "forwarded"
			s.audit(rec)
		case OpUpdate, OpDetach:
			if sess == nil {
				refuse("no session is attached on this connection")
				continue
			}
			fwd := Request{V: ProtocolVersion, Op: req.Op, Policy: req.Policy, Hosts: req.Hosts}
			if err := writeJSONLine(sess.worker, fwd); err != nil {
				refuse("session worker is gone: " + err.Error())
				continue
			}
			rec.Result = "forwarded"
			s.audit(rec)
			if req.Op == OpDetach {
				detachRequested = true
			}
		}
	}
	if sess != nil && !detachRequested {
		s.audit(auditRecord{Event: "disconnect", PeerUID: p.uid, Owner: p.owner, PeerPID: p.pid, Session: sess.id, Cgroup: sess.cgroup, Result: "kept", Reason: "client disconnected without detaching: enforcement stays attached until the cgroup empties or is removed"})
	}
}

func writeJSONLine(w io.Writer, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = w.Write(append(data, '\n'))
	return err
}

func newSessionID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// attach validates the request, registers the session and starts its worker.
// The worker's messages are relayed to the client by a goroutine; the attach
// result is the worker's first message.
func (s *Server) attach(p peer, req Request, c *clientConn) (*session, error) {
	target := filepath.Clean(req.Cgroup)
	if within(p.cgroup, target) {
		return nil, fmt.Errorf("the caller (pid %d) is inside the cgroup it asks to govern", p.pid)
	}
	id, err := s.cfg.ValidateCgroup(s.cfg.CgroupRoot, p.owner, target, s.cfg.ResolveOwner)
	if err != nil {
		return nil, err
	}
	se := &session{id: newSessionID(), peer: p, owner: p.owner, cgroup: target}
	s.mu.Lock()
	if len(s.sessions) >= s.cfg.Limits.MaxSessions {
		s.mu.Unlock()
		return nil, errors.New("too many sessions")
	}
	n := 0
	for _, other := range s.sessions {
		if other.owner == p.owner {
			n++
		}
		if within(target, other.cgroup) || within(other.cgroup, target) {
			s.mu.Unlock()
			return nil, fmt.Errorf("cgroup %s overlaps the governed cgroup of session %s", target, other.id)
		}
	}
	if n >= s.cfg.Limits.MaxSessionsPerUID {
		s.mu.Unlock()
		return nil, fmt.Errorf("too many sessions for uid %d", p.owner)
	}
	s.sessions[se.id] = se
	s.mu.Unlock()

	w, err := s.cfg.SpawnWorker(se.id)
	if err != nil {
		s.removeSession(se.id)
		return nil, fmt.Errorf("start session worker: %v", err)
	}
	se.worker = w
	fwd := Request{V: ProtocolVersion, Op: OpAttach, Cgroup: target, CgroupID: id, Policy: req.Policy, Hosts: req.Hosts}
	if err := writeJSONLine(w, fwd); err != nil {
		w.Kill()
		_ = w.Wait()
		s.removeSession(se.id)
		return nil, fmt.Errorf("start session worker: %v", err)
	}
	attached := make(chan struct{})
	go s.relay(se, c, attached)
	go func() {
		select {
		case <-attached:
		case <-time.After(s.cfg.Limits.AttachTimeout):
			s.cfg.Logf("session %s: worker did not attach within %s; stopping it", se.id, s.cfg.Limits.AttachTimeout)
			w.Kill()
		}
	}()
	return se, nil
}

func (s *Server) removeSession(id string) {
	s.mu.Lock()
	delete(s.sessions, id)
	s.mu.Unlock()
}

// relay forwards a worker's messages to the session's client until the worker
// exits, then ends the session.
func (s *Server) relay(se *session, c *clientConn, attached chan struct{}) {
	sc := bufio.NewScanner(se.worker)
	sc.Buffer(make([]byte, 64*1024), MaxLineBytes)
	first := true
	var reason string
	for sc.Scan() {
		var m Message
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			reason = "malformed message from the session worker"
			break
		}
		if first && m.Type == TypeResult {
			first = false
			close(attached)
			res := "ok"
			if !m.OK {
				res = "failed"
			}
			s.audit(auditRecord{Event: "attach", PeerUID: se.peer.uid, Owner: se.owner, PeerPID: se.peer.pid, PeerCgroup: se.peer.cgroup, Session: se.id, Cgroup: se.cgroup, Result: res, Reason: m.Error})
			m.Session = se.id
		}
		if m.Type == TypeEnded {
			reason = m.Error
			continue
		}
		c.send(m)
	}
	se.worker.Kill()
	_ = se.worker.Wait()
	_ = se.worker.Close()
	if first {
		close(attached)
		if reason == "" {
			reason = "the session worker exited before attaching"
		}
		c.send(Message{Type: TypeResult, Error: reason})
	}
	if reason == "" {
		reason = "the session worker exited"
	}
	s.removeSession(se.id)
	s.audit(auditRecord{Event: "session-end", PeerUID: se.peer.uid, Owner: se.owner, PeerPID: se.peer.pid, Session: se.id, Cgroup: se.cgroup, Result: "detached", Reason: reason})
	c.send(Message{Type: TypeEnded, Error: reason})
}
