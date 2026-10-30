// Package authz serves Leash's plugin authorization socket (#142): one
// private Unix socket per authz-enabled --inject-service plugin, answering
// protocol v1 requests (pkg/authz) from the same engine the proxy
// enforces with: the Cedar engine published by policy.Decisions.
package authz

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/strongdm/leash/internal/engine"
	"github.com/strongdm/leash/internal/lsm"
	"github.com/strongdm/leash/internal/policy"
	wire "github.com/strongdm/leash/pkg/authz"
)

// EnvPlugins carries the plugin grants from the runner to leashd as JSON.
const EnvPlugins = "LEASH_AUTHZ_PLUGINS"

// BuiltinNamespace is the grant that lets a plugin query Leash's own actions
// (Action::"McpCall", Action::"NetworkConnect", ...).
const BuiltinNamespace = engine.BuiltinActionType

// PrincipalType is the entity type of every authz principal.
const PrincipalType = "Plugin"

// Server limits.
const (
	MaxConnsPerPlugin = 16
	RatePerSecond     = 200
	RateBurst         = 400
	IdleTimeout       = 2 * time.Minute
)

// PluginGrant is one authz-enabled plugin, as the runner describes it.
type PluginGrant struct {
	ID         string   `json:"id"`
	Socket     string   `json:"socket"`
	UID        int      `json:"uid"`
	Namespaces []string `json:"namespaces"`
}

var (
	pluginIDRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	namespaceRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(::[A-Za-z_][A-Za-z0-9_]*)*$`)
)

// ValidatePluginID reports whether id is an acceptable plugin identity.
func ValidatePluginID(id string) error {
	if !pluginIDRe.MatchString(id) {
		return fmt.Errorf("authz plugin id %q: want 1-64 of [A-Za-z0-9._-], starting alphanumeric", id)
	}
	return nil
}

// ValidateNamespace reports whether ns is a Cedar namespace path.
func ValidateNamespace(ns string) error {
	if !namespaceRe.MatchString(ns) {
		return fmt.Errorf("authz namespace %q is not a Cedar namespace (e.g. Secret or Walk::Secret)", ns)
	}
	return nil
}

// ParseGrants decodes and validates the EnvPlugins payload.
func ParseGrants(raw string) ([]PluginGrant, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var grants []PluginGrant
	if err := json.Unmarshal([]byte(raw), &grants); err != nil {
		return nil, fmt.Errorf("%s: %w", EnvPlugins, err)
	}
	seenID, seenSock := map[string]bool{}, map[string]bool{}
	for _, g := range grants {
		if err := ValidatePluginID(g.ID); err != nil {
			return nil, err
		}
		if !filepath.IsAbs(g.Socket) || filepath.Clean(g.Socket) != g.Socket {
			return nil, fmt.Errorf("authz plugin %q: socket %q must be a clean absolute path", g.ID, g.Socket)
		}
		if len(g.Namespaces) == 0 {
			return nil, fmt.Errorf("authz plugin %q: no namespaces granted", g.ID)
		}
		for _, ns := range g.Namespaces {
			if err := ValidateNamespace(ns); err != nil {
				return nil, err
			}
		}
		if seenID[g.ID] || seenSock[g.Socket] {
			return nil, fmt.Errorf("authz plugin %q: duplicate id or socket", g.ID)
		}
		seenID[g.ID], seenSock[g.Socket] = true, true
	}
	return grants, nil
}

// Source returns the current decision snapshot (nil before a policy loads).
type Source func() *policy.DecisionSnapshot

// Config configures a Server.
type Config struct {
	Grants []PluginGrant
	Source Source
	// Logger receives one event=authz.decision line per decision.
	Logger *lsm.SharedLogger
	// BoxCgroup is the workload's cgroup directory (e.g.
	// /sys/fs/cgroup/leash/box). A peer whose process lives in it, or below
	// it, is the workload and is refused. Empty disables the check.
	BoxCgroup string
	// Now is the clock for rate limiting (tests).
	Now func() time.Time
	// ProcCgroup reads /proc/<pid>/cgroup; nil uses the real file (tests override it).
	ProcCgroup func(pid int) ([]byte, error)
}

// Server is the authz socket service.
type Server struct {
	cfg       Config
	mu        sync.Mutex
	listeners []net.Listener
	conns     map[net.Conn]struct{}
	wg        sync.WaitGroup
	closed    bool
}

// New returns a server; Start binds the sockets.
func New(cfg Config) *Server {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.ProcCgroup == nil {
		cfg.ProcCgroup = readProcCgroup
	}
	return &Server{cfg: cfg, conns: map[net.Conn]struct{}{}}
}

// Start binds one socket per grant and serves it. A socket that cannot be
// bound is reported in the returned error; the others keep serving, and the
// plugin whose socket failed fails closed in its client.
func (s *Server) Start() error {
	var errs []error
	for _, g := range s.cfg.Grants {
		ln, err := listen(g)
		if err != nil {
			errs = append(errs, fmt.Errorf("authz plugin %q: %w", g.ID, err))
			continue
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			_ = ln.Close()
			break
		}
		s.listeners = append(s.listeners, ln)
		s.mu.Unlock()
		p := newPluginState(g, s.cfg.Now)
		s.wg.Add(1)
		go s.accept(ln, p)
	}
	return errors.Join(errs...)
}

// Close stops every listener and connection and removes the sockets.
func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	lns := s.listeners
	s.listeners = nil
	for c := range s.conns {
		_ = c.Close()
	}
	s.mu.Unlock()
	for _, ln := range lns {
		_ = ln.Close()
	}
	s.wg.Wait()
	for _, g := range s.cfg.Grants {
		removeSocket(g.Socket)
	}
	return nil
}

func removeSocket(path string) {
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSocket != 0 {
		_ = os.Remove(path)
	}
}

func listen(g PluginGrant) (net.Listener, error) {
	dir := filepath.Dir(g.Socket)
	if fi, err := os.Lstat(dir); err != nil || !fi.IsDir() {
		return nil, fmt.Errorf("socket directory %s is missing or not a directory", dir)
	}
	// Refuse to clobber anything but a stale socket.
	if fi, err := os.Lstat(g.Socket); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("refusing to replace %s: exists and is not a socket", g.Socket)
		}
		if err := os.Remove(g.Socket); err != nil {
			return nil, err
		}
	}
	ln, err := net.Listen("unix", g.Socket)
	if err != nil {
		return nil, err
	}
	if ul, ok := ln.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(true)
	}
	if err := os.Chmod(g.Socket, 0o600); err != nil {
		_ = ln.Close()
		return nil, err
	}
	if g.UID >= 0 && g.UID != os.Getuid() {
		if err := chownSocket(g.Socket, g.UID); err != nil {
			_ = ln.Close()
			return nil, err
		}
	}
	return ln, nil
}

// chownSocket is overridable for tests (which cannot chown as non-root).
var chownSocket = func(path string, uid int) error { return os.Chown(path, uid, -1) }

// pluginState is the per-plugin identity, grants, limiter and connection count.
type pluginState struct {
	grant      PluginGrant
	principal  engine.EntityUID
	namespaces map[string]bool

	mu     sync.Mutex
	conns  int
	tokens float64
	last   time.Time
	now    func() time.Time
}

func newPluginState(g PluginGrant, now func() time.Time) *pluginState {
	p := &pluginState{
		grant:      g,
		principal:  engine.EntityUID{Type: PrincipalType, ID: g.ID},
		namespaces: map[string]bool{},
		tokens:     RateBurst,
		last:       now(),
		now:        now,
	}
	for _, ns := range g.Namespaces {
		p.namespaces[ns] = true
	}
	return p
}

func (p *pluginState) acquireConn() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.conns >= MaxConnsPerPlugin {
		return false
	}
	p.conns++
	return true
}

func (p *pluginState) releaseConn() {
	p.mu.Lock()
	p.conns--
	p.mu.Unlock()
}

// allow takes one token from the plugin's bucket.
func (p *pluginState) allow() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	p.tokens += now.Sub(p.last).Seconds() * RatePerSecond
	if p.tokens > RateBurst {
		p.tokens = RateBurst
	}
	p.last = now
	if p.tokens < 1 {
		return false
	}
	p.tokens--
	return true
}

func (s *Server) accept(ln net.Listener, p *pluginState) {
	defer s.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("authz: accept for %s: %v", p.grant.ID, err)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if err := s.authenticate(conn, p); err != nil {
			s.audit(p, nil, wire.Response{Decision: wire.DecisionDeny, Reason: "peer_rejected", Error: err.Error()}, 0)
			_ = conn.Close()
			continue
		}
		if !p.acquireConn() {
			_ = conn.Close()
			continue
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			p.releaseConn()
			_ = conn.Close()
			return
		}
		s.conns[conn] = struct{}{}
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer p.releaseConn()
			defer func() {
				s.mu.Lock()
				delete(s.conns, conn)
				s.mu.Unlock()
				_ = conn.Close()
			}()
			s.serve(conn, p)
		}()
	}
}

// authenticate checks the peer: same uid as the plugin (or root), and not a
// process of the workload's cgroup.
func (s *Server) authenticate(conn net.Conn, p *pluginState) error {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return errors.New("not a unix connection")
	}
	cred, err := peerCredentials(uc)
	if err != nil {
		return fmt.Errorf("peer credentials: %w", err)
	}
	if cred.UID != 0 && p.grant.UID >= 0 && cred.UID != p.grant.UID {
		return fmt.Errorf("peer uid %d is not the plugin's uid %d", cred.UID, p.grant.UID)
	}
	if s.cfg.BoxCgroup != "" && cred.PID > 0 {
		inBox, err := pidInCgroup(s.cfg.ProcCgroup, cred.PID, s.cfg.BoxCgroup)
		if err != nil {
			return fmt.Errorf("peer pid %d: %w", cred.PID, err)
		}
		if inBox {
			return fmt.Errorf("peer pid %d belongs to the workload cgroup", cred.PID)
		}
	}
	return nil
}

// Credentials of a socket peer. PID is 0 when unknown (e.g. the peer lives
// outside this process's pid namespace).
type Credentials struct {
	UID int
	PID int
}

// PeerCredentials returns a Unix socket peer's credentials (SO_PEERCRED on
// Linux, LOCAL_PEERCRED on macOS). The enforcer daemon (internal/enforcerd)
// authenticates its callers with the same check.
func PeerCredentials(conn *net.UnixConn) (Credentials, error) { return peerCredentials(conn) }

func readProcCgroup(pid int) ([]byte, error) {
	return os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cgroup"))
}

// pidInCgroup reports whether pid's cgroup v2 path is boxDir or below it.
// boxDir is a cgroupfs directory (/sys/fs/cgroup/...).
func pidInCgroup(read func(int) ([]byte, error), pid int, boxDir string) (bool, error) {
	data, err := read(pid)
	if err != nil {
		return false, err
	}
	rel := "/" + strings.Trim(strings.TrimPrefix(filepath.Clean(boxDir), "/sys/fs/cgroup"), "/")
	for _, line := range strings.Split(string(data), "\n") {
		path, ok := strings.CutPrefix(line, "0::")
		if !ok {
			continue
		}
		path = strings.TrimSpace(path)
		if rel == "/" {
			return true, nil
		}
		return path == rel || strings.HasPrefix(path, rel+"/"), nil
	}
	return false, errors.New("no cgroup v2 entry")
}

func (s *Server) serve(conn net.Conn, p *pluginState) {
	rd := bufio.NewReaderSize(conn, 4096)
	enc := json.NewEncoder(conn)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(IdleTimeout))
		line, err := wire.ReadLine(rd, wire.MaxLineBytes)
		if err != nil {
			if errors.Is(err, wire.ErrLineTooLong) {
				_ = enc.Encode(wire.Response{V: wire.ProtocolVersion, Decision: wire.DecisionDeny, Reason: wire.ReasonInvalidRequest, Principal: wireUID(p.principal), Error: err.Error()})
			}
			return
		}
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		resp := s.handle(line, p)
		_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if err := enc.Encode(resp); err != nil {
			return
		}
	}
}

func wireUID(e engine.EntityUID) wire.EntityUID { return wire.EntityUID{Type: e.Type, ID: e.ID} }

// rawRequest mirrors wire.Request with the context left raw for strict
// conversion.
type rawRequest struct {
	V        int                        `json:"v"`
	ID       string                     `json:"id"`
	Action   wire.EntityUID             `json:"action"`
	Resource wire.EntityUID             `json:"resource"`
	Context  map[string]json.RawMessage `json:"context"`
}

// handle answers one request line. Every path returns a deny unless the
// decision core allowed it.
func (s *Server) handle(line []byte, p *pluginState) wire.Response {
	resp := wire.Response{V: wire.ProtocolVersion, Decision: wire.DecisionDeny, Principal: wireUID(p.principal)}
	var req rawRequest
	if err := json.Unmarshal(line, &req); err != nil {
		resp.Reason, resp.Error = wire.ReasonInvalidRequest, "malformed JSON: "+err.Error()
		s.audit(p, nil, resp, 0)
		return resp
	}
	resp.ID = req.ID
	if len(resp.ID) > 128 {
		resp.ID = resp.ID[:128]
	}
	lreq := &engine.Request{
		Principal: p.principal,
		Action:    engine.EntityUID{Type: req.Action.Type, ID: req.Action.ID},
		Resource:  engine.EntityUID{Type: req.Resource.Type, ID: req.Resource.ID},
	}
	fail := func(reason, detail string) wire.Response {
		resp.Reason, resp.Error = reason, detail
		s.audit(p, lreq, resp, 0)
		return resp
	}
	if req.V != wire.ProtocolVersion {
		return fail(wire.ReasonUnsupportedVersion, fmt.Sprintf("protocol v%d is not supported; this server speaks v%d", req.V, wire.ProtocolVersion))
	}
	if !p.allow() {
		return fail(wire.ReasonRateLimited, "rate limit exceeded")
	}
	if req.Action.Type == "" || req.Action.ID == "" || req.Resource.Type == "" {
		return fail(wire.ReasonInvalidRequest, "action.type, action.id and resource.type are required")
	}
	if len(req.Action.ID) > wire.MaxStringBytes || len(req.Resource.ID) > wire.MaxStringBytes || len(req.Action.Type) > 256 || len(req.Resource.Type) > 256 {
		return fail(wire.ReasonInvalidRequest, "entity type or id too long")
	}
	if ns, ok := namespaceOf(req.Action.Type); ok && !p.namespaces[ns] {
		return fail(wire.ReasonNamespaceNotGranted, fmt.Sprintf("plugin %q is not granted namespace %q", p.grant.ID, ns))
	}
	ctx, err := convertContext(req.Context)
	if err != nil {
		return fail(wire.ReasonInvalidRequest, err.Error())
	}
	lreq.Context = ctx

	snap := s.cfg.Source()
	if snap == nil || snap.Engine == nil {
		return fail(wire.ReasonNoPolicy, "no policy loaded yet")
	}
	dec := snap.Engine.Decide(*lreq)
	if dec.Allow {
		resp.Decision = wire.DecisionAllow
	}
	resp.Reason = dec.Reason
	resp.Policies = dec.PolicyIDs
	resp.Error = dec.Detail
	resp.Generation = snap.Generation
	s.audit(p, lreq, resp, snap.Generation)
	return resp
}

// namespaceOf returns the grant namespace an action needs: "Action" for
// Leash's built-in actions, the plugin namespace otherwise. Actions that are
// neither are left to the decision core, which rejects them.
func namespaceOf(actionType string) (string, bool) {
	if actionType == engine.BuiltinActionType {
		return BuiltinNamespace, true
	}
	return engine.PluginActionNamespace(actionType)
}

func convertContext(raw map[string]json.RawMessage) (map[string]engine.Value, error) {
	if len(raw) > wire.MaxContextKeys {
		return nil, fmt.Errorf("context has %d keys, over the limit of %d", len(raw), wire.MaxContextKeys)
	}
	out := make(map[string]engine.Value, len(raw))
	for k, v := range raw {
		if k == "" || len(k) > 256 {
			return nil, fmt.Errorf("context key %q is empty or too long", k)
		}
		val, err := convertValue(v, true)
		if err != nil {
			return nil, fmt.Errorf("context.%s: %w", k, err)
		}
		out[k] = val
	}
	return out, nil
}

func convertValue(raw json.RawMessage, allowSet bool) (engine.Value, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return engine.Value{}, err
	}
	switch x := v.(type) {
	case string:
		if len(x) > wire.MaxStringBytes {
			return engine.Value{}, fmt.Errorf("string longer than %d bytes", wire.MaxStringBytes)
		}
		return engine.StringValue(x), nil
	case bool:
		return engine.BoolValue(x), nil
	case json.Number:
		n, err := strconv.ParseInt(x.String(), 10, 64)
		if err != nil {
			return engine.Value{}, fmt.Errorf("number %s is not a 64-bit integer", x)
		}
		return engine.LongValue(n), nil
	case []any:
		if !allowSet {
			return engine.Value{}, errors.New("nested sets are not supported")
		}
		var elems []json.RawMessage
		if err := json.Unmarshal(raw, &elems); err != nil {
			return engine.Value{}, err
		}
		if len(elems) > wire.MaxSetElements {
			return engine.Value{}, fmt.Errorf("set longer than %d elements", wire.MaxSetElements)
		}
		set := engine.Value{Kind: engine.ValueSet}
		for _, e := range elems {
			ev, err := convertValue(e, false)
			if err != nil {
				return engine.Value{}, err
			}
			set.Set = append(set.Set, ev)
		}
		return set, nil
	case map[string]any:
		var ent struct {
			Entity *wire.EntityUID `json:"__entity"`
		}
		if _, isEntity := x["__entity"]; isEntity {
			if len(x) != 1 || json.Unmarshal(raw, &ent) != nil || ent.Entity == nil || ent.Entity.Type == "" {
				return engine.Value{}, errors.New(`an entity is {"__entity":{"type":..,"id":..}}`)
			}
			return engine.EntityValue(engine.EntityUID{Type: ent.Entity.Type, ID: ent.Entity.ID}), nil
		}
		// A flat record (#113: McpCall's context.args): only at the top
		// level of the context, with string, long and boolean values.
		if !allowSet {
			return engine.Value{}, errors.New("nested records are not supported")
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			return engine.Value{}, err
		}
		if len(fields) > wire.MaxContextKeys {
			return engine.Value{}, fmt.Errorf("record has %d keys, over the limit of %d", len(fields), wire.MaxContextKeys)
		}
		rec := make(map[string]engine.Value, len(fields))
		for k, fv := range fields {
			if len(k) > 256 {
				return engine.Value{}, fmt.Errorf("record key %q is too long", k)
			}
			ev, err := convertValue(fv, false)
			if err != nil {
				return engine.Value{}, fmt.Errorf("record key %q: %w", k, err)
			}
			if ev.Kind == engine.ValueSet || ev.Kind == engine.ValueEntity || ev.Kind == engine.ValueRecord {
				return engine.Value{}, fmt.Errorf("record key %q: record values are strings, longs and booleans", k)
			}
			rec[k] = ev
		}
		return engine.RecordValue(rec), nil
	case nil:
		return engine.Value{}, errors.New("null is not a Cedar value")
	}
	return engine.Value{}, fmt.Errorf("unsupported value %T", v)
}

// audit writes one decision to the shared event log. Context values are never
// logged (they may carry secrets or source text); only their keys are.
func (s *Server) audit(p *pluginState, req *engine.Request, resp wire.Response, generation uint64) {
	if s.cfg.Logger == nil {
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "time=%s event=authz.decision plugin=%s", time.Now().Format(time.RFC3339), p.grant.ID)
	if req != nil {
		fmt.Fprintf(&b, " action=%s resource=%s", strconv.Quote(req.Action.String()), strconv.Quote(req.Resource.String()))
		if len(req.Context) > 0 {
			keys := make([]string, 0, len(req.Context))
			for k := range req.Context {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			fmt.Fprintf(&b, " context_keys=%s", strconv.Quote(strings.Join(keys, ",")))
		}
	}
	fmt.Fprintf(&b, " decision=%s reason=%s", resp.Decision, resp.Reason)
	if len(resp.Policies) > 0 {
		fmt.Fprintf(&b, " policies=%s", strconv.Quote(strings.Join(resp.Policies, ",")))
	}
	if resp.Rule != "" {
		fmt.Fprintf(&b, " rule=%s", strconv.Quote(resp.Rule))
	}
	if generation > 0 {
		fmt.Fprintf(&b, " generation=%d", generation)
	}
	if resp.Error != "" {
		fmt.Fprintf(&b, " error=%s", strconv.Quote(resp.Error))
	}
	_ = s.cfg.Logger.Write(b.String())
}
