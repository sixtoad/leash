package engine

import (
	"fmt"
	"iter"
	"sort"
	"strings"
	"time"

	cedar "github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
	xast "github.com/cedar-policy/cedar-go/x/exp/ast"
)

// Annotations Leash reads on policies.
const (
	// AnnotationID names the policy in decisions and audit records.
	AnnotationID = "id"
	// AnnotationExpires (RFC 3339) stops the policy from applying from that
	// instant on. Cedar itself ignores annotations; the engine drops expired
	// policies from evaluation.
	AnnotationExpires = "expires"
	// AnnotationSource names the legacy policy ("<file>:<line>") a rewritten
	// policy came from; see transpiler.RewriteLegacy.
	AnnotationSource = "leash_source"
)

type entry struct {
	id      cedar.PolicyID
	policy  *cedar.Policy
	display string
	expires time.Time // zero: never
}

// partition is the ordered list of policies a class of requests is
// evaluated against.
type partition []entry

// live iterates the partition without the policies that expired at now.
type live struct {
	entries partition
	now     time.Time
}

func (l live) All() iter.Seq2[cedar.PolicyID, *cedar.Policy] {
	return func(yield func(cedar.PolicyID, *cedar.Policy) bool) {
		for _, e := range l.entries {
			if !e.expires.IsZero() && !l.now.Before(e.expires) {
				continue
			}
			if !yield(e.id, e.policy) {
				return
			}
		}
	}
}

// Engine evaluates requests against one strict-Cedar policy set with
// cedar.Authorize. It is immutable once built and safe for concurrent use; a
// policy change builds a new Engine.
type Engine struct {
	builtin partition
	// byAction holds, per requestable built-in action, the built-in policies
	// whose action scope can match it. Skipping the others is only an
	// optimization: their scope is false for that request.
	byAction map[string]partition
	// named holds every entity literal a built-in policy names. A request's
	// parents are filtered to it: `resource in E` only ever tests literals
	// (built-in requests carry no entity-valued context), so a parent no
	// policy names cannot change a decision. Optimization only.
	named     map[types.EntityUID]bool
	plugins   map[string]partition
	display   map[cedar.PolicyID]string
	mcpActive bool
	now       func() time.Time
}

// Scope classifies the actions a policy's action scope names.
type Scope struct {
	// Builtin is true when the policy applies to Leash's own actions: its
	// action scope is unconstrained or names Action::"..." entities.
	Builtin bool
	// Unconstrained is true for `action` with no constraint.
	Unconstrained bool
	// Actions are the built-in action IDs named by the scope (empty when
	// Unconstrained).
	Actions []string
	// Namespaces are the plugin namespaces named by the scope.
	Namespaces []string
}

// ClassifyActions returns which actions p's action scope can apply to. A
// policy may not mix Leash's actions with plugin actions, and every action
// entity must be Action::"..." or <Namespace>::Action::"...".
func ClassifyActions(p *cedar.Policy) (Scope, error) {
	pa := (*xast.Policy)(p.AST())
	var uids []types.EntityUID
	switch s := pa.Action.(type) {
	case xast.ScopeTypeAll:
		return Scope{Builtin: true, Unconstrained: true}, nil
	case xast.ScopeTypeEq:
		uids = []types.EntityUID{s.Entity}
	case xast.ScopeTypeIn:
		uids = []types.EntityUID{s.Entity}
	case xast.ScopeTypeInSet:
		uids = s.Entities
	default:
		return Scope{}, fmt.Errorf("unsupported action scope %T", pa.Action)
	}
	var sc Scope
	seen := map[string]bool{}
	for _, uid := range uids {
		typ := string(uid.Type)
		if typ == BuiltinActionType {
			sc.Builtin = true
			sc.Actions = append(sc.Actions, string(uid.ID))
			continue
		}
		ns, ok := PluginActionNamespace(typ)
		if !ok {
			return Scope{}, fmt.Errorf("action %s: an action must be Action::\"...\" (Leash) or <Namespace>::Action::\"...\" (plugin)", uid)
		}
		if !seen[ns] {
			seen[ns] = true
			sc.Namespaces = append(sc.Namespaces, ns)
		}
	}
	if sc.Builtin && len(sc.Namespaces) > 0 {
		return Scope{}, fmt.Errorf("policy mixes plugin actions with Leash actions; write them as separate policies")
	}
	return sc, nil
}

// DisplayID returns the name decisions report for a policy: its @id
// annotation, else the legacy policy it was rewritten from
// (@leash_source("<file>:<line>")), else its Cedar policy ID.
func DisplayID(id cedar.PolicyID, p *cedar.Policy) string {
	ann := p.Annotations()
	for _, key := range []types.Ident{AnnotationID, AnnotationSource} {
		if v, ok := ann[key]; ok && strings.TrimSpace(string(v)) != "" {
			return string(v)
		}
	}
	return string(id)
}

// Expiry returns the @expires instant of p (zero when it has none).
func Expiry(p *cedar.Policy) (time.Time, error) {
	v, ok := p.Annotations()[AnnotationExpires]
	if !ok {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, string(v))
	if err != nil {
		return time.Time{}, fmt.Errorf("@expires(%q): want an RFC 3339 timestamp: %w", string(v), err)
	}
	return t, nil
}

// New builds an engine from a strict-Cedar policy set. It fails when a
// policy's action scope is invalid or an annotation is malformed; nothing is
// skipped.
func New(ps *cedar.PolicySet) (*Engine, error) {
	e := &Engine{plugins: map[string]partition{}, byAction: map[string]partition{}, named: map[types.EntityUID]bool{}, display: map[cedar.PolicyID]string{}, now: time.Now}
	if ps == nil {
		return e, nil
	}
	ids := make([]cedar.PolicyID, 0)
	for id := range ps.All() {
		ids = append(ids, id)
	}
	sortPolicyIDs(ids, ps)
	for _, id := range ids {
		p := ps.Get(id)
		sc, err := ClassifyActions(p)
		if err != nil {
			return nil, fmt.Errorf("policy %s: %w", DisplayID(id, p), err)
		}
		exp, err := Expiry(p)
		if err != nil {
			return nil, fmt.Errorf("policy %s: %w", DisplayID(id, p), err)
		}
		en := entry{id: id, policy: p, display: DisplayID(id, p), expires: exp}
		e.display[id] = en.display
		if sc.Builtin {
			e.builtin = append(e.builtin, en)
			collectEntityLiterals((*xast.Policy)(p.AST()), e.named)
			for _, a := range requestableActions {
				if actionScopeMayMatch((*xast.Policy)(p.AST()).Action, a) {
					e.byAction[a] = append(e.byAction[a], en)
				}
			}
			if appliesToMCP(sc) && !isUnconditionalPermitAll(p, exp) {
				e.mcpActive = true
			}
		}
		for _, ns := range sc.Namespaces {
			e.plugins[ns] = append(e.plugins[ns], en)
		}
	}
	// No policy that can apply to McpCall at all: every call is denied, so
	// the proxy must inspect MCP traffic.
	if !e.mcpActive && !e.hasMCPPermit() {
		e.mcpActive = true
	}
	return e, nil
}

// NewFromText parses strict Cedar text and builds an engine.
func NewFromText(name, text string) (*Engine, error) {
	ps, err := cedar.NewPolicySetFromBytes(name, []byte(text))
	if err != nil {
		return nil, err
	}
	return New(ps)
}

func sortPolicyIDs(ids []cedar.PolicyID, ps *cedar.PolicySet) {
	sort.Slice(ids, func(i, j int) bool {
		a, b := ps.Get(ids[i]).Position(), ps.Get(ids[j]).Position()
		if a.Filename != b.Filename {
			return a.Filename < b.Filename
		}
		if a.Offset != b.Offset {
			return a.Offset < b.Offset
		}
		return ids[i] < ids[j]
	})
}

// collectEntityLiterals records every entity literal of a policy's
// principal and resource scopes and conditions.
func collectEntityLiterals(pa *xast.Policy, into map[types.EntityUID]bool) {
	for _, scope := range []any{pa.Principal, pa.Resource} {
		switch s := scope.(type) {
		case xast.ScopeTypeEq:
			into[s.Entity] = true
		case xast.ScopeTypeIn:
			into[s.Entity] = true
		case xast.ScopeTypeIsIn:
			into[s.Entity] = true
		}
	}
	var value func(v types.Value)
	value = func(v types.Value) {
		switch x := v.(type) {
		case types.EntityUID:
			into[x] = true
		case types.Set:
			for e := range x.All() {
				value(e)
			}
		}
	}
	for _, c := range pa.Conditions {
		xast.Inspect(xast.NewNode(c.Body), func(n xast.IsNode) bool {
			if v, ok := n.(xast.NodeValue); ok {
				value(v.Value)
			}
			return true
		})
	}
}

// requestableActions are the built-in actions a request can carry.
var requestableActions = []string{ActionFileOpenReadOnly, ActionFileOpenReadWrite, ActionProcessExec, ActionNetworkConnect, ActionMcpCall}

// actionScopeMayMatch reports whether an action scope can be true for a
// request with built-in action a (Action::"FileOpen" is the group of the two
// open actions).
func actionScopeMayMatch(scope xast.IsActionScopeNode, a string) bool {
	in := func(uid types.EntityUID) bool {
		if string(uid.Type) != BuiltinActionType {
			return false
		}
		id := string(uid.ID)
		return id == a || (id == ActionFileOpen && (a == ActionFileOpenReadOnly || a == ActionFileOpenReadWrite))
	}
	switch s := scope.(type) {
	case xast.ScopeTypeAll:
		return true
	case xast.ScopeTypeEq:
		return string(s.Entity.Type) == BuiltinActionType && string(s.Entity.ID) == a
	case xast.ScopeTypeIn:
		return in(s.Entity)
	case xast.ScopeTypeInSet:
		for _, uid := range s.Entities {
			if in(uid) {
				return true
			}
		}
	}
	return false
}

func appliesToMCP(sc Scope) bool {
	if sc.Unconstrained {
		return true
	}
	for _, a := range sc.Actions {
		if a == ActionMcpCall {
			return true
		}
	}
	return false
}

func (e *Engine) hasMCPPermit() bool {
	for _, en := range e.builtin {
		sc, _ := ClassifyActions(en.policy)
		if appliesToMCP(sc) && en.policy.Effect() == cedar.Permit {
			return true
		}
	}
	return false
}

// isUnconditionalPermitAll reports whether p permits every McpCall: a permit
// with no principal, resource or condition constraint and no expiry.
func isUnconditionalPermitAll(p *cedar.Policy, expires time.Time) bool {
	if p.Effect() != cedar.Permit || !expires.IsZero() {
		return false
	}
	pa := (*xast.Policy)(p.AST())
	if _, ok := pa.Principal.(xast.ScopeTypeAll); !ok {
		return false
	}
	if _, ok := pa.Resource.(xast.ScopeTypeAll); !ok {
		return false
	}
	return len(pa.Conditions) == 0
}

// WithClock returns a copy of e whose @expires checks use now.
func (e *Engine) WithClock(now func() time.Time) *Engine {
	cp := *e
	cp.now = now
	return &cp
}

// HasMCPPolicies reports whether MCP tools/call decisions depend on the call:
// the proxy only parses MCP traffic when they do. It is false only when an
// unconditional permit covers every call and no other policy can apply.
func (e *Engine) HasMCPPolicies() bool { return e != nil && e.mcpActive }

// HasPluginPolicies reports whether any policy names a plugin namespace.
func (e *Engine) HasPluginPolicies() bool { return e != nil && len(e.plugins) > 0 }

// Decide routes a generic request to its partition and evaluates it.
func (e *Engine) Decide(req Request) Decision {
	if e == nil {
		return Decision{Reason: ReasonNoPolicy}
	}
	if req.Action.Type == BuiltinActionType {
		return e.decideBuiltin(req)
	}
	ns, ok := PluginActionNamespace(req.Action.Type)
	if !ok {
		return Decision{Reason: ReasonUnsupportedAction, Detail: fmt.Sprintf("action %s is neither a Leash action nor a namespaced plugin action", req.Action)}
	}
	if req.Principal.IsZero() || req.Resource.IsZero() {
		return invalidRequest("a plugin request needs a principal and a resource")
	}
	ctx, err := contextRecord(req.Context)
	if err != nil {
		return invalidRequest("context: %v", err)
	}
	creq := cedar.Request{
		Principal: uid(req.Principal),
		Action:    uid(req.Action),
		Resource:  uid(req.Resource),
		Context:   ctx,
	}
	return e.authorize(e.plugins[ns], nil, creq)
}

func (e *Engine) decideBuiltin(req Request) Decision {
	switch req.Action.ID {
	case ActionFileOpenReadOnly, ActionFileOpenReadWrite, ActionFileOpen, ActionProcessExec:
		if req.Resource.Type != TypeFile || !strings.HasPrefix(req.Resource.ID, "/") {
			return invalidRequest("%s needs resource File::\"/absolute/path\"", req.Action.ID)
		}
		switch req.Action.ID {
		case ActionProcessExec:
			return e.DecideExec(req.Resource.ID)
		case ActionFileOpen:
			// A generic open is allowed only when both modes are.
			ro := e.DecideOpen(req.Resource.ID, ActionFileOpenReadOnly)
			if !ro.Allow {
				return ro
			}
			return e.DecideOpen(req.Resource.ID, ActionFileOpenReadWrite)
		default:
			return e.DecideOpen(req.Resource.ID, req.Action.ID)
		}
	case ActionNetworkConnect:
		if req.Resource.Type != TypeHost || req.Resource.ID == "" {
			return invalidRequest("NetworkConnect needs resource Host::\"name\"")
		}
		var ip string
		var port uint16
		if v, ok := req.Context["port"]; ok {
			if v.Kind != ValueLong || v.Long < 0 || v.Long > 65535 {
				return invalidRequest("context.port must be a long in 0-65535")
			}
			port = uint16(v.Long)
		}
		if v, ok := req.Context["ip"]; ok {
			if v.Kind != ValueString {
				return invalidRequest("context.ip must be a string")
			}
			ip = v.Str
		}
		return e.DecideConnect(req.Resource.ID, ip, port)
	case ActionMcpCall:
		if req.Resource.Type != TypeMCPTool {
			return invalidRequest("McpCall needs resource MCP::Tool::\"name\"")
		}
		server := ""
		if v, ok := req.Context["server"]; ok {
			if v.Kind != ValueString {
				return invalidRequest("context.server must be a string")
			}
			server = v.Str
		}
		return e.DecideMCP(server, req.Resource.ID)
	}
	return Decision{Reason: ReasonUnsupportedAction, Detail: fmt.Sprintf("Leash action %q cannot be queried", req.Action.ID)}
}

// DecideOpen decides a file open of an absolute path. action is
// ActionFileOpenReadOnly or ActionFileOpenReadWrite.
func (e *Engine) DecideOpen(path, action string) Decision {
	if e == nil {
		return Decision{Reason: ReasonNoPolicy}
	}
	res := types.NewEntityUID(TypeFile, types.String(path))
	return e.builtinRequest(action, res, fileParents(path, true), types.Record{})
}

// NewEntryName stands for "a new entry" of a directory: the NUL byte no
// path and no kernel-enforced policy entity can contain.
const NewEntryName = "\x00"

// DecideMutation decides a directory mutation of an absolute path (mkdir,
// unlink, rmdir, and each side of a rename): it needs FileOpenReadWrite on
// the path itself and on a new entry of its directory, i.e. on writing the
// directory's contents. There is no Cedar action of its own: the kernel's
// mutation hooks enforce these two FileOpenReadWrite decisions (#142).
func (e *Engine) DecideMutation(path string) Decision {
	if d := e.DecideOpen(path, ActionFileOpenReadWrite); !d.Allow {
		return d
	}
	return e.DecideOpen(path[:strings.LastIndexByte(path, '/')+1]+NewEntryName, ActionFileOpenReadWrite)
}

// DecideExec decides an exec of an absolute path.
func (e *Engine) DecideExec(path string) Decision {
	if e == nil {
		return Decision{Reason: ReasonNoPolicy}
	}
	res := types.NewEntityUID(TypeFile, types.String(path))
	return e.builtinRequest(ActionProcessExec, res, fileParents(path, false), types.Record{})
}

// DecideConnect decides an outbound connection; see connectResource for the
// arguments.
func (e *Engine) DecideConnect(hostname, ip string, port uint16) Decision {
	if e == nil {
		return Decision{Reason: ReasonNoPolicy}
	}
	res, parents, ok := connectResource(hostname, ip, port)
	if !ok {
		return invalidRequest("connect needs a hostname or an IPv4 address")
	}
	return e.builtinRequest(ActionNetworkConnect, res, parents, types.Record{})
}

// DecideMCP decides an MCP tools/call of tool on server. context.server
// carries the normalized server name.
func (e *Engine) DecideMCP(server, tool string) Decision {
	if e == nil {
		return Decision{Reason: ReasonNoPolicy}
	}
	res, parents := mcpResource(server, tool)
	ctx := types.NewRecord(types.RecordMap{"server": types.String(NormalizeMCPServer(server))})
	return e.builtinRequest(ActionMcpCall, res, parents, ctx)
}

// CheckConnect implements the proxy PolicyChecker interface.
func (e *Engine) CheckConnect(hostname, ip string, port uint16) bool {
	return e.DecideConnect(hostname, ip, port).Allow
}

// CheckMCPCall implements the proxy PolicyChecker interface.
func (e *Engine) CheckMCPCall(server, tool string) bool { return e.DecideMCP(server, tool).Allow }

func (e *Engine) builtinRequest(action string, res types.EntityUID, parents []types.EntityUID, ctx types.Record) Decision {
	act := actionEntity(action)
	kept := parents[:0:0]
	for _, p := range parents {
		if e.named[p] {
			kept = append(kept, p)
		}
	}
	entities := types.EntityMap{
		act.UID: act,
		res:     {UID: res, Parents: types.NewEntityUIDSet(kept...)},
	}
	creq := cedar.Request{
		Principal: uid(WorkloadPrincipal),
		Action:    act.UID,
		Resource:  res,
		Context:   ctx,
	}
	return e.authorize(e.byAction[action], entities, creq)
}

func (e *Engine) authorize(p partition, entities types.EntityMap, req cedar.Request) Decision {
	ok, diag := cedar.Authorize(live{entries: p, now: e.now()}, entities, req)
	d := Decision{Allow: bool(ok)}
	for _, r := range diag.Reasons {
		d.PolicyIDs = append(d.PolicyIDs, e.display[r.PolicyID])
	}
	switch {
	case d.Allow:
		d.Reason = ReasonMatchedPermit
	case len(d.PolicyIDs) > 0:
		d.Reason = ReasonMatchedForbid
	default:
		d.Reason = ReasonDefaultDeny
	}
	if len(diag.Errors) > 0 {
		msgs := make([]string, 0, len(diag.Errors))
		for _, er := range diag.Errors {
			msgs = append(msgs, fmt.Sprintf("%s: %s", e.display[er.PolicyID], er.Message))
		}
		d.Detail = "not applicable (evaluation error): " + strings.Join(msgs, "; ")
	}
	return d
}

func uid(e EntityUID) types.EntityUID {
	return types.NewEntityUID(types.EntityType(e.Type), types.String(e.ID))
}

func contextRecord(ctx map[string]Value) (types.Record, error) {
	if len(ctx) == 0 {
		return types.Record{}, nil
	}
	m := make(types.RecordMap, len(ctx))
	for k, v := range ctx {
		cv, err := cedarValue(v)
		if err != nil {
			return types.Record{}, fmt.Errorf("%s: %w", k, err)
		}
		m[types.String(k)] = cv
	}
	return types.NewRecord(m), nil
}

func cedarValue(v Value) (types.Value, error) {
	switch v.Kind {
	case ValueString:
		return types.String(v.Str), nil
	case ValueLong:
		return types.Long(v.Long), nil
	case ValueBool:
		return types.Boolean(v.Bool), nil
	case ValueEntity:
		return uid(v.Entity), nil
	case ValueSet:
		vals := make([]types.Value, 0, len(v.Set))
		for _, e := range v.Set {
			cv, err := cedarValue(e)
			if err != nil {
				return nil, err
			}
			vals = append(vals, cv)
		}
		return types.NewSet(vals...), nil
	}
	return nil, fmt.Errorf("unsupported value kind %d", v.Kind)
}
