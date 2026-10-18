package transpiler

import (
	"fmt"
	"sort"
	"strings"

	cedarlib "github.com/cedar-policy/cedar-go"
	cedarast "github.com/cedar-policy/cedar-go/ast"
	"github.com/cedar-policy/cedar-go/types"
	xast "github.com/cedar-policy/cedar-go/x/exp/ast"

	"github.com/strongdm/leash/internal/engine"
	"github.com/strongdm/leash/internal/lsm"
)

// Legacy-to-Cedar rewrite (#142).
//
// Leash's legacy semantics are, by definition, those of the IR its
// transpiler produces (#138): the transpiler lowers each policy to rules and
// the matchers pick the most specific rule. RewriteLegacy keeps that lowering
// as the meaning of a legacy policy and re-emits it as strict Cedar that
// cedar.Authorize, over Leash's entity hierarchy (package engine), decides
// identically:
//
//   - File open and exec rules are most-specific-wins. A forbid F gains
//     `unless { resource in P }` for every permit P of the same action whose
//     resource is strictly more specific than F's and inside it (P's path
//     starts with F's: byte prefix for File, which also covers Dir self).
//     Equal specificity adds no exception, so the forbid wins, as in #138.
//     Nesting needs nothing special: forbid /a, permit /a/b, forbid /a/b/c,
//     permit /a/b/c/d gives forbid /a unless [/a/b, /a/b/c/d] and forbid
//     /a/b/c unless [/a/b/c/d]. The generic FileOpen rule is expanded to
//     FileOpenReadOnly and FileOpenReadWrite first, so each exception is
//     per action.
//   - Any allow rule on "/" (for any open mode) makes the legacy file-open
//     default allow for every mode: a lowest-specificity permit for both
//     modes is added.
//   - MCP is default-allow and only forbids are enforced: an explicit
//     `permit (principal, action == Action::"McpCall", resource)` is added.
//   - Host::"*" is the connect default: `forbid` is the strict default deny
//     (dropped), `permit` becomes an unconstrained connect permit unless any
//     forbid Host::"*" exists, in which case the default is deny.
//   - What legacy ignored (principal constraints, conditions other than
//     `resource in [...]` and context.hostname, `unless` read as `when`,
//     policies that lowered to no rule) is reproduced, not reinterpreted:
//     the rewritten policy carries exactly the rules legacy enforced, and
//     the report lists every dropped construct. Except where that would
//     allow more than the policy says (#164, unenforceable.go): a permit
//     with such a constraint that grants any file, exec or connect rule,
//     and a forbid that would be enforced on fewer requests than written,
//     fail the rewrite with an UnenforceableError.
//   - Plugin-action policies already had Cedar semantics and are kept as
//     written.
//
// The emitted policies carry no @leash_semantics marker: strict Cedar is
// the default (an input marker is dropped).

// LegacyLayer is one legacy policy source: a parsed file, or a raw IR layer
// (whose rules are legacy by definition).
type LegacyLayer struct {
	Name     string
	Policies *CedarPolicySet
	IR       *lsm.PolicySet
}

// RewriteOptions tune the emitted text.
type RewriteOptions struct {
	// Provenance annotates each rewritten policy with
	// @leash_source("<file>:<line>") so decisions name the legacy policy.
	Provenance bool
	// Name is the source name the rewritten text is parsed under.
	Name string
	// OmitGlobalDefaults leaves out the legacy defaults that are not a rule
	// of any one policy (the MCP default permit, the file-open default allow
	// of an allow on "/"): set when strict layers are merged with the legacy
	// ones, so a strict policy's default deny is not widened by a legacy
	// layer. The legacy layers' own rules are rewritten as usual.
	OmitGlobalDefaults bool
}

// ForbidException records a forbid that gained exceptions.
type ForbidException struct {
	Source     string
	Actions    []string
	Resources  []string
	Exceptions []string
}

func (f ForbidException) String() string {
	return fmt.Sprintf("%s: forbid %s on %s unless %s", f.Source, strings.Join(f.Actions, "|"), strings.Join(f.Resources, ", "), strings.Join(f.Exceptions, ", "))
}

// RewriteNote is a construct legacy semantics ignored or reinterpreted.
type RewriteNote struct {
	Source  string
	Message string
}

func (n RewriteNote) String() string { return n.Source + ": " + n.Message }

// RewriteReport describes what the rewrite changed.
type RewriteReport struct {
	Exceptions  []ForbidException
	Notes       []RewriteNote
	Synthesized []string
}

// Rewrite is the strict-Cedar form of legacy policies.
type Rewrite struct {
	Text     string
	Policies *cedarlib.PolicySet
	Report   RewriteReport
}

type legacyUnit struct {
	source  string
	annots  []xast.AnnotationType
	verbat  *xast.Policy // plugin policy, kept as written
	rewrite *xast.Policy // the HttpRewrite part of a policy
	open    []lsm.PolicyRule
	exec    []lsm.PolicyRule
	connect []lsm.PolicyRule
	mcp     []lsm.MCPPolicyRule
	// raw IR layers carry the connect default as flags
	defaultAllow, defaultDeny bool
}

// RewriteLegacy rewrites legacy layers, in order, to one strict-Cedar set.
// Layers are rewritten together: legacy specificity crosses layers.
func RewriteLegacy(opts RewriteOptions, layers ...LegacyLayer) (*Rewrite, error) {
	rw := &Rewrite{}
	var units []*legacyUnit
	var unenforceable []UnenforceableFinding
	for _, layer := range layers {
		switch {
		case layer.Policies != nil:
			for _, p := range layer.Policies.Policies {
				u, finding, err := lowerLegacyPolicy(layer.Name, p, &rw.Report)
				if err != nil {
					return nil, err
				}
				if finding != nil {
					unenforceable = append(unenforceable, *finding)
					continue
				}
				if u != nil {
					units = append(units, u)
				}
			}
		case layer.IR != nil:
			u, err := lowerLegacyIR(layer.Name, layer.IR)
			if err != nil {
				return nil, err
			}
			units = append(units, u)
		}
	}
	if len(unenforceable) > 0 {
		// #164: enforcing these as legacy semantics did would allow more
		// than the policies say. Fail the load, naming every one.
		return nil, &UnenforceableError{Findings: unenforceable}
	}
	text, err := emitStrict(units, opts, &rw.Report)
	if err != nil {
		return nil, err
	}
	name := opts.Name
	if name == "" {
		name = "rewritten.cedar"
	}
	ps, err := cedarlib.NewPolicySetFromBytes(name, []byte(text))
	if err != nil {
		return nil, fmt.Errorf("internal error: rewritten policy does not parse: %w\n%s", err, text)
	}
	rw.Text = text
	rw.Policies = ps
	return rw, nil
}

func policySource(layer string, p *cedarlib.Policy) string {
	pos := p.Position()
	name := pos.Filename
	if name == "" {
		name = layer
	}
	if pos.Line > 0 {
		return fmt.Sprintf("%s:%d", name, pos.Line)
	}
	return name
}

func keptAnnotations(p *xast.Policy) []xast.AnnotationType {
	var out []xast.AnnotationType
	for _, a := range p.Annotations {
		switch string(a.Key) {
		case AnnotationSemantics, annotationRewrite, annotationSource:
			continue
		}
		out = append(out, a)
	}
	return out
}

// lowerLegacyPolicy lowers one legacy policy. A policy legacy semantics
// cannot enforce as written without allowing more than it says returns a
// finding instead (#164).
func lowerLegacyPolicy(layer string, p CedarPolicy, report *RewriteReport) (*legacyUnit, *UnenforceableFinding, error) {
	native := p.NativePolicy
	if native == nil {
		return nil, nil, nil
	}
	pa := (*xast.Policy)(native.AST())
	u := &legacyUnit{source: policySource(layer, native), annots: keptAnnotations(pa)}
	note := func(format string, args ...any) {
		report.Notes = append(report.Notes, RewriteNote{Source: u.source, Message: fmt.Sprintf(format, args...)})
	}

	sc, err := engine.ClassifyActions(native)
	if err != nil {
		return nil, nil, fmt.Errorf("policy %s at %s:1: %w", engine.DisplayID(cedarlib.PolicyID(p.ID), native), u.source, err)
	}
	if len(sc.Namespaces) > 0 {
		// Plugin actions always had Cedar semantics (#142): kept as
		// written, conditions included; cedar.Authorize evaluates them
		// with the context the plugin sends.
		u.verbat = pa
		return u, nil, nil
	}

	tr := NewCedarToLeashTranspiler()
	ir, _, err := tr.TranspilePolicySet(&CedarPolicySet{Policies: []CedarPolicy{p}})
	if err != nil {
		return nil, nil, err
	}
	u.open, u.exec, u.connect, u.mcp = ir.Open, ir.Exec, ir.Connect, ir.MCP
	dropNeverMatching(u, report)

	hasRewrite := false
	for _, a := range append(append([]string{}, p.Action.Actions...), p.Action.InSet...) {
		if strings.EqualFold(strings.Trim(strings.TrimPrefix(a, "Action::"), `"`), engine.ActionHttpRewrite) && strings.HasPrefix(a, "Action::") {
			hasRewrite = true
		}
	}
	if hasRewrite {
		if p.Effect == Permit {
			cp := *pa
			cp.Action = xast.ScopeTypeEq{Entity: types.NewEntityUID(engine.BuiltinActionType, engine.ActionHttpRewrite)}
			u.rewrite = &cp
		} else {
			note("forbid on HttpRewrite has no effect (rewrites are configured by permits); dropped")
		}
	}

	isMCP := hasMCPCallAction(p)
	if why := legacyUnenforceable(p, pa, u, isMCP); why != "" {
		effect := "permit"
		if p.Effect != Permit {
			effect = "forbid"
		}
		return nil, &UnenforceableFinding{ID: engine.DisplayID(cedarlib.PolicyID(p.ID), native), Policy: legacyFindingRef(layer, p.ID, native), Effect: effect, Reason: why}, nil
	}
	stricter := ""
	if p.Effect != Permit {
		stricter = "; the forbid applies without it (stricter)"
	}
	if !(p.Principal.IsAny && len(p.Principal.InSet) == 0 && p.Principal.Type == "" && p.Principal.ID == "") && !hasRewrite {
		note("principal constraint ignored: legacy semantics apply built-in policies to every principal%s", stricter)
	}
	ignored, unlessIn := false, false
	for _, c := range p.Conditions {
		switch c.Type {
		case ConditionResourceIn:
			if c.Kind == "unless" {
				unlessIn = true
			}
			continue
		case ConditionContextEquals, ConditionContextLike:
			key := strings.ToLower(c.ContextKey)
			if key == "hostname" || (hasRewrite && (key == "header" || key == "value")) {
				continue
			}
		}
		ignored = true
	}
	if unlessIn {
		note("`unless { resource in [...] }` was read as `when`: the listed resources are the policy's resources%s", stricter)
	}
	if ignored && !(hasRewrite && len(u.open)+len(u.exec)+len(u.connect)+len(u.mcp) == 0) {
		note("conditions other than `resource in [...]` and context.hostname were ignored by legacy semantics and are dropped%s", stricter)
	}
	if len(u.open)+len(u.exec)+len(u.connect)+len(u.mcp) == 0 && u.rewrite == nil {
		switch {
		case isMCP && p.Effect == Permit:
			note("permit on McpCall had no effect (MCP was default-allow); the MCP default permit covers it")
		default:
			note("policy had no effect under legacy semantics (no supported action and resource); dropped")
		}
		return nil, nil, nil
	}
	return u, nil, nil
}

func lowerLegacyIR(name string, ir *lsm.PolicySet) (*legacyUnit, error) {
	for _, r := range ir.Exec {
		if r.ArgCount > 0 && r.Action == lsm.PolicyDeny {
			return nil, fmt.Errorf("%s: exec rule %s: argument-matching deny rules (line format only) have no Cedar form", name, r.String())
		}
	}
	u := &legacyUnit{source: name, open: ir.Open, exec: ir.Exec, connect: ir.Connect, mcp: ir.MCP}
	dropNeverMatching(u, nil)
	if ir.ConnectDefaultExplicit && !ir.ConnectDefaultAllow {
		u.defaultDeny = true
	}
	if ir.ConnectDefaultAllow {
		u.defaultAllow = true
	}
	return u, nil
}

// dropNeverMatching removes rules legacy accepted but that can never match a
// request (a relative path; a host name with a trailing dot, upper case is
// fine, or characters no host name has), noting each: strict Cedar rejects
// such entities, and dropping them changes no decision.
func dropNeverMatching(u *legacyUnit, report *RewriteReport) {
	note := func(format string, args ...any) {
		if report != nil {
			report.Notes = append(report.Notes, RewriteNote{Source: u.source, Message: fmt.Sprintf(format, args...)})
		}
	}
	keepPaths := func(rules []lsm.PolicyRule) []lsm.PolicyRule {
		var out []lsm.PolicyRule
		for _, r := range rules {
			if path := string(r.Path[:r.PathLen]); !strings.HasPrefix(path, "/") {
				note("rule on relative path %q never matched an (absolute) request path; dropped", path)
				continue
			}
			out = append(out, r)
		}
		return out
	}
	u.open, u.exec = keepPaths(u.open), keepPaths(u.exec)
	var connect []lsm.PolicyRule
	for _, r := range u.connect {
		if lsm.IsConnectDefaultRule(r) {
			connect = append(connect, r)
			continue
		}
		if id := connectAtomID(r); id != "" {
			if _, err := parseHostID(id); err != nil {
				note("connect rule %s never matched a request (%v); dropped", r.String(), err)
				continue
			}
		}
		connect = append(connect, r)
	}
	u.connect = connect
}

// pathRule is a file-open or exec rule after FileOpen expansion.
type pathRule struct {
	allow  bool
	action string // engine.ActionFileOpenReadOnly / ReadWrite / ProcessExec
	path   string
	dir    bool
}

func (r pathRule) entity() string {
	typ := engine.TypeFilePrefix // legacy File rules matched by byte prefix
	if r.dir {
		typ = engine.TypeDir
	}
	return entityRef(typ, r.path)
}

func entityRef(typ, id string) string {
	return string(types.NewEntityUID(types.EntityType(typ), types.String(id)).MarshalCedar())
}

func expandPathRules(rules []lsm.PolicyRule) []pathRule {
	var out []pathRule
	for _, r := range rules {
		path := string(r.Path[:r.PathLen])
		base := pathRule{allow: r.Action == lsm.PolicyAllow, path: path, dir: r.IsDirectory != 0}
		switch r.Operation {
		case lsm.OpOpen:
			a, b := base, base
			a.action, b.action = engine.ActionFileOpenReadOnly, engine.ActionFileOpenReadWrite
			out = append(out, a, b)
		case lsm.OpOpenRO:
			base.action = engine.ActionFileOpenReadOnly
			out = append(out, base)
		case lsm.OpOpenRW:
			base.action = engine.ActionFileOpenReadWrite
			out = append(out, base)
		case lsm.OpExec:
			if r.ArgCount > 0 {
				// Argument rules exist only in the line format; Cedar never
				// produces them. An allow with arguments never matched (a
				// deny with arguments is rejected by lowerLegacyIR).
				continue
			}
			base.action = engine.ActionProcessExec
			out = append(out, base)
		}
	}
	return out
}

// exceptionsFor returns the permits strictly more specific than f that lie
// inside it (their path starts with f's), for f's action.
func exceptionsFor(f pathRule, allows []pathRule) []string {
	seen := map[string]bool{}
	var out []string
	for _, a := range allows {
		if a.action != f.action || len(a.path) <= len(f.path) || !strings.HasPrefix(a.path, f.path) {
			continue
		}
		ref := a.entity()
		if !seen[ref] {
			seen[ref] = true
			out = append(out, ref)
		}
	}
	sort.Strings(out)
	return out
}

// pathGroup is one emitted file/exec policy: a cross product of actions and
// resources sharing one exception set.
type pathGroup struct {
	allow      bool
	actions    []string
	resources  []string
	exceptions []string
}

func groupPathRules(rules []pathRule, allows map[string][]pathRule) []pathGroup {
	type key struct {
		allow  bool
		action string
		exc    string
	}
	type acc struct {
		key
		exceptions []string
		resources  []string
		seen       map[string]bool
	}
	var order []key
	byKey := map[key]*acc{}
	for _, r := range rules {
		var exc []string
		if !r.allow {
			exc = exceptionsFor(r, allows[r.action])
		}
		k := key{allow: r.allow, action: r.action, exc: strings.Join(exc, "\x00")}
		a := byKey[k]
		if a == nil {
			a = &acc{key: k, exceptions: exc, seen: map[string]bool{}}
			byKey[k] = a
			order = append(order, k)
		}
		if ref := r.entity(); !a.seen[ref] {
			a.seen[ref] = true
			a.resources = append(a.resources, ref)
		}
	}
	// Merge groups that differ only in the action.
	var groups []pathGroup
	index := map[string]int{}
	for _, k := range order {
		a := byKey[k]
		res := append([]string(nil), a.resources...)
		sort.Strings(res)
		mk := fmt.Sprintf("%v|%s|%s", k.allow, k.exc, strings.Join(res, "\x00"))
		if i, ok := index[mk]; ok {
			groups[i].actions = append(groups[i].actions, k.action)
			continue
		}
		index[mk] = len(groups)
		groups = append(groups, pathGroup{allow: k.allow, actions: []string{k.action}, resources: res, exceptions: a.exceptions})
	}
	return groups
}

// connectAtom renders a connect rule as the Host entity it matches, or ""
// for a rule that matches every connection.
func connectAtom(r lsm.PolicyRule) string {
	id := connectAtomID(r)
	if id == "" {
		return ""
	}
	return entityRef(engine.TypeHost, id)
}

func connectAtomID(r lsm.PolicyRule) string {
	host := strings.ToLower(string(r.Hostname[:r.HostnameLen]))
	switch {
	case host != "":
		if host == "*" && r.DestPort == 0 {
			return ""
		}
	case r.DestIP != 0 || r.DestIP6 != [16]byte{}:
		host = lsm.ConnectRuleAddr(r.DestIP, r.DestIP6)
	default:
		// No IP and no hostname: any destination (Host::"0.0.0.0" lowers
		// to this), optionally on one port.
		if r.DestPort == 0 {
			return ""
		}
		host = "*"
	}
	if r.DestPort != 0 {
		host = engine.HostWithPort(host, r.DestPort)
	}
	return host
}

type strictWriter struct {
	b    strings.Builder
	opts RewriteOptions
}

func (w *strictWriter) policy(annots []xast.AnnotationType, source, effect string, actions []string, conditions []string) {
	if w.b.Len() > 0 {
		w.b.WriteString("\n")
	}
	for _, a := range annots {
		fmt.Fprintf(&w.b, "@%s(%s)\n", a.Key, a.Value.MarshalCedar())
	}
	if w.opts.Provenance && source != "" {
		fmt.Fprintf(&w.b, "@%s(%s)\n", annotationSource, types.String(source).MarshalCedar())
	}
	fmt.Fprintf(&w.b, "%s (\n    principal,\n    %s,\n    resource\n)", effect, actionScope(actions))
	for _, c := range conditions {
		w.b.WriteString("\n" + c)
	}
	w.b.WriteString(";\n")
}

func (w *strictWriter) ast(p *xast.Policy, source string) {
	cp := *p
	cp.Annotations = keptAnnotations(p)
	if w.opts.Provenance && source != "" {
		cp.Annotations = append(cp.Annotations, xast.AnnotationType{Key: annotationSource, Value: types.String(source)})
	}
	cp.Position = xast.Position{}
	if w.b.Len() > 0 {
		w.b.WriteString("\n")
	}
	w.b.Write(cedarlib.NewPolicyFromAST((*cedarast.Policy)(&cp)).MarshalCedar())
	w.b.WriteString("\n")
}

func actionScope(actions []string) string {
	if len(actions) == 0 {
		return "action"
	}
	if len(actions) == 1 {
		return "action == " + entityRef(engine.BuiltinActionType, actions[0])
	}
	refs := make([]string, len(actions))
	for i, a := range actions {
		refs[i] = entityRef(engine.BuiltinActionType, a)
	}
	return "action in [" + strings.Join(refs, ", ") + "]"
}

func inList(refs []string) string {
	if len(refs) == 1 {
		return "resource in " + refs[0]
	}
	return "resource in [" + strings.Join(refs, ", ") + "]"
}

func effectWord(allow bool) string {
	if allow {
		return "permit"
	}
	return "forbid"
}

func emitStrict(units []*legacyUnit, opts RewriteOptions, report *RewriteReport) (string, error) {
	w := &strictWriter{opts: opts}

	// Global facts legacy decisions depend on.
	allows := map[string][]pathRule{}
	openRootAllow := false
	denyAny, allowAny := false, false
	for _, u := range units {
		for _, r := range expandPathRules(u.open) {
			if r.allow {
				allows[r.action] = append(allows[r.action], r)
				if r.path == "/" {
					openRootAllow = true
				}
			}
		}
		for _, r := range expandPathRules(u.exec) {
			if r.allow {
				allows[r.action] = append(allows[r.action], r)
			}
		}
		for _, r := range u.connect {
			if lsm.IsConnectDefaultRule(r) {
				if r.Action == lsm.PolicyAllow {
					allowAny = true
				} else {
					denyAny = true
				}
			}
		}
		denyAny = denyAny || u.defaultDeny
		allowAny = allowAny || u.defaultAllow
	}

	for _, u := range units {
		if u.verbat != nil {
			w.ast(u.verbat, u.source)
			continue
		}
		if u.rewrite != nil {
			w.ast(u.rewrite, u.source)
		}
		for _, rules := range [][]pathRule{expandPathRules(u.open), expandPathRules(u.exec)} {
			for _, g := range groupPathRules(rules, allows) {
				conds := []string{"when { " + inList(g.resources) + " }"}
				if len(g.exceptions) > 0 {
					conds = append(conds, "unless { "+inList(g.exceptions)+" }")
					report.Exceptions = append(report.Exceptions, ForbidException{Source: u.source, Actions: g.actions, Resources: g.resources, Exceptions: g.exceptions})
				}
				w.policy(u.annots, u.source, effectWord(g.allow), g.actions, conds)
			}
		}

		// Connect: legacy matching already is forbid-overrides-permit.
		for _, allow := range []bool{true, false} {
			var atoms []string
			seen := map[string]bool{}
			any := false
			for _, r := range u.connect {
				if (r.Action == lsm.PolicyAllow) != allow {
					continue
				}
				if lsm.IsConnectDefaultRule(r) {
					continue
				}
				atom := connectAtom(r)
				if atom == "" {
					any = true
					continue
				}
				if !seen[atom] {
					seen[atom] = true
					atoms = append(atoms, atom)
				}
			}
			switch {
			case any:
				w.policy(u.annots, u.source, effectWord(allow), []string{engine.ActionNetworkConnect}, nil)
			case len(atoms) > 0:
				w.policy(u.annots, u.source, effectWord(allow), []string{engine.ActionNetworkConnect}, []string{"when { " + inList(atoms) + " }"})
			}
		}
		hasDefault := u.defaultAllow
		for _, r := range u.connect {
			if lsm.IsConnectDefaultRule(r) && r.Action == lsm.PolicyAllow {
				hasDefault = true
			}
		}
		if hasDefault {
			if denyAny {
				report.Notes = append(report.Notes, RewriteNote{Source: u.source, Message: `permit Host::"*" is overridden by a forbid Host::"*" (legacy default deny); dropped`})
			} else if allowAny {
				w.policy(u.annots, u.source, "permit", []string{engine.ActionNetworkConnect}, nil)
			}
		}

		emitMCP(w, u)
	}

	if openRootAllow && !opts.OmitGlobalDefaults {
		w.policy([]xast.AnnotationType{{Key: annotationRewrite, Value: "file-open-default-allow"}}, "", "permit",
			[]string{engine.ActionFileOpenReadOnly, engine.ActionFileOpenReadWrite}, nil)
		report.Synthesized = append(report.Synthesized, "file-open-default-allow: an allow on \"/\" made the legacy file-open default allow for every mode")
	}
	if !opts.OmitGlobalDefaults {
		w.policy([]xast.AnnotationType{{Key: annotationRewrite, Value: "mcp-default-allow"}}, "", "permit", []string{engine.ActionMcpCall}, nil)
		report.Synthesized = append(report.Synthesized, "mcp-default-allow: legacy MCP calls were allowed unless forbidden")
	}
	return w.b.String(), nil
}

func emitMCP(w *strictWriter, u *legacyUnit) {
	var rules []lsm.MCPPolicyRule
	for _, r := range u.mcp {
		if r.Action == lsm.PolicyDeny { // legacy MCP permits never decided anything
			rules = append(rules, lsm.MCPPolicyRule{Action: r.Action, Server: engine.NormalizeMCPServer(r.Server), Tool: engine.NormalizeMCPTool(r.Tool)})
		}
	}
	if len(rules) == 0 {
		return
	}
	servers, tools := map[string]bool{}, map[string]bool{}
	combos := map[[2]string]bool{}
	for _, r := range rules {
		servers[r.Server] = true
		tools[r.Tool] = true
		combos[[2]string{r.Server, r.Tool}] = true
	}
	cond := func(server, tool []string) []string {
		var parts []string
		if !(len(server) == 1 && server[0] == "") {
			refs := make([]string, len(server))
			for i, s := range server {
				refs[i] = entityRef(engine.TypeMCPServer, s)
			}
			parts = append(parts, inList(refs))
		}
		if !(len(tool) == 1 && tool[0] == "") {
			refs := make([]string, len(tool))
			for i, t := range tool {
				refs[i] = entityRef(engine.TypeMCPTool, t)
			}
			parts = append(parts, inList(refs))
		}
		if len(parts) == 0 {
			return nil
		}
		return []string{"when { " + strings.Join(parts, " && ") + " }"}
	}
	keys := func(m map[string]bool) []string {
		out := make([]string, 0, len(m))
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	sl, tl := keys(servers), keys(tools)
	product := len(combos) == len(sl)*len(tl) && !(servers[""] && len(sl) > 1) && !(tools[""] && len(tl) > 1)
	if product {
		w.policy(u.annots, u.source, "forbid", []string{engine.ActionMcpCall}, cond(sl, tl))
		return
	}
	cl := make([][2]string, 0, len(combos))
	for c := range combos {
		cl = append(cl, c)
	}
	sort.Slice(cl, func(i, j int) bool { return cl[i][0]+"\x00"+cl[i][1] < cl[j][0]+"\x00"+cl[j][1] })
	for _, c := range cl {
		w.policy(u.annots, u.source, "forbid", []string{engine.ActionMcpCall}, cond([]string{c[0]}, []string{c[1]}))
	}
}
