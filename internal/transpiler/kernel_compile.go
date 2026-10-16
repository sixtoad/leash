package transpiler

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	cedarlib "github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
	xast "github.com/cedar-policy/cedar-go/x/exp/ast"

	"github.com/strongdm/leash/internal/engine"
	"github.com/strongdm/leash/internal/lsm"
)

// Kernel compilation (#142).
//
// The eBPF programs and the macOS extensions cannot call cedar.Authorize, so
// they enforce tables compiled from the strict policy set. CompileKernel
// accepts only the policies whose compilation is equivalent to the engine
// and fails the whole load, with the offending policy named, for anything
// else that can apply to a kernel-enforced action (FileOpenReadOnly,
// FileOpenReadWrite, ProcessExec, NetworkConnect). The kernel subset:
//
//   - principal unconstrained (the kernel enforces for the whole workload);
//   - no @expires (the kernel tables are not re-timed);
//   - the resource scope and every when/unless body built only from
//     `resource in E`, `resource in [E, ...]`, `resource == File::"path"`,
//     `resource == Host::"name"`,
//     `resource is T [in E]`, `action == A`, `action in A|[...]`,
//     `action != A`, literals true/false, `&&`, `||`, `!` and if-then-else;
//     no context, no principal, no attributes;
//   - File (exact), FilePrefix and Dir IDs absolute and at most 255 bytes
//     (`==` only on File), Host IDs lowercase in one of the forms name,
//     *.zone, *, IPv4, each optionally with :port, or an IPv6 address in
//     RFC 5952 form, bare or as [IPv6]:port.
//
// Files and execs compile by regions: every FilePrefix/Dir entity named by
// a kernel policy is a prefix point, every exact File (and, for opens, a
// Dir's directory itself) a single; the non-single paths whose longest
// matching prefix point is x, and each single, form regions in which every
// resource atom has the same truth value, so cedar.Authorize decides each
// region one way. One representative per region is evaluated with the
// engine: prefix regions become longest-prefix rules (pruned when equal to
// their enclosing region), singles become exact rules where the prefix
// rules would decide otherwise (lsm.ExactPath for opens, a NUL-terminated
// path for execs). Connect compiles
// symbolically: each policy must reduce, for NetworkConnect, to a
// disjunction of single Host atoms (or true/false), which the kernel's
// deny-first scan decides exactly like Cedar's forbid-overrides-permit.
//
// MCP and plugin policies are userspace-only and are not compiled; MCP
// policies may use the full language except principal constraints.

var kernelFileActions = []string{engine.ActionFileOpenReadOnly, engine.ActionFileOpenReadWrite}

// kernelReach is the set of kernel-relevant built-in actions a policy can
// apply to.
type kernelReach struct {
	ro, rw, exec, connect, mcp, rewrite bool
}

func (k kernelReach) kernel() bool { return k.ro || k.rw || k.exec || k.connect }

func reachOf(sc engine.Scope, pa *xast.Policy) (kernelReach, error) {
	if sc.Unconstrained {
		return kernelReach{ro: true, rw: true, exec: true, connect: true, mcp: true}, nil
	}
	_, isEq := pa.Action.(xast.ScopeTypeEq)
	var r kernelReach
	for _, a := range sc.Actions {
		switch a {
		case engine.ActionFileOpen:
			if isEq {
				return r, fmt.Errorf(`action == Action::"FileOpen" matches no request: file opens are Action::"FileOpenReadOnly" or Action::"FileOpenReadWrite"; write action in Action::"FileOpen" for both`)
			}
			r.ro, r.rw = true, true
		case engine.ActionFileOpenReadOnly:
			r.ro = true
		case engine.ActionFileOpenReadWrite:
			r.rw = true
		case engine.ActionProcessExec:
			r.exec = true
		case engine.ActionNetworkConnect:
			r.connect = true
		case engine.ActionMcpCall:
			r.mcp = true
		case engine.ActionHttpRewrite:
			r.rewrite = true
		default:
			return r, fmt.Errorf("unknown Leash action Action::%q", a)
		}
	}
	return r, nil
}

// kernelPolicy is a built-in policy accepted for kernel compilation.
type kernelPolicy struct {
	name   string
	reach  kernelReach
	ast    *xast.Policy
	effect bool // true = permit
}

// KernelWarning is a place where the kernel tables enforce more strictly
// than Cedar decides (never more loosely), with the policy that asked for
// what the kernel cannot grant there.
type KernelWarning struct {
	// Policy is the policy reference: its ID and "at file:line:col".
	Policy  string
	Path    string
	Message string
}

func (w KernelWarning) String() string {
	return fmt.Sprintf("policy %s: %s: %s", w.Policy, w.Path, w.Message)
}

// CompileKernel compiles the built-in policies of a strict policy set to
// kernel tables. eng must be the engine built from the same set; it decides
// the region representatives.
func CompileKernel(ps *cedarlib.PolicySet, eng *engine.Engine) (*lsm.PolicySet, error) {
	out, _, err := CompileKernelReport(ps, eng)
	return out, err
}

// CompileKernelReport is CompileKernel, also returning the places where the
// kernel is stricter than Cedar.
func CompileKernelReport(ps *cedarlib.PolicySet, eng *engine.Engine) (*lsm.PolicySet, []KernelWarning, error) {
	out, warnings, err := compileKernel(ps, eng)
	if err != nil {
		return nil, nil, err
	}
	return out, warnings, nil
}

func compileKernel(ps *cedarlib.PolicySet, eng *engine.Engine) (*lsm.PolicySet, []KernelWarning, error) {
	out := &lsm.PolicySet{Open: []lsm.PolicyRule{}, Exec: []lsm.PolicyRule{}, Connect: []lsm.PolicyRule{}, MCP: []lsm.MCPPolicyRule{}}
	if ps == nil {
		return out, nil, nil
	}
	var kps []kernelPolicy
	for _, id := range orderedIDs(ps) {
		p := ps.Get(id)
		name := policyRef(id, p)
		sc, err := engine.ClassifyActions(p)
		if err != nil {
			return nil, nil, fmt.Errorf("policy %s: %w", name, err)
		}
		if !sc.Builtin {
			continue
		}
		pa := (*xast.Policy)(p.AST())
		reach, err := reachOf(sc, pa)
		if err != nil {
			return nil, nil, fmt.Errorf("policy %s: %w", name, err)
		}
		if !reach.kernel() && !reach.mcp {
			continue // HttpRewrite configuration
		}
		if _, ok := pa.Principal.(xast.ScopeTypeAll); !ok {
			return nil, nil, fmt.Errorf("policy %s: built-in actions are enforced for the whole workload; the principal cannot be constrained", name)
		}
		if !reach.kernel() {
			continue // MCP: userspace only
		}
		if _, ok := p.Annotations()[engine.AnnotationExpires]; ok {
			return nil, nil, fmt.Errorf("policy %s: @expires is not supported on policies the kernel enforces (file, exec, connect)", name)
		}
		if err := checkKernelScope(pa.Resource); err != nil {
			return nil, nil, fmt.Errorf("policy %s: %w", name, err)
		}
		for _, c := range pa.Conditions {
			if err := kernelRefs(c.Body); err != nil {
				return nil, nil, fmt.Errorf("policy %s: %w", name, err)
			}
			if err := checkKernelExpr(c.Body); err != nil {
				return nil, nil, fmt.Errorf("policy %s: %w", name, err)
			}
		}
		if reach.exec {
			if err := checkExecPathLengths(pa); err != nil {
				return nil, nil, fmt.Errorf("policy %s: %w", name, err)
			}
		}
		kps = append(kps, kernelPolicy{name: name, reach: reach, ast: pa, effect: pa.Effect == xast.EffectPermit})
	}

	var points []pathPoint
	for _, kp := range kps {
		if kp.reach.ro || kp.reach.rw || kp.reach.exec {
			for _, p := range collectPathPoints(kp.ast) {
				p.policy = kp.name
				points = append(points, p)
			}
		}
	}
	open, err := compileOpenRegions(points, eng)
	if err != nil {
		return nil, nil, err
	}
	mutation, warnings := compileMutationRules(points, eng)
	out.Open = append(open, mutation...)
	out.Exec = compileExecRegions(points, eng)

	if err := compileConnect(kps, out); err != nil {
		return nil, nil, err
	}
	return out, warnings, nil
}

// policyRef names a policy in an error or warning: its display ID and its
// position in the "at file:line:col" form Cedar errors use. A policy from a
// legacy rewrite is placed at its legacy source (@leash_source).
func policyRef(id cedarlib.PolicyID, p *cedarlib.Policy) string {
	name := engine.DisplayID(id, p)
	if src, ok := p.Annotations()[engine.AnnotationSource]; ok && strings.TrimSpace(string(src)) != "" {
		return fmt.Sprintf("%s at %s:1", name, string(src))
	}
	if pos := p.Position(); pos.Line > 0 {
		return fmt.Sprintf("%s at %s:%d:%d", name, pos.Filename, pos.Line, pos.Column)
	}
	return name
}

func orderedIDs(ps *cedarlib.PolicySet) []cedarlib.PolicyID {
	var ids []cedarlib.PolicyID
	for id := range ps.All() {
		ids = append(ids, id)
	}
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
	return ids
}

func errKernel(format string, args ...any) error {
	return fmt.Errorf("not enforceable by the kernel: "+format, args...)
}

func checkKernelScope(scope xast.IsResourceScopeNode) error {
	switch s := scope.(type) {
	case xast.ScopeTypeAll, xast.ScopeTypeIs:
		return nil
	case xast.ScopeTypeEq:
		return checkKernelEntity(s.Entity, true)
	case xast.ScopeTypeIn:
		return checkKernelEntity(s.Entity, false)
	case xast.ScopeTypeIsIn:
		return checkKernelEntity(s.Entity, false)
	}
	return errKernel("resource scope %T", scope)
}

func isVar(n xast.IsNode, name string) bool {
	v, ok := n.(xast.NodeTypeVariable)
	return ok && string(v.Name) == name
}

// entityLiterals returns the entity literals of an entity or a set literal.
func entityLiterals(n xast.IsNode) ([]types.EntityUID, bool) {
	switch v := n.(type) {
	case xast.NodeValue:
		switch x := v.Value.(type) {
		case types.EntityUID:
			return []types.EntityUID{x}, true
		case types.Set:
			var out []types.EntityUID
			for e := range x.All() {
				uid, ok := e.(types.EntityUID)
				if !ok {
					return nil, false
				}
				out = append(out, uid)
			}
			return out, true
		}
	case xast.NodeTypeSet:
		var out []types.EntityUID
		for _, e := range v.Elements {
			ev, ok := e.(xast.NodeValue)
			if !ok {
				return nil, false
			}
			uid, ok := ev.Value.(types.EntityUID)
			if !ok {
				return nil, false
			}
			out = append(out, uid)
		}
		return out, true
	}
	return nil, false
}

// kernelRefs rejects the inputs the kernel does not have: the context, the
// principal and entity attributes.
func kernelRefs(body xast.IsNode) error {
	var err error
	xast.Inspect(xast.NewNode(body), func(n xast.IsNode) bool {
		if err != nil {
			return false
		}
		switch v := n.(type) {
		case xast.NodeTypeVariable:
			if name := string(v.Name); name == "context" || name == "principal" {
				err = errKernel("%s is not available to the kernel; kernel-enforced policies may only test resource membership and the action", name)
			}
		case xast.NodeTypeAccess:
			if isVar(v.Arg, "context") {
				err = errKernel("context is not available to the kernel; kernel-enforced policies may only test resource membership and the action")
			} else {
				err = errKernel("attributes are not available to the kernel")
			}
		case xast.NodeTypeHas, xast.NodeTypeGetTag, xast.NodeTypeHasTag:
			err = errKernel("context, attributes and tags are not available to the kernel")
		}
		return err == nil
	})
	return err
}

// checkKernelExpr accepts the kernel subset of conditions (see above).
func checkKernelExpr(n xast.IsNode) error {
	switch v := n.(type) {
	case xast.NodeValue:
		if _, ok := v.Value.(types.Boolean); ok {
			return nil
		}
		return errKernel("literal %s used as a condition", v.Value)
	case xast.NodeTypeAnd:
		if err := checkKernelExpr(v.Left); err != nil {
			return err
		}
		return checkKernelExpr(v.Right)
	case xast.NodeTypeOr:
		if err := checkKernelExpr(v.Left); err != nil {
			return err
		}
		return checkKernelExpr(v.Right)
	case xast.NodeTypeNot:
		return checkKernelExpr(v.Arg)
	case xast.NodeTypeIfThenElse:
		for _, part := range []xast.IsNode{v.If, v.Then, v.Else} {
			if err := checkKernelExpr(part); err != nil {
				return err
			}
		}
		return nil
	case xast.NodeTypeIn:
		uids, ok := entityLiterals(v.Right)
		if !ok {
			return errKernel("`in` must test against entity literals")
		}
		switch {
		case isVar(v.Left, "resource"):
			for _, uid := range uids {
				if err := checkKernelEntity(uid, false); err != nil {
					return err
				}
			}
			return nil
		case isVar(v.Left, "action"):
			return checkActionLiterals(uids)
		}
		return errKernel("only `resource in ...` and `action in ...` are supported")
	case xast.NodeTypeEquals, xast.NodeTypeNotEquals:
		var b xast.BinaryNode
		neq := false
		if e, ok := v.(xast.NodeTypeEquals); ok {
			b = e.BinaryNode
		} else {
			b = v.(xast.NodeTypeNotEquals).BinaryNode
			neq = true
		}
		left, right := b.Left, b.Right
		if !isVar(left, "resource") && !isVar(left, "action") {
			left, right = right, left
		}
		uids, ok := entityLiterals(right)
		if !ok || len(uids) != 1 {
			return errKernel("`==` must compare resource or action with one entity literal")
		}
		if _, isSetLit := right.(xast.NodeTypeSet); isSetLit {
			return errKernel("`==` must compare with one entity literal")
		}
		switch {
		case isVar(left, "action"):
			return checkActionLiterals(uids)
		case isVar(left, "resource") && !neq:
			return checkKernelEntity(uids[0], true)
		}
		return errKernel("only `resource == E`, `action == A` and `action != A` are supported")
	case xast.NodeTypeIs:
		if isVar(v.Left, "resource") {
			return nil
		}
		return errKernel("only `resource is T` is supported")
	case xast.NodeTypeIsIn:
		if !isVar(v.Left, "resource") {
			return errKernel("only `resource is T in E` is supported")
		}
		uids, ok := entityLiterals(v.Entity)
		if !ok {
			return errKernel("`is ... in` must test against entity literals")
		}
		for _, uid := range uids {
			if err := checkKernelEntity(uid, false); err != nil {
				return err
			}
		}
		return nil
	case xast.NodeTypeVariable:
		return errKernel("%s may not be used here; kernel-enforced policies may only test resource membership and the action", v.Name)
	case xast.NodeTypeAccess, xast.NodeTypeHas:
		return errKernel("attributes and context are not available to the kernel")
	}
	return errKernel("%s is not supported in policies the kernel enforces (only resource membership, the action and boolean logic)", strings.TrimPrefix(fmt.Sprintf("%T", n), "ast."))
}

func checkActionLiterals(uids []types.EntityUID) error {
	for _, uid := range uids {
		if string(uid.Type) != engine.BuiltinActionType {
			return errKernel("action %s is not a Leash action", uid)
		}
	}
	return nil
}

// checkKernelEntity validates a resource entity literal. eq is true for
// `resource == E`.
func checkKernelEntity(uid types.EntityUID, eq bool) error {
	id := string(uid.ID)
	switch string(uid.Type) {
	case engine.TypeFile, engine.TypeDir, engine.TypeFilePrefix:
		if eq && string(uid.Type) != engine.TypeFile {
			return errKernel("`resource == %s` never matches (a file request's resource is File::\"<path>\"); use `resource in %s`", uid, uid)
		}
		if !strings.HasPrefix(id, "/") {
			return errKernel("%s: file and directory paths must be absolute", uid)
		}
		if strings.IndexByte(id, 0) >= 0 {
			return errKernel("%s: path contains a NUL byte", uid)
		}
		if string(uid.Type) == engine.TypeDir && !strings.HasSuffix(id, "/") {
			id += "/"
		}
		if len(id) > lsm.MaxPolicyPathLength {
			return fmt.Errorf("%w: %s exceeds %d bytes after normalization", errFilePolicyPathTooLong, uid, lsm.MaxPolicyPathLength)
		}
		return nil
	case engine.TypeHost:
		form, err := parseHostID(id)
		if err != nil {
			return errKernel("%s: %v", uid, err)
		}
		if eq && (form.port != 0 || form.ip != "" || form.wildcard || form.any) {
			return errKernel("`resource == %s` never matches (a connect resource is the bare host name); use `resource in %s`", uid, uid)
		}
		return nil
	case engine.TypeMCPServer, engine.TypeMCPTool:
		return nil // never a kernel resource: false for kernel requests
	}
	return errKernel("%s: unknown resource type for a built-in action (file, exec and connect resources are File, Dir and Host; run `leash policy migrate` on a legacy file)", uid)
}

type hostForm struct {
	name     string // hostname, "*.zone" or "*"
	ip       string
	port     uint16
	wildcard bool
	any      bool
}

// parseHostID parses a Host entity ID in the forms the hierarchy defines:
// name, *.zone, *, IPv4 or a bare IPv6 address, each but the IPv6 address
// optionally with :port, and [IPv6]:port.
func parseHostID(id string) (hostForm, error) {
	var f hostForm
	host := id
	parsePort := func(s string) error {
		p, err := strconv.ParseUint(s, 10, 16)
		if err != nil || p == 0 {
			return fmt.Errorf("port %q must be 1-65535", s)
		}
		f.port = uint16(p)
		return nil
	}
	switch {
	case strings.HasPrefix(id, "["):
		end := strings.Index(id, "]")
		if end < 0 || !strings.HasPrefix(id[end+1:], ":") {
			return f, fmt.Errorf("brackets are only for an IPv6 address with a port ([2001:db8::1]:443); write a bare IPv6 address without them")
		}
		host = id[1:end]
		if !strings.Contains(host, ":") || net.ParseIP(host) == nil {
			return f, fmt.Errorf("brackets enclose only an IPv6 address")
		}
		if err := parsePort(id[end+2:]); err != nil {
			return f, err
		}
	case strings.Count(id, ":") > 1:
		// A bare IPv6 address: its colons are not a port separator (the
		// engine names an IPv6 host on a port [addr]:port).
		if net.ParseIP(id) == nil {
			return f, fmt.Errorf("write an IPv6 address with a port as [address]:port")
		}
	default:
		if i := strings.LastIndex(id, ":"); i >= 0 {
			if err := parsePort(id[i+1:]); err != nil {
				return f, err
			}
			host = id[:i]
		}
	}
	switch {
	case host == "":
		return f, fmt.Errorf("empty host")
	case host == "*":
		f.any = true
		f.name = host
	case net.ParseIP(host) != nil:
		canonical := engine.CanonicalIP(host)
		if canonical != host {
			return f, fmt.Errorf("IP addresses must be written in canonical form (%s): dotted IPv4 (also for an IPv4-mapped address), RFC 5952 IPv6", canonical)
		}
		if net.ParseIP(host).IsUnspecified() {
			// The kernel rule ABI reads an all-zero address as "any
			// destination"; the engine matches only that literal address.
			return f, fmt.Errorf("the unspecified address %s is not a destination; use Host::\"*\" for any host", host)
		}
		f.ip = host
	default:
		if host != strings.ToLower(host) || strings.HasSuffix(host, ".") || strings.ContainsAny(host, " /") {
			return f, fmt.Errorf("host names must be lowercase, without a trailing dot")
		}
		if strings.HasPrefix(host, "*.") {
			if len(host) <= 2 || strings.Contains(host[2:], "*") {
				return f, fmt.Errorf("a wildcard is only supported as a leading \"*.\" label")
			}
			f.wildcard = true
		} else if strings.Contains(host, "*") {
			return f, fmt.Errorf("a wildcard is only supported as a leading \"*.\" label")
		}
		if len(host) >= 128 {
			return f, fmt.Errorf("hostname too long")
		}
		f.name = host
	}
	return f, nil
}

// checkExecPathLengths rejects the file entities of a policy that can apply
// to ProcessExec when the kernel's exec matcher could not hold their rule:
// rules are at most lsm.MaxExecPolicyPathLength bytes, and an exact path
// takes one more byte for its terminating NUL. Failing here names the
// policy, instead of the Linux exec loader rejecting the whole load later.
func checkExecPathLengths(pa *xast.Policy) error {
	for _, p := range collectPathPoints(pa) {
		limit, what := lsm.MaxExecPolicyPathLength, "a prefix"
		if p.kind == pointExact {
			limit, what = lsm.MaxExecPolicyPathLength-1, "an exact path"
		}
		if len(p.bytes) > limit {
			return errKernel("exec rule %q is %d bytes; the kernel exec matcher holds %s of at most %d bytes", p.bytes, len(p.bytes), what, limit)
		}
	}
	return nil
}

// pathPoint is a file entity named by a kernel policy: bytes is the path (a
// Dir with its trailing slash).
type pathPoint struct {
	bytes  string
	kind   pointKind
	policy string // the policy that names it (for warnings)
}

type pointKind uint8

const (
	pointPrefix pointKind = iota // FilePrefix: every path the bytes prefix
	pointDir                     // Dir: the bytes as a prefix, plus the directory itself for opens
	pointExact                   // File: exactly the path
)

func collectPathPoints(pa *xast.Policy) []pathPoint {
	var out []pathPoint
	add := func(uid types.EntityUID) {
		id := string(uid.ID)
		switch string(uid.Type) {
		case engine.TypeFile:
			out = append(out, pathPoint{bytes: id, kind: pointExact})
		case engine.TypeFilePrefix:
			out = append(out, pathPoint{bytes: id, kind: pointPrefix})
		case engine.TypeDir:
			if !strings.HasSuffix(id, "/") {
				id += "/"
			}
			out = append(out, pathPoint{bytes: id, kind: pointDir})
		}
	}
	switch s := pa.Resource.(type) {
	case xast.ScopeTypeEq:
		add(s.Entity)
	case xast.ScopeTypeIn:
		add(s.Entity)
	case xast.ScopeTypeIsIn:
		add(s.Entity)
	}
	for _, c := range pa.Conditions {
		xast.Inspect(xast.NewNode(c.Body), func(n xast.IsNode) bool {
			if uids, ok := entityLiterals(n); ok {
				for _, u := range uids {
					add(u)
				}
			}
			return true
		})
	}
	return out
}

// regionSet is the distinct points of one compilation. A prefix point x
// heads the region of paths whose longest prefix point is x; a single is a
// path decided on its own (an exact File, or a directory itself for opens).
type regionSet struct {
	prefixes []string        // distinct prefix point bytes, shortest first
	dirs     map[string]bool // prefix bytes that are directories ("d/")
	singles  []string        // paths decided alone, sorted
	single   map[string]bool
}

func newRegionSet(points []pathPoint, dirSelf bool) regionSet {
	rs := regionSet{dirs: map[string]bool{}, single: map[string]bool{}}
	seen := map[string]bool{}
	addSingle := func(p string) {
		if !rs.single[p] {
			rs.single[p] = true
			rs.singles = append(rs.singles, p)
		}
	}
	for _, p := range points {
		switch p.kind {
		case pointExact:
			addSingle(p.bytes)
			continue
		case pointDir:
			rs.dirs[p.bytes] = true
			if dirSelf && len(p.bytes) > 1 {
				addSingle(strings.TrimSuffix(p.bytes, "/"))
			}
		}
		if !seen[p.bytes] {
			seen[p.bytes] = true
			rs.prefixes = append(rs.prefixes, p.bytes)
		}
	}
	sort.Slice(rs.prefixes, func(i, j int) bool {
		if len(rs.prefixes[i]) != len(rs.prefixes[j]) {
			return len(rs.prefixes[i]) < len(rs.prefixes[j])
		}
		return rs.prefixes[i] < rs.prefixes[j]
	})
	sort.Strings(rs.singles)
	return rs
}

// blocked reports whether path is not in the prefix region headed by base:
// it matches a longer prefix point, or it is a single.
func (rs regionSet) blocked(path, base string) bool {
	for _, y := range rs.prefixes {
		if len(y) > len(base) && strings.HasPrefix(path, y) {
			return true
		}
	}
	return rs.single[path]
}

// representative returns a path in the prefix region of x: x followed by a
// byte no longer point continues with, or x itself ("" when the region is
// empty).
func (rs regionSet) representative(x string) string {
	if len(x) < lsm.MaxPolicyPathLength {
		for c := byte(1); c < 0x7f; c++ {
			if c == '/' {
				continue
			}
			cand := x + string([]byte{c})
			if !rs.blocked(cand, x) {
				return cand
			}
		}
	}
	if !rs.blocked(x, x) {
		return x
	}
	return ""
}

// defaultRepresentative returns an absolute path no point matches.
func (rs regionSet) defaultRepresentative() string {
	for c := byte(1); c < 0x7f; c++ {
		if c == '/' {
			continue
		}
		cand := "/" + string([]byte{c})
		if !rs.blocked(cand, "") {
			return cand
		}
	}
	return ""
}

func (rs regionSet) hasPoint(x string) bool {
	for _, y := range rs.prefixes {
		if y == x {
			return true
		}
	}
	return false
}

// newPathRule builds a file rule; kind is 0 (prefix), 1 (directory: prefix
// plus self) or lsm.ExactPath.
func newPathRule(allow bool, op int32, path string, kind int32) lsm.PolicyRule {
	r := lsm.PolicyRule{Action: lsm.PolicyDeny, Operation: op, PathLen: int32(len(path)), IsDirectory: kind}
	if allow {
		r.Action = lsm.PolicyAllow
	}
	copy(r.Path[:], path)
	return r
}

func dirKind(path string) int32 {
	if strings.HasSuffix(path, "/") {
		return 1
	}
	return 0
}

// openEmit is the emitted prefix-rule state of one op.
type openEmit struct {
	dec     map[string]bool // region decision of each prefix point
	emitted map[string]bool // prefix points that carry a rule for this op
	root    bool
}

// effective returns the decision the kernel's prefix rules give path: the
// nearest emitted prefix point it starts with (path itself only when
// includeSelf), else the root.
func (e openEmit) effective(rs regionSet, path string, includeSelf bool) bool {
	best := ""
	found := false
	for _, y := range rs.prefixes {
		if !e.emitted[y] || !strings.HasPrefix(path, y) {
			continue
		}
		if y == path && !includeSelf {
			continue
		}
		if !found || len(y) > len(best) {
			best, found = y, true
		}
	}
	if !found {
		return e.root
	}
	return e.dec[best]
}

// emitPrefixes decides every prefix region with decide and marks the points
// whose decision differs from their enclosing region's.
func emitPrefixes(rs regionSet, decide func(path string) bool) openEmit {
	em := openEmit{dec: map[string]bool{}, emitted: map[string]bool{}}
	for _, x := range rs.prefixes {
		if rep := rs.representative(x); rep != "" {
			em.dec[x] = decide(rep)
		}
	}
	if rs.hasPoint("/") {
		em.root = em.dec["/"]
	} else if rep := rs.defaultRepresentative(); rep != "" {
		em.root = decide(rep)
	}
	em.emitted["/"] = rs.hasPoint("/")
	for _, x := range rs.prefixes {
		if x != "/" && em.dec[x] != em.effective(rs, x, false) {
			em.emitted[x] = true
		}
	}
	return em
}

func compileOpenRegions(points []pathPoint, eng *engine.Engine) ([]lsm.PolicyRule, error) {
	rs := newRegionSet(points, true)
	actions := []string{engine.ActionFileOpenReadOnly, engine.ActionFileOpenReadWrite}

	type ruleKey struct {
		path string
		kind int32
	}
	type opRule struct{ allow, set bool }
	rules := map[ruleKey]*[2]opRule{}
	var order []ruleKey
	put := func(path string, kind int32, i int, allow bool) {
		k := ruleKey{path, kind}
		r := rules[k]
		if r == nil {
			r = &[2]opRule{}
			rules[k] = r
			order = append(order, k)
		}
		r[i] = opRule{allow: allow, set: true}
	}
	unset := func(path string, kind int32, i int) {
		if r := rules[ruleKey{path, kind}]; r != nil {
			r[i] = opRule{}
		}
	}

	var rootDec [2]bool
	for i, action := range actions {
		em := emitPrefixes(rs, func(p string) bool { return eng.DecideOpen(p, action).Allow })
		rootDec[i] = em.root
		for _, x := range rs.prefixes {
			if x != "/" && em.emitted[x] {
				put(x, 0, i, em.dec[x])
			}
		}
		// Singles: an exact entry wherever the prefix rules would decide
		// otherwise. It outranks every prefix of the path.
		exact := map[string]bool{}
		for _, s := range rs.singles {
			want := eng.DecideOpen(s, action).Allow
			if want != em.effective(rs, s, true) {
				exact[s] = want
				put(s, lsm.ExactPath, i, want)
			}
		}
		// A directory's prefix rule and its own decision fold into one
		// directory rule (prefix plus self) when they agree: the form
		// macOS reads as a Directory rule.
		for _, x := range rs.prefixes {
			if !rs.dirs[x] || len(x) < 2 || !em.emitted[x] {
				continue
			}
			self := strings.TrimSuffix(x, "/")
			final, hasExact := exact[self]
			if !hasExact {
				final = em.effective(rs, self, true)
			}
			if final != em.dec[x] {
				continue
			}
			unset(x, 0, i)
			put(x, 1, i, em.dec[x])
			if hasExact {
				unset(self, lsm.ExactPath, i)
			}
		}
	}

	var out []lsm.PolicyRule
	// The root: the kernel default is "allow if any allow rule is on /".
	switch {
	case rootDec[0] && rootDec[1]:
		out = append(out, newPathRule(true, lsm.OpOpen, "/", 1))
	case rootDec[0] != rootDec[1]:
		out = append(out, newPathRule(rootDec[0], lsm.OpOpenRO, "/", 1), newPathRule(rootDec[1], lsm.OpOpenRW, "/", 1))
	}
	for _, k := range order {
		r := rules[k]
		ro, rw := r[0], r[1]
		switch {
		case ro.set && rw.set && ro.allow == rw.allow:
			out = append(out, newPathRule(ro.allow, lsm.OpOpen, k.path, k.kind))
		default:
			if ro.set {
				out = append(out, newPathRule(ro.allow, lsm.OpOpenRO, k.path, k.kind))
			}
			if rw.set {
				out = append(out, newPathRule(rw.allow, lsm.OpOpenRW, k.path, k.kind))
			}
		}
	}
	return out, nil
}

// compileExecRegions: exec has prefix rules only and no directory-self
// match. An exact File compiles to its path plus a terminating NUL, which
// the exec matcher compares against the NUL-terminated resolved path, so it
// matches only that path and, being one byte longer, outranks every prefix.
func compileExecRegions(points []pathPoint, eng *engine.Engine) []lsm.PolicyRule {
	rs := newRegionSet(points, false)
	em := emitPrefixes(rs, func(p string) bool { return eng.DecideExec(p).Allow })
	var out []lsm.PolicyRule
	if em.root {
		out = append(out, newPathRule(true, lsm.OpExec, "/", 1))
	}
	for _, x := range rs.prefixes {
		if x != "/" && em.emitted[x] {
			out = append(out, newPathRule(em.dec[x], lsm.OpExec, x, dirKind(x)))
		}
	}
	for _, s := range rs.singles {
		if want := eng.DecideExec(s).Allow; want != em.effective(rs, s, true) {
			out = append(out, newPathRule(want, lsm.OpExec, s+"\x00", 0))
		}
	}
	return out
}

// connectForm is a policy's resource condition for NetworkConnect: a
// constant, or a disjunction of Host atoms.
type connectForm struct {
	constant bool
	value    bool
	atoms    []string
}

func constForm(v bool) connectForm { return connectForm{constant: true, value: v} }

func atomsForm(ids []string) connectForm {
	for _, id := range ids {
		if id == "*" {
			return constForm(true)
		}
	}
	if len(ids) == 0 {
		return constForm(false)
	}
	return connectForm{atoms: ids}
}

func hostIDs(uids []types.EntityUID) []string {
	var out []string
	for _, u := range uids {
		if string(u.Type) == engine.TypeHost {
			out = append(out, string(u.ID))
		}
	}
	return out
}

func actionMatchesConnect(uids []types.EntityUID) bool {
	for _, u := range uids {
		if string(u.Type) == engine.BuiltinActionType && string(u.ID) == engine.ActionNetworkConnect {
			return true
		}
	}
	return false
}

func connectExpr(n xast.IsNode) (connectForm, error) {
	errConj := errKernel("a connect condition must be a disjunction of host constraints (the kernel's rule list cannot express a conjunction or negation of two host constraints)")
	switch v := n.(type) {
	case xast.NodeValue:
		b, _ := v.Value.(types.Boolean)
		return constForm(bool(b)), nil
	case xast.NodeTypeAnd:
		l, err := connectExpr(v.Left)
		if err != nil {
			return l, err
		}
		r, err := connectExpr(v.Right)
		if err != nil {
			return r, err
		}
		switch {
		case l.constant && !l.value, r.constant && !r.value:
			return constForm(false), nil
		case l.constant:
			return r, nil
		case r.constant:
			return l, nil
		}
		return connectForm{}, errConj
	case xast.NodeTypeOr:
		l, err := connectExpr(v.Left)
		if err != nil {
			return l, err
		}
		r, err := connectExpr(v.Right)
		if err != nil {
			return r, err
		}
		switch {
		case l.constant && l.value, r.constant && r.value:
			return constForm(true), nil
		case l.constant:
			return r, nil
		case r.constant:
			return l, nil
		}
		return connectForm{atoms: append(append([]string{}, l.atoms...), r.atoms...)}, nil
	case xast.NodeTypeNot:
		x, err := connectExpr(v.Arg)
		if err != nil {
			return x, err
		}
		if x.constant {
			return constForm(!x.value), nil
		}
		return connectForm{}, errConj
	case xast.NodeTypeIfThenElse:
		c, err := connectExpr(v.If)
		if err != nil {
			return c, err
		}
		if !c.constant {
			return connectForm{}, errConj
		}
		if c.value {
			return connectExpr(v.Then)
		}
		return connectExpr(v.Else)
	case xast.NodeTypeIn:
		uids, _ := entityLiterals(v.Right)
		if isVar(v.Left, "action") {
			return constForm(actionMatchesConnect(uids)), nil
		}
		return atomsForm(hostIDs(uids)), nil
	case xast.NodeTypeEquals:
		left, right := v.Left, v.Right
		if !isVar(left, "resource") && !isVar(left, "action") {
			left, right = right, left
		}
		uids, _ := entityLiterals(right)
		if isVar(left, "action") {
			return constForm(actionMatchesConnect(uids)), nil
		}
		return atomsForm(hostIDs(uids)), nil
	case xast.NodeTypeNotEquals:
		left, right := v.Left, v.Right
		if !isVar(left, "action") {
			right = left
		}
		uids, _ := entityLiterals(right)
		return constForm(!actionMatchesConnect(uids)), nil
	case xast.NodeTypeIs:
		return constForm(string(v.EntityType) == engine.TypeHost), nil
	case xast.NodeTypeIsIn:
		if string(v.EntityType) != engine.TypeHost {
			return constForm(false), nil
		}
		uids, _ := entityLiterals(v.Entity)
		return atomsForm(hostIDs(uids)), nil
	}
	return connectForm{}, errKernel("unsupported connect condition %T", n)
}

func connectScope(scope xast.IsResourceScopeNode) connectForm {
	switch s := scope.(type) {
	case xast.ScopeTypeEq:
		return atomsForm(hostIDs([]types.EntityUID{s.Entity}))
	case xast.ScopeTypeIn:
		return atomsForm(hostIDs([]types.EntityUID{s.Entity}))
	case xast.ScopeTypeIs:
		return constForm(string(s.Type) == engine.TypeHost)
	case xast.ScopeTypeIsIn:
		if string(s.Type) != engine.TypeHost {
			return constForm(false)
		}
		return atomsForm(hostIDs([]types.EntityUID{s.Entity}))
	}
	return constForm(true)
}

// policyConnectForm reduces a policy to its NetworkConnect condition.
func policyConnectForm(kp kernelPolicy) (connectForm, error) {
	form := connectScope(kp.ast.Resource)
	conj := func(next connectForm) error {
		switch {
		case form.constant && !form.value, next.constant && next.value:
		case next.constant && !next.value:
			form = constForm(false)
		case form.constant:
			form = next
		default:
			return errKernel("a connect policy may constrain the host in its scope or in one condition, not both")
		}
		return nil
	}
	for _, c := range kp.ast.Conditions {
		f, err := connectExpr(c.Body)
		if err != nil {
			return f, err
		}
		if c.Condition == xast.ConditionUnless {
			if !f.constant {
				return f, errKernel("`unless` on a host constraint (an exception) cannot be compiled for the kernel's deny-first rule list")
			}
			f = constForm(!f.value)
		}
		if err := conj(f); err != nil {
			return f, err
		}
	}
	return form, nil
}

func compileConnect(kps []kernelPolicy, out *lsm.PolicySet) error {
	tr := NewCedarToLeashTranspiler()
	allowAll, denyAll := false, false
	var denies, allows []lsm.PolicyRule
	seen := map[string]bool{}
	for _, kp := range kps {
		if !kp.reach.connect {
			continue
		}
		form, err := policyConnectForm(kp)
		if err != nil {
			return fmt.Errorf("policy %s: %w", kp.name, err)
		}
		if form.constant {
			if form.value {
				if kp.effect {
					allowAll = true
				} else {
					denyAll = true
				}
			}
			continue
		}
		action := int32(lsm.PolicyDeny)
		if kp.effect {
			action = lsm.PolicyAllow
		}
		for _, id := range form.atoms {
			key := fmt.Sprintf("%d|%s", action, id)
			if seen[key] {
				continue
			}
			seen[key] = true
			rule, err := connectRuleFor(tr, action, id)
			if err != nil {
				return fmt.Errorf("policy %s: %w", kp.name, err)
			}
			if action == lsm.PolicyDeny {
				denies = append(denies, rule)
			} else {
				allows = append(allows, rule)
			}
		}
	}
	star := func(action int32) lsm.PolicyRule {
		r, _ := connectRuleFor(tr, action, "*")
		return r
	}
	// The default is always explicit: the compiler decides it, so the
	// loader's own guesses (an address-less allow rule, or allow "*", turning
	// the default to allow) never apply.
	out.ConnectDefaultExplicit = true
	switch {
	case denyAll:
		// A forbid of every connection beats every permit.
		out.Connect = []lsm.PolicyRule{star(lsm.PolicyDeny)}
	default:
		out.Connect = append(denies, allows...)
		if allowAll {
			out.Connect = append(out.Connect, star(lsm.PolicyAllow))
			out.ConnectDefaultAllow = true
		}
	}
	return nil
}

// connectRuleFor encodes a Host atom as a kernel rule. "*:port" (any host on
// a port) is an address-less rule with the port, which the kernel keeps as
// is; "*" is the connect default rule.
func connectRuleFor(tr *CedarToLeashTranspiler, action int32, id string) (lsm.PolicyRule, error) {
	if port, ok := strings.CutPrefix(id, "*:"); ok {
		p, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return lsm.PolicyRule{}, err
		}
		return lsm.PolicyRule{Action: action, Operation: lsm.OpConnect, DestPort: uint16(p)}, nil
	}
	return tr.buildRule(action, "connect", Resource{Type: "Host", Value: id})
}
