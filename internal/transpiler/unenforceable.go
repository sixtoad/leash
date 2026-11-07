package transpiler

import (
	"fmt"
	"strings"

	cedarlib "github.com/cedar-policy/cedar-go"
	cedarast "github.com/cedar-policy/cedar-go/ast"
	"github.com/cedar-policy/cedar-go/types"
	xast "github.com/cedar-policy/cedar-go/x/exp/ast"

	"github.com/strongdm/leash/internal/engine"
)

// Unenforceable conditions (#164).
//
// A permit whose condition or principal constraint Leash cannot enforce must
// not load: enforcing it without the constraint would grant more than the
// policy says (fail-open). Two places can be asked to do that:
//
//   - The legacy rewrite. Legacy semantics enforce only `resource in [...]`
//     and context.hostname conditions on built-in actions; they ignored
//     principal constraints and every other condition, and read `unless` as
//     `when`. A legacy permit carrying any of those that still grants a file,
//     exec or connect rule is rejected. A legacy forbid that legacy
//     semantics would enforce on fewer requests than written (its resources
//     sat inside the ignored condition, or an `unless` would be read as the
//     forbid's resources) is rejected too; any other forbid keeps being
//     enforced without its condition (stricter), with a note.
//   - Strict McpCall policies (userspace only, evaluated by cedar.Authorize).
//     The MCP adapters supply context.server, context.args and
//     context.argNames (#113) and no principal or entity attributes, so a
//     policy reading anything else could never apply as written: rejected. Kernel actions are checked by CompileKernel's
//     subset, plugin actions are evaluated with the context the plugin sends
//     and are not restricted here.

// UnenforceableFinding is one policy Leash cannot enforce as written.
type UnenforceableFinding struct {
	// ID is the policy's display ID (engine.DisplayID).
	ID string
	// Policy is the policy reference: its ID and "at file:line:col".
	Policy string
	// Effect is "permit" or "forbid".
	Effect string
	// Reason says which construct cannot be enforced and why that matters.
	Reason string
}

func (f UnenforceableFinding) String() string {
	return fmt.Sprintf("policy %s: %s", f.Policy, f.Reason)
}

// UnenforceableError rejects a policy set with policies whose conditions
// or principal constraints Leash cannot enforce (#164).
type UnenforceableError struct {
	Findings []UnenforceableFinding
}

func (e *UnenforceableError) Error() string {
	if e == nil || len(e.Findings) == 0 {
		return "policy not enforceable as written"
	}
	parts := make([]string, len(e.Findings))
	for i, f := range e.Findings {
		parts[i] = f.String()
	}
	return strings.Join(parts, "; ")
}

// Issues renders the findings as lint issues.
func (e *UnenforceableError) Issues() []LintIssue {
	var out []LintIssue
	for _, f := range e.Findings {
		out = append(out, LintIssue{PolicyID: f.ID, Severity: LintError, Code: "unenforceable_condition", Message: f.String(),
			Suggestion: "Leash refuses a permit whose condition or principal constraint it cannot enforce (it would allow more than written), and a forbid it would enforce on fewer requests than written; see docs/design/AUTHZ-SERVICE.md section 4.3."})
	}
	return out
}

// legacyFindingRef names a legacy policy the way compile errors do:
// "<id> at <file>:<line>:<col>".
func legacyFindingRef(layer string, id string, p *cedarlib.Policy) string {
	name := engine.DisplayID(cedarlib.PolicyID(id), p)
	pos := p.Position()
	file := pos.Filename
	if file == "" {
		file = layer
	}
	if pos.Line > 0 {
		col := pos.Column
		if col <= 0 {
			col = 1
		}
		return fmt.Sprintf("%s at %s:%d:%d", name, file, pos.Line, col)
	}
	return fmt.Sprintf("%s at %s", name, file)
}

// legacyConstraints is what legacy semantics did with a policy's principal
// scope and conditions.
type legacyConstraints struct {
	principal     bool     // principal scope constrained (ignored)
	isType        string   // head `resource is T` (ignored), "" if none
	headResource  bool     // the head names an entity (it becomes rules)
	ignored       []string // conditions legacy ignored, as written
	unless        []string // unless clauses legacy read as `when`
	whenResources bool     // a when clause legacy turned into resources
	// mcpEntityOutside: an MCP::Server or MCP::Tool literal appears in an
	// ignored or unless clause (the legacy MCP lowering scans those).
	mcpEntityOutside bool
}

func classifyLegacyConstraints(pa *xast.Policy) legacyConstraints {
	var lc legacyConstraints
	if _, ok := pa.Principal.(xast.ScopeTypeAll); !ok {
		lc.principal = true
	}
	switch s := pa.Resource.(type) {
	case xast.ScopeTypeEq, xast.ScopeTypeIn:
		lc.headResource = true
	case xast.ScopeTypeIsIn:
		lc.headResource = true
		lc.isType = string(s.Type)
	case xast.ScopeTypeIs:
		lc.isType = string(s.Type)
	}
	for _, c := range pa.Conditions {
		text := conditionText(c)
		resourceClause, trivial := legacyHonoredClause(c.Body)
		switch {
		case c.Condition == xast.ConditionUnless:
			lc.unless = append(lc.unless, text)
		case resourceClause:
			lc.whenResources = true
			continue
		case trivial:
			continue
		default:
			lc.ignored = append(lc.ignored, text)
		}
		if mentionsMCPEntity(c.Body) {
			lc.mcpEntityOutside = true
		}
	}
	return lc
}

// legacyHonoredClause reports whether a when body is one legacy semantics
// enforced exactly: `resource in E`, `resource in [E, ...]`,
// `context.hostname == "name"` or `context.hostname like "pattern"`
// (resourceClause), or the literal `true` (trivial). The legacy parser
// reads each clause as a whole (it does not split `&&`), so these are the
// only forms whose meaning survived.
func legacyHonoredClause(n xast.IsNode) (resourceClause, trivial bool) {
	switch v := n.(type) {
	case xast.NodeValue:
		if b, ok := v.Value.(types.Boolean); ok && bool(b) {
			return false, true
		}
	case xast.NodeTypeIn:
		if _, ok := entityLiterals(v.Right); ok && isVar(v.Left, "resource") {
			return true, false
		}
	case xast.NodeTypeEquals:
		if isContextHostname(v.Left) {
			if lit, ok := v.Right.(xast.NodeValue); ok {
				if _, ok := lit.Value.(types.String); ok {
					return true, false
				}
			}
		}
	case xast.NodeTypeLike:
		if isContextHostname(v.Arg) {
			return true, false
		}
	}
	return false, false
}

func isContextHostname(n xast.IsNode) bool {
	a, ok := n.(xast.NodeTypeAccess)
	return ok && isVar(a.Arg, "context") && string(a.Value) == "hostname"
}

func mentionsMCPEntity(n xast.IsNode) bool {
	found := false
	xast.Inspect(xast.NewNode(n), func(n xast.IsNode) bool {
		if v, ok := n.(xast.NodeValue); ok {
			check := func(val types.Value) {
				if uid, ok := val.(types.EntityUID); ok {
					if t := string(uid.Type); t == engine.TypeMCPServer || t == engine.TypeMCPTool {
						found = true
					}
				}
			}
			check(v.Value)
			if set, ok := v.Value.(types.Set); ok {
				for e := range set.All() {
					check(e)
				}
			}
		}
		return !found
	})
	return found
}

// conditionText renders one when/unless clause as Cedar.
func conditionText(c xast.ConditionType) string {
	p := xast.Permit()
	p.Conditions = []xast.ConditionType{c}
	text := string(cedarlib.NewPolicyFromAST((*cedarast.Policy)(p)).MarshalCedar())
	for _, kw := range []string{"when", "unless"} {
		if i := strings.Index(text, "\n"+kw); i >= 0 {
			text = text[i+1:]
			break
		}
	}
	text = strings.TrimSuffix(strings.TrimSpace(text), ";")
	return strings.Join(strings.Fields(text), " ")
}

// legacyIsTypeHonored reports whether a head `resource is T` is a no-op for
// the requests a legacy policy's rules apply to (File for opens and execs,
// Host for connects); legacy semantics ignored it.
func legacyIsTypeHonored(isType string, paths, connect bool) bool {
	if isType == "" {
		return true
	}
	if paths && isType != engine.TypeFile {
		return false
	}
	if connect && isType != engine.TypeHost {
		return false
	}
	return true
}

// legacyUnenforceable returns why legacy semantics cannot enforce p as
// written in a way that is at least as strict, or "" when they can. u is
// p's lowering (after never-matching rules were dropped).
func legacyUnenforceable(p CedarPolicy, pa *xast.Policy, u *legacyUnit, isMCP bool) string {
	lc := classifyLegacyConstraints(pa)
	paths := len(u.open)+len(u.exec) > 0
	connect := len(u.connect) > 0
	if p.Effect == Permit {
		if !paths && !connect {
			return "" // grants nothing (MCP permits were no-ops)
		}
		var why []string
		if lc.principal {
			why = append(why, "its principal constraint (legacy semantics apply built-in policies to every principal)")
		}
		if !legacyIsTypeHonored(lc.isType, paths, connect) {
			why = append(why, fmt.Sprintf("`resource is %s` (ignored by legacy semantics; the requests are File or Host)", lc.isType))
		}
		for _, c := range lc.ignored {
			why = append(why, fmt.Sprintf("the condition `%s` (legacy semantics enforce only a whole condition `resource in [...]`, or `context.hostname` `==`/`like` a string)", c))
		}
		for _, c := range lc.unless {
			why = append(why, fmt.Sprintf("`%s` (legacy semantics read `unless` as `when`, granting what it excludes)", c))
		}
		if len(why) == 0 {
			return ""
		}
		hint := " Remove the constraint to grant unconditionally, or narrow the policy's resources instead."
		if len(lc.unless) > 0 {
			hint = " Express the exception as a forbid, or migrate the file to strict Cedar, the default dialect (`leash policy migrate`), where `unless { resource in [...] }` is enforced as written."
		}
		return "permit cannot be enforced as written: " + strings.Join(why, "; ") +
			". Legacy semantics would grant it without that constraint, allowing more than the policy says, so the load is refused." + hint
	}

	// Forbid: enforcing it without a constraint is stricter, unless legacy
	// semantics would take its resources from the ignored constraint.
	if isMCP {
		if lc.mcpEntityOutside {
			return "forbid cannot be enforced as written: it names MCP::Server or MCP::Tool entities inside a condition legacy semantics do not enforce as written (" +
				strings.Join(append(append([]string{}, lc.ignored...), lc.unless...), "; ") +
				"), and legacy semantics would forbid only those entities, fewer calls than the policy says." +
				" Put the forbid's servers and tools in the head or in `when { resource in [...] }`."
		}
		return ""
	}
	if len(lc.ignored)+len(lc.unless) == 0 || !hasKernelAction(p) {
		return ""
	}
	if lc.headResource || lc.whenResources {
		// Its resources are enforced; dropping the rest only widens the
		// forbid (stricter). The rewrite notes it.
		return ""
	}
	var why []string
	for _, c := range lc.ignored {
		why = append(why, fmt.Sprintf("`%s`", c))
	}
	for _, c := range lc.unless {
		why = append(why, fmt.Sprintf("`%s` (read as `when`)", c))
	}
	return "forbid cannot be enforced as written: its resources are not constrained outside " + strings.Join(why, "; ") +
		", so legacy semantics would drop the forbid or apply it to the wrong resources, forbidding less than the policy says." +
		" Name the forbidden resources in the head or in `when { resource in [...] }`."
}

// hasKernelAction reports whether a legacy policy names a file, exec or
// connect action.
func hasKernelAction(p CedarPolicy) bool {
	for _, a := range append(append([]string{}, p.Action.Actions...), p.Action.InSet...) {
		if !strings.HasPrefix(a, "Action::") {
			continue
		}
		switch strings.Trim(strings.TrimPrefix(a, "Action::"), `"`) {
		case engine.ActionFileOpen, engine.ActionFileOpenReadOnly, engine.ActionFileOpenReadWrite, engine.ActionProcessExec, engine.ActionNetworkConnect:
			return true
		}
	}
	return false
}

// mcpUnenforceable returns why a strict policy on McpCall cannot be
// enforced by the MCP adapters, or "" when it can. Those adapters (the HTTP
// proxy's tools/call check and the authz socket's built-in McpCall query)
// send the workload as principal, MCP::Tool/MCP::Server entities without
// attributes or tags, and a context holding `server` and, when the call's
// arguments are known, the record `args` and the set `argNames`
// (engine.MCPCall).
func mcpUnenforceable(pa *xast.Policy) string {
	for _, c := range pa.Conditions {
		if why := mcpUnavailable(c.Body); why != "" {
			return fmt.Sprintf("%s on McpCall cannot be enforced as written: `%s` uses %s, which the MCP adapters do not supply (they send context.server, context.args (a record of the call's arguments) and context.argNames), so the policy could never apply as written. Test `context.server`, `resource in MCP::Server::\"...\"`, a field of `context.args` (`context.args has repo && context.args.repo == \"...\"`) or `context.argNames` instead.", effectName(pa), conditionText(c), why)
		}
	}
	return ""
}

// mcpContextKeys are the McpCall context keys the adapters supply.
var mcpContextKeys = map[string]bool{
	engine.MCPContextServer:   true,
	engine.MCPContextArgs:     true,
	engine.MCPContextArgNames: true,
}

// isContextArgs reports whether n is `context.args`.
func isContextArgs(n xast.IsNode) bool {
	a, ok := n.(xast.NodeTypeAccess)
	return ok && isVar(a.Arg, "context") && string(a.Value) == engine.MCPContextArgs
}

func mcpUnavailable(body xast.IsNode) string {
	why := ""
	xast.Inspect(xast.NewNode(body), func(n xast.IsNode) bool {
		if why != "" {
			return false
		}
		switch v := n.(type) {
		case xast.NodeTypeAccess:
			if isContextArgs(v.Arg) {
				return false // a field of context.args
			}
			if isVar(v.Arg, "context") {
				switch {
				case string(v.Value) == engine.MCPContextArgs:
					// The record itself: only its fields are meaningful.
					why = "context.args as a value (it is a record: test its fields, e.g. `context.args.repo`)"
				case !mcpContextKeys[string(v.Value)]:
					why = fmt.Sprintf("context.%s", string(v.Value))
				}
				return false
			}
			why = fmt.Sprintf("the attribute .%s", string(v.Value))
			return false
		case xast.NodeTypeHas:
			if isContextArgs(v.Arg) {
				return false
			}
			if isVar(v.Arg, "context") {
				if !mcpContextKeys[string(v.Value)] {
					why = fmt.Sprintf("context has %s", string(v.Value))
				}
				return false
			}
			why = fmt.Sprintf("the attribute %s", string(v.Value))
			return false
		case xast.NodeTypeGetTag, xast.NodeTypeHasTag:
			why = "entity tags"
			return false
		case xast.NodeTypeVariable:
			switch string(v.Name) {
			case "principal":
				why = "the principal"
			case "context":
				why = "the context record"
			}
			return false
		}
		return true
	})
	return why
}

func effectName(pa *xast.Policy) string {
	if pa.Effect == xast.EffectForbid {
		return "forbid"
	}
	return "permit"
}
