// Package engine is Leash's single authorization decision engine (#142).
//
// Every userspace decision (the MITM proxy's connect check, MCP tools/call,
// the plugin authorization socket) is a Cedar request evaluated by cedar-go's
// own evaluator (cedar.Authorize) against the active, strict-Cedar policy set.
// There is no second evaluator: the only Leash-specific code here builds the
// request (the entity hierarchy Leash defines for files, hosts and MCP tools)
// and routes it to the policies that may apply (the namespace rule below).
//
// The kernel (eBPF) and the macOS extensions cannot call Go. They enforce
// tables compiled from the same strict policy set by
// transpiler.CompileKernel, which accepts only a subset of Cedar whose
// compilation is equivalent to this engine; the parity tests check it.
//
// Namespace rule: a request for a plugin action (<Namespace>::Action::"Verb")
// is evaluated only against the policies whose action scope names that
// namespace. A policy with an unconstrained action scope applies to Leash's
// built-in actions (Action::"...") only, so a broad `forbid (principal,
// action, resource)` written for the workload never silently decides a
// plugin's question, and a plugin grant is always explicit.
package engine

import (
	"fmt"
	"strconv"
	"strings"
)

// EntityUID names a Cedar entity: Type is the full entity type path (e.g.
// "File", "MCP::Tool", "Secret::Item"), ID its identifier.
type EntityUID struct {
	Type string
	ID   string
}

// String renders the UID in Cedar syntax: Type::"id".
func (e EntityUID) String() string { return e.Type + "::" + strconv.Quote(e.ID) }

// IsZero reports whether the UID is unset.
func (e EntityUID) IsZero() bool { return e.Type == "" && e.ID == "" }

// Built-in action IDs. Their entity type is the root "Action" namespace,
// which is reserved for Leash.
const (
	BuiltinActionType       = "Action"
	ActionFileOpen          = "FileOpen" // group: FileOpenReadOnly and FileOpenReadWrite are in it
	ActionFileOpenReadOnly  = "FileOpenReadOnly"
	ActionFileOpenReadWrite = "FileOpenReadWrite"
	ActionProcessExec       = "ProcessExec"
	ActionNetworkConnect    = "NetworkConnect"
	ActionMcpCall           = "McpCall"
	ActionHttpRewrite       = "HttpRewrite" // configuration, never requested
)

// Entity types of Leash's built-in resources.
const (
	TypeFile       = "File"       // an exact path
	TypeFilePrefix = "FilePrefix" // every path these bytes prefix
	TypeDir        = "Dir"
	TypeHost       = "Host"
	TypeMCPTool    = "MCP::Tool"
	TypeMCPServer  = "MCP::Server"
	TypePlugin     = "Plugin"
	TypeWorkload   = "Workload"
)

// WorkloadPrincipal is the principal of every built-in request. The kernel
// and the proxy enforce for the whole workload and cannot tell principals
// apart, so built-in policies may not constrain the principal (the kernel
// compiler rejects them) and this value never changes a decision.
var WorkloadPrincipal = EntityUID{Type: TypeWorkload, ID: "workload"}

// PluginActionNamespace returns the namespace of a plugin action type
// ("Secret::Action" -> "Secret"). The root "Action" type is Leash's own.
func PluginActionNamespace(actionType string) (string, bool) {
	ns, ok := strings.CutSuffix(actionType, "::Action")
	if !ok || ns == "" {
		return "", false
	}
	return ns, true
}

// Decision reasons. They are part of the authz wire contract: add new ones,
// never rename.
const (
	ReasonMatchedPermit     = "matched_permit"
	ReasonMatchedForbid     = "matched_forbid"
	ReasonDefaultAllow      = "default_allow" // reserved: strict Cedar has no default allow
	ReasonDefaultDeny       = "default_deny"
	ReasonUnsupportedAction = "unsupported_action"
	ReasonInvalidRequest    = "invalid_request"
	ReasonNoPolicy          = "no_policy"
)

// Decision is the result of one evaluation.
type Decision struct {
	Allow bool
	// Reason is one of the Reason* constants.
	Reason string
	// PolicyIDs are the deciding policies (their @id, or the Cedar policy ID):
	// every applicable forbid for a deny, every applicable permit for an
	// allow, exactly cedar.Authorize's diagnostic reasons.
	PolicyIDs []string
	// Detail carries a human-readable note for invalid or unsupported
	// requests, and the evaluation errors of policies that did not apply.
	Detail string
}

func invalidRequest(format string, args ...any) Decision {
	return Decision{Reason: ReasonInvalidRequest, Detail: fmt.Sprintf(format, args...)}
}

// Request is a generic authorization request, the shape the authz socket
// accepts. Built-in actions:
//
//	FileOpenReadOnly / FileOpenReadWrite  resource File::"<absolute path>"
//	FileOpen                              allowed only when both of the above are
//	ProcessExec                           resource File::"<absolute path>"
//	NetworkConnect                        resource Host::"<hostname or IP>", context.port (long, optional), context.ip (string, optional)
//	McpCall                               resource MCP::Tool::"<tool>", context.server (string)
//
// The built-in principal is always WorkloadPrincipal. Any other action must
// be a plugin action (Namespace::Action::"Name"), evaluated with the given
// principal, resource (no entity hierarchy) and context.
type Request struct {
	Principal EntityUID
	Action    EntityUID
	Resource  EntityUID
	Context   map[string]Value
}

// ValueKind is the type of a Value.
type ValueKind uint8

const (
	ValueString ValueKind = iota + 1
	ValueLong
	ValueBool
	ValueSet
	ValueEntity
)

// Value is a Cedar context value. Records and extension types are not
// supported on the wire.
type Value struct {
	Kind   ValueKind
	Str    string
	Long   int64
	Bool   bool
	Set    []Value
	Entity EntityUID
}

// Value constructors.
func StringValue(s string) Value      { return Value{Kind: ValueString, Str: s} }
func LongValue(n int64) Value         { return Value{Kind: ValueLong, Long: n} }
func BoolValue(b bool) Value          { return Value{Kind: ValueBool, Bool: b} }
func SetValue(vs ...Value) Value      { return Value{Kind: ValueSet, Set: vs} }
func EntityValue(uid EntityUID) Value { return Value{Kind: ValueEntity, Entity: uid} }

// String renders the value in Cedar syntax.
func (v Value) String() string {
	switch v.Kind {
	case ValueString:
		return strconv.Quote(v.Str)
	case ValueLong:
		return strconv.FormatInt(v.Long, 10)
	case ValueBool:
		return strconv.FormatBool(v.Bool)
	case ValueEntity:
		return v.Entity.String()
	case ValueSet:
		parts := make([]string, len(v.Set))
		for i, e := range v.Set {
			parts[i] = e.String()
		}
		return "[" + strings.Join(parts, ", ") + "]"
	}
	return "<invalid>"
}
