package engine

import (
	"fmt"
	"sort"

	"github.com/cedar-policy/cedar-go/types"
)

// MCP tools/call arguments in the McpCall context (#113).
//
// A tools/call names a tool and passes it an `arguments` object. Policies
// that pin a call to one repository or scope (the Walk code-indexer
// capability) need the argument values, so the McpCall context carries the
// call's top-level arguments, strictly typed and bounded:
//
//	context.server    string        the normalized server (always present)
//	context.args      record        top-level arguments whose value is a
//	                                string (at most MaxMCPArgStringBytes),
//	                                a boolean or an integer in the 64-bit
//	                                range; nothing nested
//	context.argNames  set<string>   the name of every top-level argument,
//	                                including the ones args omits
//
// args and argNames are present together, or both absent when the adapter
// could not represent the arguments faithfully: more than MaxMCPArgs
// arguments, a name longer than MaxMCPArgNameBytes, or (the authz socket)
// a request that did not send them. A value args omits (an object, an
// array, a float, null, a string over the limit) is still named in
// argNames.
//
// Reading an absent key is a Cedar evaluation error, and a policy whose
// condition errors does not apply. That is fail-closed for a permit and
// fail-open for a forbid, so a policy should guard every read with `has`:
//
//	context has args && context.args has repo && context.args.repo == "r"
//
// and a forbid that must apply to calls it cannot read should be written
// as `unless { <that guarded condition> }`.
const (
	// MaxMCPArgs is the most top-level arguments the context represents.
	MaxMCPArgs = 64
	// MaxMCPArgNameBytes is the longest argument name it represents.
	MaxMCPArgNameBytes = 128
	// MaxMCPArgStringBytes is the longest string argument value context.args
	// carries; a longer value is omitted (its name stays in argNames).
	MaxMCPArgStringBytes = 4 << 10
)

// McpCall context keys.
const (
	MCPContextServer   = "server"
	MCPContextArgs     = "args"
	MCPContextArgNames = "argNames"
)

// MCPCall is one MCP tools/call as an adapter observed it.
type MCPCall struct {
	// Server is the server the call was sent to (a hostname or URL; it is
	// normalized like DecideMCP's server).
	Server string
	// Tool is the called tool's name.
	Tool string
	// ArgsKnown reports whether Args and ArgNames describe the call's
	// arguments. When false, context.args and context.argNames are absent.
	ArgsKnown bool
	// Args holds the representable top-level arguments: string, long or
	// boolean values only.
	Args map[string]Value
	// ArgNames names every top-level argument; every key of Args is in it.
	ArgNames []string
}

// DecideMCPCall decides an MCP tools/call with its arguments. A call whose
// arguments break the context's typing or limits is an invalid request
// (deny): adapters must drop what they cannot represent (see MCPCall).
func (e *Engine) DecideMCPCall(c MCPCall) Decision {
	if e == nil {
		return Decision{Reason: ReasonNoPolicy}
	}
	ctx, err := mcpContext(c)
	if err != nil {
		return invalidRequest("McpCall: %v", err)
	}
	res, parents := mcpResource(c.Server, c.Tool)
	return e.builtinRequest(ActionMcpCall, res, parents, ctx)
}

func mcpContext(c MCPCall) (types.Record, error) {
	m := types.RecordMap{MCPContextServer: types.String(NormalizeMCPServer(c.Server))}
	if !c.ArgsKnown {
		if len(c.Args) > 0 || len(c.ArgNames) > 0 {
			return types.Record{}, fmt.Errorf("arguments given but not marked known")
		}
		return types.NewRecord(m), nil
	}
	if len(c.ArgNames) > MaxMCPArgs {
		return types.Record{}, fmt.Errorf("%d arguments, over the limit of %d", len(c.ArgNames), MaxMCPArgs)
	}
	names := make(map[string]bool, len(c.ArgNames))
	set := make([]types.Value, 0, len(c.ArgNames))
	for _, n := range c.ArgNames {
		if len(n) > MaxMCPArgNameBytes {
			return types.Record{}, fmt.Errorf("argument name longer than %d bytes", MaxMCPArgNameBytes)
		}
		if names[n] {
			return types.Record{}, fmt.Errorf("argument %q named twice", n)
		}
		names[n] = true
		set = append(set, types.String(n))
	}
	args := make(types.RecordMap, len(c.Args))
	for k, v := range c.Args {
		if !names[k] {
			return types.Record{}, fmt.Errorf("argument %q is not in argNames", k)
		}
		switch v.Kind {
		case ValueString:
			if len(v.Str) > MaxMCPArgStringBytes {
				return types.Record{}, fmt.Errorf("argument %q: string longer than %d bytes", k, MaxMCPArgStringBytes)
			}
			args[types.String(k)] = types.String(v.Str)
		case ValueLong:
			args[types.String(k)] = types.Long(v.Long)
		case ValueBool:
			args[types.String(k)] = types.Boolean(v.Bool)
		default:
			return types.Record{}, fmt.Errorf("argument %q: only string, long and boolean values are supported", k)
		}
	}
	m[MCPContextArgs] = types.NewRecord(args)
	m[MCPContextArgNames] = types.NewSet(set...)
	return types.NewRecord(m), nil
}

// mcpCallFromRequest builds the MCPCall of a generic McpCall request (the
// authz socket): context.server (string), and optionally context.args (a
// record of string, long and boolean values) with context.argNames (a set
// of strings; when absent it is the keys of args).
func mcpCallFromRequest(req Request) (MCPCall, error) {
	c := MCPCall{Tool: req.Resource.ID}
	if v, ok := req.Context[MCPContextServer]; ok {
		if v.Kind != ValueString {
			return c, fmt.Errorf("context.server must be a string")
		}
		c.Server = v.Str
	}
	args, hasArgs := req.Context[MCPContextArgs]
	names, hasNames := req.Context[MCPContextArgNames]
	if !hasArgs && !hasNames {
		return c, nil
	}
	if !hasArgs {
		return c, fmt.Errorf("context.argNames needs context.args")
	}
	if args.Kind != ValueRecord {
		return c, fmt.Errorf("context.args must be a record")
	}
	c.ArgsKnown = true
	c.Args = args.Record
	if hasNames {
		if names.Kind != ValueSet {
			return c, fmt.Errorf("context.argNames must be a set of strings")
		}
		for _, n := range names.Set {
			if n.Kind != ValueString {
				return c, fmt.Errorf("context.argNames must be a set of strings")
			}
			c.ArgNames = append(c.ArgNames, n.Str)
		}
	} else {
		for k := range args.Record {
			c.ArgNames = append(c.ArgNames, k)
		}
		sort.Strings(c.ArgNames)
	}
	return c, nil
}
