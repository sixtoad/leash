package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/strongdm/leash/internal/engine"
)

// MCP tools/call extraction for policy enforcement (#113).
//
// The enforcement path must see a call exactly as the MCP server will, or a
// crafted body could be decided as one call and executed as another. So the
// body is parsed strictly: object keys are matched case-sensitively (Go's
// struct decoding is case-insensitive), a duplicated key anywhere on the path
// to the tool name and its arguments makes the request ambiguous, and a
// JSON-RPC batch is decided call by call. A body the parser cannot decide
// unambiguously is "malformed"; while MCP policies are active such a request
// is denied (fail-closed) instead of being forwarded unchecked.

// governedMCPBodyLimit is the most request body the proxy reads ahead while
// MCP policies are active. A JSON body beyond it cannot be checked and is
// denied. It is larger than the observability sniff limit so ordinary large
// JSON requests (LLM API calls) still pass. A variable for tests.
var governedMCPBodyLimit = int64(64 << 20)

const (
	// maxMCPBatch is the most JSON-RPC requests one batch body may carry.
	maxMCPBatch = 64
)

// errDuplicateKey reports a JSON object with a key given twice.
var errDuplicateKey = errors.New("duplicate object key")

// strictObject decodes a JSON object into its members in order, rejecting
// duplicate keys. ok is false when raw is not an object.
func strictObject(raw []byte) (keys []string, members map[string]json.RawMessage, ok bool, err error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, nil, false, err
	}
	if d, isDelim := tok.(json.Delim); !isDelim || d != '{' {
		return nil, nil, false, nil
	}
	members = map[string]json.RawMessage{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, nil, true, err
		}
		key, isString := tok.(string)
		if !isString {
			return nil, nil, true, fmt.Errorf("object key is not a string")
		}
		if _, dup := members[key]; dup {
			return nil, nil, true, fmt.Errorf("%w %q", errDuplicateKey, key)
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, nil, true, err
		}
		keys = append(keys, key)
		members[key] = v
	}
	if _, err := dec.Token(); err != nil { // the closing '}'
		return nil, nil, true, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, nil, true, fmt.Errorf("trailing data after the object")
	}
	return keys, members, true, nil
}

func isJSONNull(raw json.RawMessage) bool {
	return len(raw) == 0 || string(bytes.TrimSpace(raw)) == "null"
}

// mcpBody is what a request body holds for MCP observation and enforcement.
type mcpBody struct {
	// envelope is the first JSON-RPC request with a method (observation).
	envelope *parsedEnvelope
	// calls are the body's tools/call requests, in order; their Server is
	// filled in by the caller.
	calls []engine.MCPCall
	// malformed says why the body cannot be decided unambiguously.
	malformed string
}

// parseMCPBody parses a complete JSON request body.
func parseMCPBody(body []byte) mcpBody {
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if len(trimmed) == 0 {
		return mcpBody{}
	}
	if !json.Valid(trimmed) {
		return mcpBody{malformed: "request body is not valid JSON"}
	}
	var out mcpBody
	switch trimmed[0] {
	case '[':
		var elems []json.RawMessage
		if err := json.Unmarshal(trimmed, &elems); err != nil {
			return mcpBody{malformed: "invalid JSON-RPC batch"}
		}
		if len(elems) > maxMCPBatch {
			return mcpBody{malformed: fmt.Sprintf("JSON-RPC batch of %d requests, over the limit of %d", len(elems), maxMCPBatch)}
		}
		for _, el := range elems {
			if why := out.addRequest(el); why != "" {
				return mcpBody{malformed: why}
			}
		}
	case '{':
		if why := out.addRequest(trimmed); why != "" {
			return mcpBody{malformed: why}
		}
	}
	return out
}

// addRequest parses one JSON-RPC request object. It returns why the request
// is malformed, or "".
func (b *mcpBody) addRequest(raw []byte) string {
	_, obj, isObject, err := strictObject(raw)
	if err != nil {
		return "JSON-RPC request: " + err.Error()
	}
	if !isObject {
		return "" // not a request; the server rejects it
	}
	var method string
	if m, ok := obj["method"]; ok {
		if json.Unmarshal(m, &method) != nil {
			return "" // a non-string method is no call
		}
	}
	method = strings.TrimSpace(method)
	if method == "" {
		return ""
	}
	env := &parsedEnvelope{Method: method}
	if v, ok := obj["jsonrpc"]; ok {
		_ = json.Unmarshal(v, &env.JSONRPC)
	}
	if id, ok := obj["id"]; ok && !isJSONNull(id) {
		env.ID = normalizeID(id)
	}
	if method == "tools/call" {
		call, why := parseToolsCall(obj["params"])
		if why != "" {
			return why
		}
		env.ToolName = call.Tool
		b.calls = append(b.calls, call)
	}
	if b.envelope == nil {
		b.envelope = env
	}
	return ""
}

// parseToolsCall extracts the tool name and arguments of tools/call params.
func parseToolsCall(params json.RawMessage) (engine.MCPCall, string) {
	var call engine.MCPCall
	if isJSONNull(params) {
		return call, "tools/call without params"
	}
	_, p, isObject, err := strictObject(params)
	if err != nil {
		return call, "tools/call params: " + err.Error()
	}
	if !isObject {
		return call, "tools/call params is not an object"
	}
	rawName, ok := p["name"]
	if !ok || json.Unmarshal(rawName, &call.Tool) != nil {
		return call, "tools/call params.name is not a string"
	}
	call.Tool = strings.TrimSpace(call.Tool)
	rawArgs, ok := p["arguments"]
	call.ArgsKnown = true
	call.Args = map[string]engine.Value{}
	call.ArgNames = []string{}
	if !ok || isJSONNull(rawArgs) {
		return call, ""
	}
	names, args, isObject, err := strictObject(rawArgs)
	if err != nil {
		return call, "tools/call params.arguments: " + err.Error()
	}
	if !isObject {
		return call, "tools/call params.arguments is not an object"
	}
	if len(names) > engine.MaxMCPArgs {
		return unknownArgs(call), ""
	}
	for _, n := range names {
		if len(n) > engine.MaxMCPArgNameBytes {
			return unknownArgs(call), ""
		}
	}
	call.ArgNames = names
	for _, n := range names {
		if v, ok := argValue(args[n]); ok {
			call.Args[n] = v
		}
	}
	return call, ""
}

// unknownArgs marks a call whose arguments the context cannot represent.
func unknownArgs(c engine.MCPCall) engine.MCPCall {
	c.ArgsKnown, c.Args, c.ArgNames = false, nil, nil
	return c
}

// argValue converts a top-level argument value the McpCall context can carry:
// a string within the limit, a boolean, or an integer in the 64-bit range.
func argValue(raw json.RawMessage) (engine.Value, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if dec.Decode(&v) != nil {
		return engine.Value{}, false
	}
	switch x := v.(type) {
	case string:
		if len(x) > engine.MaxMCPArgStringBytes {
			return engine.Value{}, false
		}
		return engine.StringValue(x), true
	case bool:
		return engine.BoolValue(x), true
	case json.Number:
		n, err := strconv.ParseInt(x.String(), 10, 64)
		if err != nil {
			return engine.Value{}, false
		}
		return engine.LongValue(n), true
	}
	return engine.Value{}, false
}
