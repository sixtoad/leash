package proxy

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/strongdm/leash/internal/engine"
)

func TestParseMCPBodyExtractsCallsStrictly(t *testing.T) {
	str := engine.StringValue
	for _, tc := range []struct {
		name      string
		body      string
		calls     []engine.MCPCall
		method    string
		malformed string // substring; "" = well-formed
	}{
		{name: "call with arguments",
			body:   `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":" search ","arguments":{"repo":"github.com/o/r","query":"auth","limit":5,"exact":true,"ratio":0.5,"filters":{"a":1},"paths":["x"],"none":null}}}`,
			method: "tools/call",
			calls: []engine.MCPCall{{Tool: "search", ArgsKnown: true,
				Args:     map[string]engine.Value{"repo": str("github.com/o/r"), "query": str("auth"), "limit": engine.LongValue(5), "exact": engine.BoolValue(true)},
				ArgNames: []string{"repo", "query", "limit", "exact", "ratio", "filters", "paths", "none"}}}},
		{name: "no arguments",
			body:   `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search"}}`,
			method: "tools/call",
			calls:  []engine.MCPCall{{Tool: "search", ArgsKnown: true, Args: map[string]engine.Value{}, ArgNames: []string{}}}},
		{name: "null arguments",
			body:   `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search","arguments":null}}`,
			method: "tools/call",
			calls:  []engine.MCPCall{{Tool: "search", ArgsKnown: true, Args: map[string]engine.Value{}, ArgNames: []string{}}}},
		// Go's struct decoding would read "Name" as name; servers do not.
		{name: "keys are case-sensitive",
			body:   `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search","Name":"index","arguments":{"repo":"r","Repo":"x"}}}`,
			method: "tools/call",
			calls:  []engine.MCPCall{{Tool: "search", ArgsKnown: true, Args: map[string]engine.Value{"repo": str("r"), "Repo": str("x")}, ArgNames: []string{"repo", "Repo"}}}},
		{name: "oversized string omitted but named",
			body:   fmt.Sprintf(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"s","arguments":{"repo":%q}}}`, strings.Repeat("a", engine.MaxMCPArgStringBytes+1)),
			method: "tools/call",
			calls:  []engine.MCPCall{{Tool: "s", ArgsKnown: true, Args: map[string]engine.Value{}, ArgNames: []string{"repo"}}}},
		{name: "integer out of range omitted",
			body:   `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"s","arguments":{"n":99999999999999999999}}}`,
			method: "tools/call",
			calls:  []engine.MCPCall{{Tool: "s", ArgsKnown: true, Args: map[string]engine.Value{}, ArgNames: []string{"n"}}}},
		{name: "too many arguments: unknown",
			body:   `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"s","arguments":{` + manyArgs(engine.MaxMCPArgs+1) + `}}}`,
			method: "tools/call",
			calls:  []engine.MCPCall{{Tool: "s"}}},
		{name: "long argument name: unknown",
			body:   fmt.Sprintf(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"s","arguments":{%q:1}}}`, strings.Repeat("k", engine.MaxMCPArgNameBytes+1)),
			method: "tools/call",
			calls:  []engine.MCPCall{{Tool: "s"}}},
		{name: "batch",
			body:   `[{"jsonrpc":"2.0","id":1,"method":"tools/list"},{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"search","arguments":{"repo":"r"}}},{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"index"}}]`,
			method: "tools/list",
			calls: []engine.MCPCall{
				{Tool: "search", ArgsKnown: true, Args: map[string]engine.Value{"repo": str("r")}, ArgNames: []string{"repo"}},
				{Tool: "index", ArgsKnown: true, Args: map[string]engine.Value{}, ArgNames: []string{}}}},
		{name: "not a call", body: `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, method: "tools/list"},
		{name: "not JSON-RPC", body: `{"model":"x","messages":[{"role":"user"}]}`},
		{name: "scalar", body: `42`},
		{name: "empty", body: ` `},
		// A JSON-RPC version mismatch is still enforced as a call.
		{name: "no jsonrpc member",
			body:   `{"method":"tools/call","params":{"name":"index"}}`,
			method: "tools/call",
			calls:  []engine.MCPCall{{Tool: "index", ArgsKnown: true, Args: map[string]engine.Value{}, ArgNames: []string{}}}},

		{name: "duplicate method", body: `{"jsonrpc":"2.0","method":"tools/list","method":"tools/call","params":{"name":"index"}}`, malformed: "duplicate object key"},
		{name: "duplicate tool name", body: `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"search","name":"index"}}`, malformed: "duplicate object key"},
		{name: "duplicate argument", body: `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"search","arguments":{"repo":"a","repo":"b"}}}`, malformed: "duplicate object key"},
		{name: "escaped duplicate argument", body: `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"search","arguments":{"repo":"a","repo":"b"}}}`, malformed: "duplicate object key"},
		{name: "duplicate in batch element", body: `[{"jsonrpc":"2.0","method":"tools/call","params":{"name":"s","name":"index"}}]`, malformed: "duplicate object key"},
		{name: "invalid JSON", body: `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"index","arguments":{"x":NaN}}}`, malformed: "not valid JSON"},
		{name: "trailing data", body: `{"jsonrpc":"2.0","method":"tools/list"} {"method":"tools/call"}`, malformed: "not valid JSON"},
		{name: "params missing", body: `{"jsonrpc":"2.0","method":"tools/call"}`, malformed: "without params"},
		{name: "params not object", body: `{"jsonrpc":"2.0","method":"tools/call","params":["index"]}`, malformed: "not an object"},
		{name: "name not string", body: `{"jsonrpc":"2.0","method":"tools/call","params":{"name":["index"]}}`, malformed: "params.name"},
		{name: "arguments not object", body: `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"s","arguments":"repo=x"}}`, malformed: "arguments is not an object"},
		{name: "batch too large", body: "[" + strings.TrimSuffix(strings.Repeat(`{"jsonrpc":"2.0","method":"tools/list"},`, maxMCPBatch+1), ",") + "]", malformed: "batch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := parseMCPBody([]byte(tc.body))
			if tc.malformed != "" {
				if !strings.Contains(got.malformed, tc.malformed) || got.calls != nil {
					t.Fatalf("want malformed %q, got %+v", tc.malformed, got)
				}
				return
			}
			if got.malformed != "" {
				t.Fatalf("unexpected malformed: %s", got.malformed)
			}
			if !reflect.DeepEqual(got.calls, tc.calls) {
				t.Fatalf("calls\n got %+v\nwant %+v", got.calls, tc.calls)
			}
			method := ""
			if got.envelope != nil {
				method = got.envelope.Method
			}
			if method != tc.method {
				t.Fatalf("method %q, want %q", method, tc.method)
			}
		})
	}
}

func manyArgs(n int) string {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = fmt.Sprintf(`"a%d":%d`, i, i)
	}
	return strings.Join(parts, ",")
}

// Every call the parser extracts is a valid engine request: the parser and
// the engine agree on the context's typing and limits.
func TestParsedCallsAreValidEngineRequests(t *testing.T) {
	e, err := engine.NewFromText("p", `permit (principal, action == Action::"McpCall", resource);`)
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{
		`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"s","arguments":{"a":"x","b":1,"c":true,"d":1.5,"e":{},"f":[]}}}`,
		`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"s","arguments":{` + manyArgs(engine.MaxMCPArgs) + `}}}`,
		`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"s","arguments":{` + manyArgs(engine.MaxMCPArgs+1) + `}}}`,
		fmt.Sprintf(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"s","arguments":{"r":%q}}}`, strings.Repeat("a", engine.MaxMCPArgStringBytes)),
	} {
		got := parseMCPBody([]byte(body))
		if len(got.calls) != 1 {
			t.Fatalf("%s: %+v", body, got)
		}
		if d := e.DecideMCPCall(got.calls[0]); !d.Allow {
			t.Fatalf("%s: engine rejected the parsed call: %+v", body, d)
		}
	}
}
