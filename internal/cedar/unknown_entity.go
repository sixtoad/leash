package cedar

import (
	"fmt"
	"strings"

	cedarlib "github.com/cedar-policy/cedar-go"

	"github.com/strongdm/leash/internal/engine"
)

// unknownEntityError returns an ErrorDetail for the first built-in policy that
// names an action or resource type Leash does not define, or nil when there is
// none. Such a policy can never match a request, so a typo'd forbid would be
// silently ignored (fail-open); compilation rejects it (#162).
//
// The type knowledge is the engine's own (engine.IsBuiltinAction,
// engine.IsBuiltinResourceType, engine.ClassifyActions), so every type the
// engine accepts — FilePrefix, MCP::Tool, ... — is accepted here. Plugin
// policies (<Ns>::Action::"...") use plugin-defined resource types and are not
// checked.
func unknownEntityError(name, cedar string, _ *Compilation) *ErrorDetail {
	ps, err := cedarlib.NewPolicySetFromBytes(name, []byte(cedar))
	if err != nil {
		return nil // the compile already succeeded; nothing more to report
	}
	type finding struct {
		id, kind, token, suggestion string
		offset                      int
	}
	var first *finding
	for id, p := range ps.All() {
		sc, err := engine.ClassifyActions(p)
		if err != nil || !sc.Builtin {
			continue
		}
		pos := p.Position()
		consider := func(f finding) {
			f.offset = pos.Offset
			if first == nil || f.offset < first.offset {
				ff := f
				first = &ff
			}
		}
		for _, a := range sc.Actions {
			if !engine.IsBuiltinAction(a) {
				consider(finding{id: engine.DisplayID(id, p), kind: "Action", token: a,
					suggestion: "Use FileOpen, FileOpenReadOnly, FileOpenReadWrite, ProcessExec, NetworkConnect, McpCall or HttpRewrite (or a plugin action <Namespace>::Action::\"...\")."})
				break
			}
		}
		for _, t := range engine.ResourceEntityTypes(p) {
			if !engine.IsBuiltinResourceType(t) {
				consider(finding{id: engine.DisplayID(id, p), kind: "Resource type", token: t,
					suggestion: "Use File, FilePrefix, Dir, Host, MCP::Tool or MCP::Server for Leash's own actions."})
				break
			}
		}
	}
	if first == nil {
		return nil
	}
	msg := fmt.Sprintf("unknown entity type or action: %s %q is not defined by Leash. A policy naming it would never match, so it would not be enforced.", first.kind, first.token)
	if id := strings.TrimSpace(first.id); id != "" {
		msg = fmt.Sprintf("policy %s: %s", id, msg)
	}
	file := strings.TrimSpace(name)
	if file == "" {
		file = "<input>"
	}
	needle := first.token
	if first.kind == "Action" {
		needle = `Action::"` + first.token + `"`
	}
	line, column := locateTokenFrom(cedar, needle, first.offset)
	snippet := extractLine(cedar, line)
	caretStart, caretEnd := caretRange(snippet, column)
	return &ErrorDetail{
		Summary:    "unknown entity type or action",
		Message:    msg,
		File:       file,
		Line:       line,
		Column:     column,
		Snippet:    snippet,
		CaretStart: caretStart,
		CaretEnd:   caretEnd,
		Suggestion: first.suggestion,
		Code:       "CEDAR_UNKNOWN_ENTITY",
	}
}

// locateTokenFrom finds the 1-based line and column of the first entity
// reference to token (as `token::`, `"token"` or the bare token) at or after
// byte offset from, falling back to the whole text; (0, 0) if absent.
func locateTokenFrom(cedar, token string, from int) (int, int) {
	if token == "" {
		return 0, 0
	}
	if from < 0 || from > len(cedar) {
		from = 0
	}
	for _, base := range []int{from, 0} {
		for _, needle := range []string{token + "::", `"` + token + `"`, token} {
			if idx := strings.Index(cedar[base:], needle); idx >= 0 {
				idx += base
				line := 1 + strings.Count(cedar[:idx], "\n")
				start := strings.LastIndexByte(cedar[:idx], '\n') + 1
				return line, 1 + len([]rune(cedar[start:idx]))
			}
		}
	}
	return 0, 0
}
