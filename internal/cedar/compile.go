package cedar

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	cedarlib "github.com/cedar-policy/cedar-go"

	"github.com/strongdm/leash/internal/engine"
	"github.com/strongdm/leash/internal/lsm"
	"github.com/strongdm/leash/internal/proxy"
	"github.com/strongdm/leash/internal/transpiler"
)

// Compilation is a Cedar policy layer ready to enforce (#142): the strict
// Cedar the engine evaluates, the engine, and the kernel tables compiled from
// the same strict set.
type Compilation struct {
	// Cedar is the source text.
	Cedar string
	// Semantics is how the source was read (legacy files are rewritten).
	Semantics transpiler.Semantics
	// Strict is the policy set every userspace decision evaluates.
	Strict *cedarlib.PolicySet
	// StrictText is Strict as Cedar text (the rewrite, for a legacy file).
	StrictText string
	// Rewrite describes the legacy rewrite (nil for a strict file).
	Rewrite *transpiler.RewriteReport
	// Engine decides userspace requests over Strict.
	Engine *engine.Engine
	// Warnings are the places where the kernel enforces more strictly than
	// Cedar decides (never more loosely).
	Warnings []transpiler.KernelWarning
	// Policies are the kernel tables compiled from Strict; Policies.Source
	// is the source, which policy.Manager merges layers by.
	Policies  *lsm.PolicySet
	HTTPRules []proxy.HeaderRewriteRule
}

// ErrorDetail captures structured Cedar error metadata surfaced to operators.
type ErrorDetail struct {
	Summary    string
	Message    string
	File       string
	Line       int
	Column     int
	Snippet    string
	CaretStart int
	CaretEnd   int
	Suggestion string
	Code       string
	// Policy is the ID of the policy a compile error names (empty for a
	// syntax error).
	Policy string
	Raw    error
}

func (d *ErrorDetail) Error() string {
	if d == nil {
		return ""
	}
	if d.Message != "" {
		return d.Message
	}
	return d.Summary
}

var parseLocationRe = regexp.MustCompile(`at\s+(.+?):(\d+):(\d+)`)

// policyRefRe extracts the policy ID of a compile error: "policy <id> at ...".
var policyRefRe = regexp.MustCompile(`^policy (.+?) at \S+:\d+:\d+`)

// CompileFile reads Cedar from disk and converts it into LSM/proxy policies.
// On parse errors, an *ErrorDetail is returned.
func CompileFile(path string) (*Compilation, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, &ErrorDetail{
			Summary:    "missing Cedar file path",
			Message:    "no Cedar file path provided",
			File:       "",
			Suggestion: "Provide the Cedar policy file path via --policy or LEASH_POLICY.",
			Code:       "CEDAR_CONFIG",
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, &ErrorDetail{
			Summary:    "failed to read Cedar policy",
			Message:    fmt.Sprintf("failed to read Cedar policy %q: %v", path, err),
			File:       path,
			Suggestion: "Ensure the Cedar file exists and the leash process can read it.",
			Code:       "CEDAR_IO",
			Raw:        err,
		}
	}
	compilation, err := CompileString(path, string(data))
	if err != nil {
		return nil, err
	}
	return compilation, nil
}

// CompileString compiles one Cedar layer: parse, read its semantics
// (@leash_semantics), rewrite a legacy file to strict Cedar, build the engine
// and compile the kernel tables. Any failure is an *ErrorDetail; nothing is
// skipped. The provided name is used for error reporting (typically a file
// path).
func CompileString(name, cedar string) (*Compilation, error) {
	comp, err := CompileLayers([]Layer{{Source: &lsm.PolicySource{Name: name, Text: cedar}}})
	if err != nil {
		return nil, formatCedarError(err, name, cedar)
	}
	comp.Cedar = cedar
	comp.Policies.Source = &lsm.PolicySource{Name: name, Text: cedar}
	if detail := unknownEntityError(name, cedar, comp); detail != nil {
		return nil, detail
	}
	return comp, nil
}

func formatCedarError(err error, filePath, cedar string) *ErrorDetail {
	if err == nil {
		return nil
	}
	message := strings.TrimSpace(err.Error())
	var policyErr *PolicyError
	isPolicyErr := errors.As(err, &policyErr)
	if root := rootError(err); !isPolicyErr && root != nil && root.Error() != "" {
		// A policy error keeps its whole message: it names the policy.
		message = strings.TrimSpace(root.Error())
	}
	file := strings.TrimSpace(filePath)
	line, column := 0, 0
	matches := parseLocationRe.FindStringSubmatch(err.Error())
	if len(matches) == 4 {
		if strings.TrimSpace(matches[1]) != "" {
			file = strings.TrimSpace(matches[1])
		}
		line = atoiSafe(matches[2])
		column = atoiSafe(matches[3])
	}
	if file == "<input>" || file == "" {
		file = strings.TrimSpace(filePath)
	}
	if file == "" {
		file = "<input>"
	}

	snippet := extractLine(cedar, line)
	caretStart, caretEnd := caretRange(snippet, column)
	summary := buildSummary(message)
	suggestion := suggestFix(message)
	code := classifyCode(message)
	policyID := ""
	if isPolicyErr {
		if m := policyRefRe.FindStringSubmatch(message); m != nil {
			policyID = m[1]
		}
		switch policyErr.Kind {
		case PolicyUnenforceableCondition:
			code = "CEDAR_UNENFORCEABLE_CONDITION"
			summary = "policy condition not enforceable: " + message
			suggestion = "Leash refuses a permit whose condition or principal constraint it cannot enforce, because enforcing it without that constraint would allow more than the policy says; see docs/design/AUTHZ-SERVICE.md section 4.3."
		case PolicyNotEnforceable:
			code = "CEDAR_NOT_ENFORCEABLE"
			summary = "policy not enforceable by the kernel: " + message
			suggestion = "Policies on file, exec and connect actions may only test resource membership and the action (no principal, context or @expires); see docs/design/AUTHZ-SERVICE.md section 3.3."
		default:
			code = "CEDAR_INVALID_POLICY"
			summary = "invalid policy: " + message
			suggestion = "Correct the named policy; see docs/design/AUTHZ-SERVICE.md."
		}
	}

	return &ErrorDetail{
		Policy:     policyID,
		Summary:    summary,
		Message:    message,
		File:       file,
		Line:       line,
		Column:     column,
		Snippet:    snippet,
		CaretStart: caretStart,
		CaretEnd:   caretEnd,
		Suggestion: suggestion,
		Code:       code,
		Raw:        err,
	}
}

func rootError(err error) error {
	for err != nil {
		unwrapped := errors.Unwrap(err)
		if unwrapped == nil {
			return err
		}
		err = unwrapped
	}
	return nil
}

func extractLine(content string, line int) string {
	if line <= 0 {
		return ""
	}
	current := 1
	start := 0
	for i := 0; i < len(content) && current < line; i++ {
		if content[i] == '\n' {
			current++
			start = i + 1
		}
	}
	if current != line {
		return ""
	}
	end := strings.IndexByte(content[start:], '\n')
	if end == -1 {
		return strings.TrimRight(content[start:], "\r\n")
	}
	return strings.TrimRight(content[start:start+end], "\r\n")
}

func caretRange(snippet string, column int) (int, int) {
	if column <= 0 {
		return 1, 1
	}
	runes := 0
	for i := 0; i < len(snippet); {
		_, width := utf8.DecodeRuneInString(snippet[i:])
		runes++
		if runes == column {
			return column, column
		}
		i += width
	}
	// Column extends beyond snippet; clamp to len+1 to point at EOL.
	return runes + 1, runes + 1
}

func atoiSafe(s string) int {
	v, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0
	}
	return v
}

func buildSummary(message string) string {
	msg := strings.TrimSpace(message)
	if msg == "" {
		return "invalid Cedar policy"
	}
	if idx := strings.Index(msg, ":"); idx > 0 && idx < len(msg)-1 {
		prefix := strings.TrimSpace(msg[:idx])
		suffix := strings.TrimSpace(msg[idx+1:])
		if prefix != "" && suffix != "" && strings.HasSuffix(strings.ToLower(prefix), "error") {
			return fmt.Sprintf("%s: %s", prefix, suffix)
		}
	}
	if len(msg) > 160 {
		msg = msg[:160]
	}
	return msg
}

func suggestFix(message string) string {
	lower := strings.ToLower(message)
	switch {
	case strings.Contains(lower, "want ,") || strings.Contains(lower, "expected ','"):
		return "Add a comma between parameters or statements at the highlighted position."
	case strings.Contains(lower, "unexpected token") && strings.Contains(lower, "permit"):
		return "Review the permit statement syntax and ensure parentheses and commas are balanced."
	case strings.Contains(lower, "unknown entity type"):
		return "Verify the entity type name is correct (e.g. Dir::\"/path\" or Host::\"example.com\")."
	case strings.Contains(lower, "unknown action"):
		return "Confirm the action name uses Cedar's Action entity with PascalCase (e.g., Action::\"ProcessExec\")."
	case strings.Contains(lower, "undeclared identifier"):
		return "Declare the identifier before using it or correct the spelling."
	default:
		return "Review the Cedar syntax near the highlighted column and correct the statement."
	}
}

func classifyCode(message string) string {
	lower := strings.ToLower(message)
	if strings.Contains(lower, "lint") {
		return "CEDAR_LINT"
	}
	return "CEDAR_PARSE"
}

// BuildErrorResponse converts an ErrorDetail into the JSON structure expected
// by the HTTP API and Control UI.
func BuildErrorResponse(detail *ErrorDetail) map[string]any {
	if detail == nil {
		return nil
	}
	return map[string]any{
		"message":    detail.Summary,
		"file":       detail.File,
		"line":       detail.Line,
		"column":     detail.Column,
		"snippet":    detail.Snippet,
		"caretStart": detail.CaretStart,
		"caretEnd":   detail.CaretEnd,
		"code":       detail.Code,
		"suggestion": detail.Suggestion,
		"policy":     detail.Policy,
	}
}
