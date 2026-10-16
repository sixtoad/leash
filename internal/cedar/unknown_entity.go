package cedar

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/strongdm/leash/internal/transpiler"
)

// unknownEntityCodes are the lint findings for an entity type or action Leash
// does not know. The transpiler drops such a policy without an error, so a
// typo'd forbid would be silently ignored (fail-open); compilation rejects it.
var unknownEntityCodes = map[string]bool{
	"unsupported_resource_type": true,
	"unsupported_action_id":     true,
	"unsupported_action_syntax": true,
}

var quotedRe = regexp.MustCompile(`"(?:[^"\\]|\\.)*"`)

// unknownEntityError returns an ErrorDetail for the first policy that names an
// unknown entity type or action, or nil when there is none.
func unknownEntityError(name, cedar string) *ErrorDetail {
	report, err := transpiler.LintFromString(cedar)
	if err != nil || report == nil {
		return nil // the transpile already succeeded; nothing more to report
	}
	for _, issue := range report.Issues {
		if issue.Severity != transpiler.LintError || !unknownEntityCodes[issue.Code] {
			continue
		}
		msg := fmt.Sprintf("unknown entity type or action: %s A policy naming it would be dropped, not enforced.", strings.TrimSpace(issue.Message))
		if id := strings.TrimSpace(issue.PolicyID); id != "" {
			msg = fmt.Sprintf("policy %s: %s", id, msg)
		}
		file := strings.TrimSpace(name)
		if file == "" {
			file = "<input>"
		}
		line, column := locateToken(cedar, issueToken(issue.Message))
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
			Suggestion: strings.TrimSpace(issue.Suggestion),
			Code:       "CEDAR_UNKNOWN_ENTITY",
		}
	}
	return nil
}

// issueToken extracts the quoted name from a lint message (`Resource type "X"`).
func issueToken(message string) string {
	m := quotedRe.FindString(message)
	if m == "" {
		return ""
	}
	if s, err := strconv.Unquote(m); err == nil {
		return s
	}
	return strings.Trim(m, `"`)
}

// locateToken finds the 1-based line and column of the first occurrence of an
// entity reference to token (as `token::` or `"token"`), or (0, 0).
func locateToken(cedar, token string) (int, int) {
	if token == "" {
		return 0, 0
	}
	for _, needle := range []string{token + "::", `"` + token + `"`, token} {
		if idx := strings.Index(cedar, needle); idx >= 0 {
			line := 1 + strings.Count(cedar[:idx], "\n")
			start := strings.LastIndexByte(cedar[:idx], '\n') + 1
			return line, 1 + len([]rune(cedar[start:idx]))
		}
	}
	return 0, 0
}
