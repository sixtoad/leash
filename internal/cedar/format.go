package cedar

import (
	"fmt"
	"strings"
)

// FormatForCLI renders a Cedar error for a terminal: the file location, the
// offending line with a caret when a snippet is available, the message, and the
// hint. The message is always included: an error without a snippet (an I/O
// failure, a kernel-subset rejection) would otherwise print only the location
// and a generic hint, losing the reason.
func FormatForCLI(detail *ErrorDetail) string {
	if detail == nil {
		return "error: invalid Cedar policy"
	}
	var b strings.Builder
	b.WriteString("error: invalid Cedar policy\n")
	if detail.File != "" {
		line := detail.Line
		if line <= 0 {
			line = 1
		}
		col := detail.Column
		if col <= 0 {
			col = detail.CaretStart
		}
		if col <= 0 {
			col = 1
		}
		fmt.Fprintf(&b, "file: %s:%d:%d\n", detail.File, line, col)
	}
	msg := strings.TrimSpace(detail.Message)
	if msg == "" {
		msg = strings.TrimSpace(detail.Summary)
	}
	if detail.Snippet != "" && detail.Line > 0 {
		fmt.Fprintf(&b, "%d | %s\n", detail.Line, detail.Snippet)
		caretPos := detail.CaretStart
		if caretPos <= 0 {
			caretPos = detail.Column
		}
		if caretPos <= 0 {
			caretPos = 1
		}
		fmt.Fprintf(&b, "   | %s^", strings.Repeat(" ", caretPos-1))
		if msg != "" {
			fmt.Fprintf(&b, " %s", msg)
		}
		b.WriteByte('\n')
	} else if msg != "" {
		fmt.Fprintf(&b, "message: %s\n", msg)
	}
	if hint := strings.TrimSpace(detail.Suggestion); hint != "" {
		fmt.Fprintf(&b, "hint: %s\n", hint)
	}
	return strings.TrimSpace(b.String())
}
