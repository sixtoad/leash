package runner

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Bounds for the target log excerpt surfaced when the target dies during
// bootstrap. Short on purpose: it is a pointer at the real failure, not a log
// dump, and every extra line is another chance to leak something.
const (
	targetLogTailLines   = 20
	targetLogLineMaxRune = 240
	targetLogMaxBytes    = 4096
	targetDiagTimeout    = 10 * time.Second
)

// targetBootstrapError reports that the target container stopped while leash was
// still bootstrapping it. It is the primary diagnostic; a sidecar launch failure
// it caused (e.g. "cannot join network namespace of a non running container") is
// kept only as secondary context (#81).
type targetBootstrapError struct {
	container string
	phase     string // e.g. "before the leash sidecar could start"
	state     string // containerSummary, e.g. "exited (exit=1)"
	exitCode  int    // -1 when unknown
	logs      string // sanitized, bounded tail; "" when unavailable
	secondary error  // the error this failure caused, if any
}

func (e *targetBootstrapError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "target container %s exited %s", e.container, e.phase)
	if e.exitCode >= 0 {
		fmt.Fprintf(&b, " (exit code %d)", e.exitCode)
	} else {
		fmt.Fprintf(&b, " (state=%s)", e.state)
	}
	if e.logs != "" {
		fmt.Fprintf(&b, "\nLast target log lines (sanitized):\n%s", indentLines(e.logs, "  "))
	} else {
		fmt.Fprintf(&b, "\nNo target log output was available.")
	}
	if e.secondary != nil {
		fmt.Fprintf(&b, "\n(secondary: %v)", e.secondary)
	}
	return b.String()
}

func (e *targetBootstrapError) Unwrap() error { return e.secondary }

// targetBootstrapFailure inspects the target and, when it is no longer running
// (exited, dead, or already gone), returns a targetBootstrapError carrying its
// exit code and a sanitized log tail. It returns nil while the target is running
// or when its state cannot be determined, so callers keep their own error. It
// runs on a non-cancelled, bounded context so the diagnostic is captured even
// while the run is being torn down, and before cleanup removes the container.
func (r *runner) targetBootstrapFailure(ctx context.Context, phase string, secondary error) *targetBootstrapError {
	diagCtx, cancel := context.WithTimeout(cleanupContext(ctx), targetDiagTimeout)
	defer cancel()
	name := r.cfg.targetContainer
	state := r.containerSummary(diagCtx, name)
	switch statusCategory(state) {
	case "exited", "dead", "missing":
	default:
		return nil
	}
	e := &targetBootstrapError{
		container: name,
		phase:     phase,
		state:     state,
		exitCode:  summaryExitCode(state),
		secondary: secondary,
	}
	if statusCategory(state) != "missing" {
		if out, err := r.rt().Output(diagCtx, "logs", "--tail", strconv.Itoa(targetLogTailLines), name); err == nil {
			e.logs = sanitizeContainerLogs(out)
		}
	}
	return e
}

// summaryExitCode extracts N from a containerSummary like "exited (exit=N)".
func summaryExitCode(summary string) int {
	const marker = "(exit="
	i := strings.Index(summary, marker)
	if i < 0 {
		return -1
	}
	rest := summary[i+len(marker):]
	j := strings.IndexByte(rest, ')')
	if j < 0 {
		return -1
	}
	n, err := strconv.Atoi(rest[:j])
	if err != nil {
		return -1
	}
	return n
}

var (
	// key=value / key: value / "key": "value" where the key names a credential.
	credentialAssignment = regexp.MustCompile(`(?i)([A-Za-z0-9_.-]*(?:api[_-]?key|access[_-]?key|private[_-]?key|secret|token|passw(?:or)?d|passwd|credential|auth|cookie|session)[A-Za-z0-9_.-]*"?\s*[:=]\s*)("[^"]*"|'[^']*'|\S+)`)
	// Authorization-style schemes.
	authScheme = regexp.MustCompile(`(?i)\b(bearer|basic|token)\s+[A-Za-z0-9._~+/=-]{8,}`)
	// Credentials embedded in URLs.
	urlUserinfo = regexp.MustCompile(`://[^/\s:@]+:[^/\s@]+@`)
	// Well-known token shapes, and long opaque base64/hex-ish blobs.
	knownTokens    = regexp.MustCompile(`\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})|\b[A-Za-z0-9+_]{40,}={0,2}`)
	privateKeyLine = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)
)

// redactCredentials masks obvious credential patterns in one log line. It is a
// best-effort filter for an error message, not a guarantee; the excerpt is also
// kept short for that reason.
func redactCredentials(line string) string {
	if privateKeyLine.MatchString(line) {
		return "<redacted private key>"
	}
	line = urlUserinfo.ReplaceAllString(line, "://<redacted>@")
	line = authScheme.ReplaceAllString(line, "$1 <redacted>")
	line = credentialAssignment.ReplaceAllString(line, "${1}<redacted>")
	line = knownTokens.ReplaceAllString(line, "<redacted>")
	return line
}

// sanitizeContainerLogs turns raw `logs --tail` output into a bounded, printable,
// credential-redacted excerpt: control/escape sequences stripped, at most
// targetLogTailLines lines of at most targetLogLineMaxRune runes each, and at
// most targetLogMaxBytes overall (keeping the most recent lines).
func sanitizeContainerLogs(raw string) string {
	var lines []string
	for _, line := range strings.FieldsFunc(raw, func(r rune) bool { return r == '\n' || r == '\r' }) {
		line = sanitizeControl(line)
		if line == "" {
			continue
		}
		line = redactCredentials(line)
		if utf8.RuneCountInString(line) > targetLogLineMaxRune {
			line = string([]rune(line)[:targetLogLineMaxRune]) + "..."
		}
		lines = append(lines, line)
	}
	if len(lines) > targetLogTailLines {
		lines = lines[len(lines)-targetLogTailLines:]
	}
	total := 0
	start := len(lines)
	for start > 0 {
		n := len(lines[start-1]) + 1
		if total+n > targetLogMaxBytes {
			break
		}
		total += n
		start--
	}
	return strings.Join(lines[start:], "\n")
}
