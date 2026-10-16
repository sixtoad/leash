package leashd

import "strings"

// FatalLine renders a leashd startup error as the single "leash: FATAL: ..."
// line that launchers extract as the refusal reason (runner.lastFatalLine). A
// multi-line error (e.g. a formatted Cedar error) is joined with "; " so the
// whole reason survives the one-line extraction.
func FatalLine(err error) string {
	if err == nil {
		return ""
	}
	var parts []string
	for _, line := range strings.Split(err.Error(), "\n") {
		if line = strings.Join(strings.Fields(line), " "); line != "" {
			parts = append(parts, line)
		}
	}
	if len(parts) == 0 {
		return "leash: FATAL: leashd exited with an empty error"
	}
	return "leash: FATAL: " + strings.Join(parts, "; ")
}
