package doctor

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
)

// Exit codes. 1 is reserved for the verdict itself (no runtime can enforce) so
// a provisioner can branch on it; usage errors take a distinct 2 rather than
// masquerading as an unusable machine.
const (
	exitUsable    = 0
	exitNoRuntime = 1
	exitUsage     = 2
)

// Main runs `leash doctor` and returns the process exit code. It returns rather
// than exits so the command stays testable and cmd/leash keeps a one-line case.
func Main(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("leash doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "emit the readiness report as JSON")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: leash doctor [--json]\n\nChecks whether this machine can enforce, per runtime.\nExits 1 when neither the native nor the container runtime is usable.\n\nflags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitUsable
		}
		return exitUsage
	}

	report := Evaluate(Probe())
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fmt.Fprintf(stderr, "leash doctor: %v\n", err)
			return exitUsage
		}
	} else {
		fmt.Fprint(stdout, report.Text())
	}
	return report.ExitCode()
}
