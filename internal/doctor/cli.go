package doctor

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
)

// Exit codes. 0 is the only code that means "this machine can enforce", so
// every other outcome — including help, usage errors and a machine that only
// runs degraded — has to be distinguishable from it and from each other. A
// provisioner gating on `leash doctor && ...` fails closed on all of them.
const (
	exitReady     = 0 // at least one runtime enforces with every layer it has
	exitNoRuntime = 1 // no runtime can run a workload at all
	exitUsage     = 2 // bad invocation (also --help: not a verdict)
	exitDegraded  = 3 // a runtime runs, but not every enforcement layer is active
	exitInternal  = 4 // doctor could not render or deliver its own report
)

const usageExitNotes = `exit codes:
  0  a runtime enforces with every layer it has
  1  no runtime can run a workload
  2  usage error, or --help (never a readiness verdict)
  3  a runtime runs, but not every layer enforces
     (Linux: eBPF LSM / Layer 1 off, proxy-only. macOS: see the macOS section.)
  4  doctor could not render or write its report
`

// Main runs `leash doctor` and returns the process exit code. It returns rather
// than exits so the command stays testable and cmd/leash keeps a one-line case.
func Main(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("leash doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "emit the readiness report as JSON")
	// Opting *out* of the expensive check, not into it: the honest answer has
	// to be the default one, or doctor keeps shipping the guess issue #23 asked
	// leash to replace. --quick is for callers who want the cheap file reads
	// only (or who cannot afford to load a BPF program), and the report says so
	// under `not checked by doctor`.
	quick := fs.Bool("quick", false, "skip the checks that load kernel programs (BPF-LSM attachability); the report declares what was not checked")
	// The two macOS seams. They are flags rather than probed guesses because
	// both have a legitimate non-default value during development — a locally
	// built leashcli outside the app bundle, and a daemon on another port — and
	// reporting the default path as missing would be true but useless. They are
	// accepted on every platform so a script does not have to branch on GOOS;
	// off macOS they simply have nothing to configure.
	leashCLI := fs.String("leash-cli-path", "", "macOS: `path` to the companion leashcli binary (default "+DefaultLeashCLIPath+")")
	daemonAddr := fs.String("darwin-daemon", "", "macOS: `address` of the running \"leash --darwin\" daemon (default $LEASH_LISTEN, else "+DefaultDarwinDaemonAddr+")")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: leash doctor [--json] [--quick] [--leash-cli-path PATH] [--darwin-daemon ADDR]\n\nChecks whether this machine can enforce, per runtime.\n\nflags:\n")
		fs.PrintDefaults()
		fmt.Fprintf(stderr, "\n%s", usageExitNotes)
	}
	if err := fs.Parse(args); err != nil {
		// --help lands here too (flag.ErrHelp), and it gets the same code
		// deliberately: help is not a readiness verdict, and returning 0 for it
		// would hand a provisioner gating on the exit status a free pass from a
		// typo like `leash doctor -help`. One branch, because the two used to
		// be written out separately and read as if they differed.
		return exitUsage
	}
	// A positional argument means the caller asked for something this command
	// does not have. Ignoring it silently is worse than it sounds: `leash
	// doctor extra --json` parses as zero flags, so the caller would get human
	// text on stdout and try to parse it as JSON.
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "leash doctor: unexpected argument %q; this command takes no positional arguments\n", fs.Arg(0))
		fs.Usage()
		return exitUsage
	}

	report := Evaluate(ProbeWithOptions(ProbeOptions{
		Quick:            *quick,
		LeashCLIPath:     *leashCLI,
		DarwinDaemonAddr: *daemonAddr,
	}))

	// Render fully before writing a byte. Encoding straight to stdout would let
	// a half-written document escape and then be reported as a usage error,
	// which is neither true nor recoverable for the consumer parsing it.
	var out []byte
	if *asJSON {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fmt.Fprintf(stderr, "leash doctor: could not encode the report: %v\n", err)
			return exitInternal
		}
		out = buf.Bytes()
	} else {
		out = []byte(report.Text())
	}
	if _, err := stdout.Write(out); err != nil {
		fmt.Fprintf(stderr, "leash doctor: could not write the report: %v\n", err)
		return exitInternal
	}
	return report.ExitCode()
}
