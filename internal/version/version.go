// Package version is leash's CLI-side version layer: it turns the link-time
// build values into the document defined by
// github.com/strongdm/leash/pkg/leashversion and renders it, either as the three
// human lines `leash --version` has always printed or as JSON.
//
// The contract itself — the Info type, the contract bounds, the capability
// names, and the comparison helpers — deliberately does NOT live here. This is
// an internal package, so a consumer in another Go module (walk is
// github.com/sixto/walk) cannot import it; the contract lives in
// pkg/leashversion, which they can. Everything here is rendering and argument
// parsing, which only leash itself needs.
//
// The build values are injected into cmd/leash at link time
// (-X main.version/commit/buildDate), so they are passed in rather than read
// from a global: this package stays pure and unit-testable.
package version

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"runtime"
	"strconv"
	"strings"

	"github.com/strongdm/leash/pkg/leashversion"
)

// Re-exports so leash's own code and tests can say version.Info rather than
// importing both packages. pkg/leashversion is the canonical definition; these
// are aliases, not copies, so the two can never drift.
type (
	// Info is the emitted document. See leashversion.Info.
	Info = leashversion.Info
	// Compatibility is a caller-vs-leash verdict. See leashversion.Compatibility.
	Compatibility = leashversion.Compatibility
)

const (
	// ContractVersion is the current CLI surface. See leashversion.
	ContractVersion = leashversion.ContractVersion
	// MinCompatibleContract is the oldest caller contract served. See leashversion.
	MinCompatibleContract = leashversion.MinCompatibleContract
)

// Enforcing reports whether a leash built for goos carries an enforcement path
// in the binary itself, rather than only observing.
//
// The criterion is "does this binary ship and drive an enforcement mechanism",
// and it is derived from the build's target platform rather than hardcoded:
//
//   - linux: the eBPF LSM programs (file-open / exec / connect) plus the
//     intercepting MITM proxy.
//   - darwin: the same MITM proxy — the darwin runtime constructs it and pushes
//     policy into it (internal/darwind/runtime_darwin.go, NewMITMProxy /
//     applyPolicyToProxy) — alongside the separately installed Endpoint Security
//     and Network Extension components it coordinates with.
//
// Any other target is a build with no enforcement path at all.
//
// This is a statement about the binary, not about the machine: whether a given
// host can actually enforce (LSM active in the kernel, the system extension
// approved, the right capabilities) is a runtime question a build-time document
// deliberately does not answer. That is `leash doctor`'s job.
func Enforcing(goos string) bool {
	switch goos {
	case "linux", "darwin":
		return true
	default:
		return false
	}
}

// unknown is what the ldflags for commit and buildDate default to on a plain
// `go build`, and what we substitute for an empty value so consumers never have
// to special-case "". It is a documented, machine-detectable sentinel, not an
// error. (main.version defaults to "dev", not to this.)
const unknown = "unknown"

// shortHashLen is how many characters of a commit hash the output has always
// shown.
const shortHashLen = 7

// Build carries the link-time values from cmd/leash. Passing them as a struct
// keeps the call site in main() to a single expression and keeps this package
// free of globals.
type Build struct {
	Version   string // -X main.version, "dev" when unset
	Commit    string // -X main.commit, may carry a "-dirty" suffix
	BuildDate string // -X main.buildDate, RFC 3339 UTC from the Makefile
}

// Describe turns link-time build values into the reportable document for the
// platform this binary was built for.
//
// It returns the *compiling* program's own constants, so it is not a
// compatibility check: a provisioner that wants to know about an installed leash
// must run that binary and decode its stdout (leashversion.Parse). Describe
// exists to produce the document, not to consume one.
func Describe(b Build) Info {
	return describeFor(b, runtime.GOOS, runtime.GOARCH)
}

// describeFor is Describe with the platform injected, so tests can pin the
// document for a platform other than the one running them.
func describeFor(b Build, goos, goarch string) Info {
	return Info{
		Version:               orUnknown(b.Version),
		Commit:                shortCommit(b.Commit),
		BuiltAt:               orUnknown(b.BuildDate),
		Enforcing:             Enforcing(goos),
		ContractVersion:       leashversion.ContractVersion,
		MinCompatibleContract: leashversion.MinCompatibleContract,
		Capabilities:          leashversion.Capabilities(),
		OS:                    goos,
		Arch:                  goarch,
	}
}

// Human renders the three lines `leash --version` has printed since the
// beginning. Kept byte-for-byte identical for every value leash's build paths
// emit, which is also why it shows the bare abbreviated hash and drops any
// "-dirty" marker the JSON document keeps.
func Human(i Info) string {
	return fmt.Sprintf("version: %s\ngit hash: %s\nbuild date: %s\n",
		i.Version, humanCommit(i.Commit), i.BuiltAt)
}

// Run implements the `version` subcommand: args is everything after the
// subcommand word. Without a format flag it prints the historical human lines,
// so `leash version` and `leash --version` agree.
//
// `--help`/`-h` writes usage to out and returns flag.ErrHelp. cmd/leash treats
// that as a clean exit: asking for help is not a failure, and routing it through
// log.Fatal would stamp a timestamp on the usage text and exit 1.
func Run(args []string, b Build, out io.Writer) error {
	asJSON, err := parseArgs(args, out)
	if err != nil {
		return err
	}
	info := Describe(b)
	if !asJSON {
		_, err := io.WriteString(out, Human(info))
		return err
	}
	encoded, err := info.JSON()
	if err != nil {
		return err
	}
	_, err = out.Write(encoded)
	return err
}

// formatSpec is one format request as it appeared on the command line, kept so a
// contradiction can name both sides of itself in the diagnostic.
type formatSpec struct {
	spelling string // as the operator wrote it, near enough to be recognisable
	wantJSON bool
}

// formatFlag records every occurrence of a format flag, in command-line order,
// resolving each to a format as it is seen.
//
// It exists because flag.FlagSet.Visit cannot express this: a flag repeated on
// the command line is visited once, with the last value, so `--output json
// --output text` and `--json --json=false` would silently resolve by
// last-one-wins — the exact behaviour the subcommand promises not to have.
type formatFlag struct {
	isBool  bool
	parse   func(string) (bool, error)
	specs   *[]formatSpec
	display func(raw string) string
}

func (f *formatFlag) String() string { return "" }

// IsBoolFlag lets `--json` stand alone (and `--json=false` mean what it says),
// matching flag.Bool.
func (f *formatFlag) IsBoolFlag() bool { return f.isBool }

func (f *formatFlag) Set(raw string) error {
	wantJSON, err := f.parse(raw)
	if err != nil {
		return err
	}
	*f.specs = append(*f.specs, formatSpec{spelling: f.display(raw), wantJSON: wantJSON})
	return nil
}

// parseArgs resolves the subcommand's only concern — which output format was
// asked for — using the same flag package (and therefore the same -h handling
// and one-or-two-dash spellings) as the sibling subcommands.
//
// A format may be specified more than once; every occurrence must agree. Any
// contradiction is rejected, whether it crosses flags (`--json --output text`)
// or repeats one (`--output json --output text`, `--json --json=false`), and in
// either order. Silently taking the last one would make a scripted caller's
// output depend on argument order it did not think it was choosing.
func parseArgs(args []string, out io.Writer) (bool, error) {
	fs := flag.NewFlagSet("leash version", flag.ContinueOnError)
	// flag's own diagnostics would interleave with the document on stdout and
	// duplicate the error Run returns to main, so render usage ourselves.
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}

	var specs []formatSpec
	fs.Var(&formatFlag{
		isBool:  true,
		parse:   parseJSONFlag,
		specs:   &specs,
		display: func(raw string) string { return "--json=" + raw },
	}, "json", "emit the build document as JSON")
	fs.Var(&formatFlag{
		parse:   parseFormat,
		specs:   &specs,
		display: func(raw string) string { return "--output " + strconv.Quote(raw) },
	}, "output", "output format: json or text")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			if _, werr := io.WriteString(out, usage()); werr != nil {
				return false, werr
			}
			return false, flag.ErrHelp
		}
		return false, fmt.Errorf("%w (try `leash version --help`)", err)
	}
	if fs.NArg() > 0 {
		return false, fmt.Errorf("unknown argument %q for version; want --json or --output json|text", fs.Arg(0))
	}
	if len(specs) == 0 {
		return false, nil // no format asked for: the historical human lines.
	}
	// Booleans, so agreeing with the first is agreeing with all of them.
	for _, spec := range specs[1:] {
		if spec.wantJSON != specs[0].wantJSON {
			return false, fmt.Errorf("conflicting output formats: %s and %s; specify one",
				specs[0].spelling, spec.spelling)
		}
	}
	return specs[0].wantJSON, nil
}

// usage renders the help text for `version --help`.
//
// The flag list is written out rather than produced by fs.PrintDefaults, which
// prints the single-dash spelling (`-json`) and would contradict the usage line
// and the docs. Both spellings work — that is the flag package — so the help
// says so once instead of showing the form nobody is told to use.
func usage() string {
	var b strings.Builder
	b.WriteString("usage: leash version [--json | --output json|text]\n\n")
	b.WriteString("Print this build's metadata: by default the same three lines as\n")
	b.WriteString("'leash --version', or with --json the machine-readable document a\n")
	b.WriteString("provisioner reads to decide whether it can drive this leash\n")
	b.WriteString("(contractVersion, minCompatibleContract and capabilities).\n\n")
	b.WriteString("flags:\n")
	b.WriteString("  --json                 Emit the build document as JSON (same as --output json).\n")
	b.WriteString("  --output json|text     Output format. Default: text.\n")
	b.WriteString("  -h, --help             Print this usage and exit 0.\n\n")
	b.WriteString("A format may be repeated but not contradicted: --json --output text,\n")
	b.WriteString("--output json --output text and --json --json=false are all rejected.\n")
	b.WriteString("Single-dash spellings (-json, -output) are accepted too.\n")
	return b.String()
}

// parseFormat reports whether the requested --output value is JSON. An empty
// value is a caller bug ("--output=" or `--output ""`), not a request for the
// default, so it is rejected instead of quietly meaning text.
func parseFormat(value string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "json":
		return true, nil
	case "text":
		return false, nil
	case "":
		return false, errors.New("empty output format for --output; want json or text")
	default:
		return false, fmt.Errorf("unsupported output format %q; want json or text", value)
	}
}

// parseJSONFlag reports the format implied by a --json occurrence: --json (or
// --json=true) means JSON, --json=false means the human lines.
func parseJSONFlag(value string) (bool, error) {
	on, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("invalid boolean %q for --json; want true or false", value)
	}
	return on, nil
}

// splitCommit separates a commit value into the hash and any build suffix
// ("-dirty"), reporting whether the leading component is an abbreviatable hash
// at all.
//
// Only a hex hash may be shortened. A value whose leading component is not hex —
// a `git describe` string such as v1.2.3-4-gabc1234, or the "dev"/"unknown"
// sentinels — is returned whole, because cutting it at seven characters yields a
// fragment ("v1.2.3-") that names a different build than the one that emitted
// it. Truncation is a display convenience; it must never turn the document into
// a claim about a build that does not exist.
func splitCommit(commit string) (hash, suffix string, isHash bool) {
	trimmed := strings.TrimSpace(commit)
	hash, rest, found := strings.Cut(trimmed, "-")
	if !isHex(hash) {
		return trimmed, "", false
	}
	if found {
		return hash, "-" + rest, true
	}
	return hash, "", true
}

// shortCommit renders the commit for the JSON document: the hash abbreviated to
// the seven characters the human output has always shown, keeping any suffix, so
// a build from a modified tree cannot advertise itself to a provisioner as the
// pristine commit it was cut from.
func shortCommit(commit string) string {
	hash, suffix, isHash := splitCommit(commit)
	if !isHash {
		return orUnknown(hash)
	}
	return abbreviate(hash) + suffix
}

// humanCommit renders the `git hash:` line: the abbreviated hash alone, without
// the suffix, exactly as `leash --version` printed it before this package
// existed.
func humanCommit(commit string) string {
	hash, _, isHash := splitCommit(commit)
	if !isHash {
		return orUnknown(hash)
	}
	return abbreviate(hash)
}

func abbreviate(hash string) string {
	if len(hash) > shortHashLen {
		return hash[:shortHashLen]
	}
	return hash
}

func isHex(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}

func orUnknown(value string) string {
	if strings.TrimSpace(value) == "" {
		return unknown
	}
	return value
}
