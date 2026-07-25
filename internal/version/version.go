// Package version renders leash's build metadata, both as the human lines
// `leash --version` has always printed and as a machine-readable document for
// provisioners (notably walk) that install a leash binary and need to verify
// they got a runtime they can drive.
//
// The build values themselves are injected into cmd/leash at link time
// (-X main.version/commit/buildDate), so they are passed in here rather than
// read from a global: this package stays pure and unit-testable.
package version

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"runtime"
	"strings"
)

// ContractVersion and MinCompatibleContract bound the leash CLI surface an
// external provisioner can rely on: the `--policy`, `--inject-service`,
// `--runtime` and `--user` flags, plus the shape of the `version --json`
// document itself. They are advertised so `walk install leash` can refuse (or
// warn) up front on a mismatch instead of failing cryptically at run time.
//
// ContractVersion is the current surface; MinCompatibleContract is the oldest
// caller contract this build still serves. A caller written against contract C
// proceeds iff
//
//	minCompatibleContract <= C <= contractVersion
//
// Both bounds are load-bearing, which is why a lone `contractVersion >= C`
// comparison is wrong: the number is bumped precisely when the surface *loses*
// something, so a leash whose contractVersion is strictly greater than C may
// have dropped what C depends on. The upper bound catches a leash that is too
// old (it predates the surface C needs); the lower bound catches a leash that is
// too new (it dropped the surface C was written against). Info.SupportsCaller
// and Info.CheckCaller implement the rule so callers never hand-roll it.
//
// A leash with no `version --json` subcommand at all — any build from before
// this feature shipped — is contract 0 by definition. A caller that gets a
// non-zero exit, an unknown-subcommand error, or unparseable output from
// `leash version --json` must treat the installed leash as contract 0 rather
// than as a broken install.
//
// Bump ContractVersion when the surface changes in a way an existing caller
// cannot absorb: a flag is removed or renamed, its argument grammar changes, or
// its meaning changes. Do NOT bump for additive changes — new flags, new JSON
// fields, new accepted flag values — those stay compatible by construction,
// which is why this is a monotonic integer and not a semver string. When a bump
// *removes* something, raise MinCompatibleContract to the first contract that no
// longer offers it; otherwise leave MinCompatibleContract alone.
//
// MinCompatibleContract is 0 today because contract 1 only added the document:
// nothing a pre-document caller drives has been taken away. That also makes the
// field's absence safe to interpret — a document decoded into a typed struct
// without the field yields 0, which is exactly "nothing has been removed".
const (
	ContractVersion       = 1
	MinCompatibleContract = 0
)

// Enforcing reports whether a leash built for goos ships leash's in-binary
// enforcement path — the eBPF LSM hooks plus the intercepting MITM proxy —
// rather than only observing.
//
// It is derived from the build's target platform rather than hardcoded: only the
// Linux build carries the LSM programs and the proxy. The darwin binary is the
// CLI for an installed Leash.app, whose enforcement lives in separate Endpoint
// Security and Network Extension components that are not part of this build, so
// it must not advertise the Linux path.
//
// This is a statement about the binary, not about the machine: whether a given
// host can actually enforce (LSM active in the kernel, an engine installed, the
// right capabilities) is a runtime question a build-time document deliberately
// does not answer.
func Enforcing(goos string) bool {
	return goos == "linux"
}

// unknown is what the ldflags default to on a plain `go build`, and what we
// substitute for an empty value so consumers never have to special-case "".
// It is a documented, machine-detectable sentinel, not an error.
const unknown = "unknown"

// shortHashLen is how many characters of a commit hash the output has always
// shown.
const shortHashLen = 7

// Build carries the link-time values from cmd/leash. Passing them as a struct
// keeps the call site in main() to a single expression and keeps this package
// free of globals.
type Build struct {
	Version   string // -X main.version
	Commit    string // -X main.commit, may carry a "-dirty" suffix
	BuildDate string // -X main.buildDate, RFC 3339 UTC from the Makefile
}

// Info is the document emitted by `leash version --json`. Field names are part
// of the contract described by ContractVersion: renaming or removing one is a
// breaking change, adding one is not.
type Info struct {
	Version               string `json:"version"`
	Commit                string `json:"commit"`
	BuiltAt               string `json:"builtAt"`
	Enforcing             bool   `json:"enforcing"`
	ContractVersion       int    `json:"contractVersion"`
	MinCompatibleContract int    `json:"minCompatibleContract"`
	OS                    string `json:"os"`
	Arch                  string `json:"arch"`
}

// Compatibility is the verdict of comparing a caller's contract against the
// range this leash serves. It is a string so a provisioner can log or surface it
// verbatim.
type Compatibility string

const (
	// Compatible: the caller's contract falls inside this leash's range.
	Compatible Compatibility = "compatible"
	// LeashTooOld: the installed leash predates the surface the caller needs
	// (callerContract > contractVersion). Upgrade leash.
	LeashTooOld Compatibility = "leash-too-old"
	// LeashTooNew: the installed leash has dropped the surface the caller was
	// written against (callerContract < minCompatibleContract). Upgrade the
	// caller.
	LeashTooNew Compatibility = "leash-too-new"
)

// CheckCaller decides whether a caller written against contract callerContract
// can drive this leash, and says which way a mismatch runs so the caller can
// tell an operator which side to upgrade. Pass 0 for a caller written before
// `version --json` existed.
func (i Info) CheckCaller(callerContract int) Compatibility {
	switch {
	case callerContract > i.ContractVersion:
		return LeashTooOld
	case callerContract < i.MinCompatibleContract:
		return LeashTooNew
	default:
		return Compatible
	}
}

// SupportsCaller is the boolean form of CheckCaller: true iff
// minCompatibleContract <= callerContract <= contractVersion.
func (i Info) SupportsCaller(callerContract int) bool {
	return i.CheckCaller(callerContract) == Compatible
}

// Describe turns link-time build values into the reportable document.
func Describe(b Build) Info {
	return Info{
		Version:               orUnknown(b.Version),
		Commit:                shortCommit(b.Commit),
		BuiltAt:               orUnknown(b.BuildDate),
		Enforcing:             Enforcing(runtime.GOOS),
		ContractVersion:       ContractVersion,
		MinCompatibleContract: MinCompatibleContract,
		OS:                    runtime.GOOS,
		Arch:                  runtime.GOARCH,
	}
}

// JSON renders the document with a trailing newline so the output is a
// well-behaved line on a terminal and still parses as a single JSON value.
func (i Info) JSON() ([]byte, error) {
	out, err := json.MarshalIndent(i, "", "  ")
	if err != nil {
		// Info is a flat struct of strings/bool/int, so this is unreachable in
		// practice; wrap rather than panic to keep the caller in charge.
		return nil, fmt.Errorf("marshal version info: %w", err)
	}
	return append(out, '\n'), nil
}

// Human renders the three lines `leash --version` has printed since the
// beginning. Kept byte-for-byte identical: scripts already grep it, which is
// also why it shows the bare abbreviated hash and drops any "-dirty" marker the
// JSON document keeps.
func (i Info) Human() string {
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
		_, err := io.WriteString(out, info.Human())
		return err
	}
	encoded, err := info.JSON()
	if err != nil {
		return err
	}
	_, err = out.Write(encoded)
	return err
}

// parseArgs resolves the subcommand's only concern — which output format was
// asked for — using the same flag package (and therefore the same -h handling
// and one-or-two-dash spellings) as the sibling subcommands.
//
// A format may be specified twice; it may not be specified two different ways.
// `--json --output text` in either order is a contradiction the caller did not
// mean, so it is rejected rather than silently resolved by last-one-wins.
func parseArgs(args []string, out io.Writer) (bool, error) {
	fs := flag.NewFlagSet("leash version", flag.ContinueOnError)
	// flag's own diagnostics would interleave with the document on stdout and
	// duplicate the error Run returns to main, so render usage ourselves.
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	asJSON := fs.Bool("json", false, "emit the build document as JSON")
	format := fs.String("output", "text", "output format: json or text")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			if _, werr := io.WriteString(out, usage(fs)); werr != nil {
				return false, werr
			}
			return false, flag.ErrHelp
		}
		return false, fmt.Errorf("%w (try `leash version --help`)", err)
	}
	if fs.NArg() > 0 {
		return false, fmt.Errorf("unknown argument %q for version; want --json or --output json|text", fs.Arg(0))
	}

	// Visit reports only the flags actually present on the command line, which
	// is what separates "--output text" from the default of the same value.
	specified := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { specified[f.Name] = true })
	if !specified["output"] {
		return *asJSON, nil
	}
	wantJSON, err := parseFormat(*format)
	if err != nil {
		return false, err
	}
	if specified["json"] && wantJSON != *asJSON {
		return false, fmt.Errorf("conflicting output formats: --json=%t and --output %s; specify one", *asJSON, *format)
	}
	return wantJSON, nil
}

// usage renders the help text for `version --help`, matching the shape the other
// subcommands print (a usage line, what the command does, then the flags).
func usage(fs *flag.FlagSet) string {
	var b strings.Builder
	b.WriteString("usage: leash version [--json | --output json|text]\n\n")
	b.WriteString("Print this build's metadata: by default the same three lines as\n")
	b.WriteString("'leash --version', or with --json the machine-readable document a\n")
	b.WriteString("provisioner reads to decide whether it can drive this leash\n")
	b.WriteString("(contractVersion and minCompatibleContract).\n\nflags:\n")
	fs.SetOutput(&b)
	fs.PrintDefaults()
	fs.SetOutput(io.Discard)
	return b.String()
}

// parseFormat reports whether the requested output format is JSON. An empty
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
