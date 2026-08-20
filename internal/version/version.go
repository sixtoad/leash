// Package version is leash's version layer: the document `leash version --json`
// emits, the contract bounds that make it checkable, and the rendering of the
// three human lines `leash --version` has always printed.
//
// It is internal on purpose. The compatibility rule is published as a *rule*, in
// docs/api-contracts-leash-core.md, not as a Go package: a consumer implements
// `minCompatibleContract <= C <= contractVersion` against a struct of its own in
// about three lines, in any language. Exporting this package instead would bind
// the module — already tagged v1.1.7 — to a permanent v1 API with no apidiff
// gate, where removing a single Info field would force a /v2 and break every
// importer. The wire document is the contract; the Go type is an implementation
// detail of leash.
//
// The build values are injected into cmd/leash at link time
// (-X main.version/commit/buildDate), so they are passed in rather than read
// from a global: this package stays pure and unit-testable.
package version

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"runtime"
	"strconv"
	"strings"
)

// ContractVersion and MinCompatibleContract bound the leash CLI surface an
// external provisioner can rely on: the flags named by the Capability constants
// plus the shape of the `version --json` document. They are advertised so
// `walk install leash` can refuse (or warn) up front instead of failing
// cryptically at run time.
//
// A caller written against contract C proceeds iff
//
//	MinCompatibleContract <= C <= ContractVersion
//
// The rule is a range, not a floor: C > ContractVersion means this leash
// predates the surface C needs (upgrade leash), and C < MinCompatibleContract
// means this leash *removed* something C was written against (upgrade the
// caller). `ContractVersion >= C` alone is necessary but not sufficient — it
// admits a leash whose floor has since risen past C, which is exactly the leash
// that dropped C's surface.
//
// The consumer-facing statement of all this — the rule, the value domains,
// contract 0, and the hazard of probing a pre-feature leash (where `version` is
// not a subcommand and falls through to the workload CLI) — is
// docs/api-contracts-leash-core.md § CLI build contract. That document, not this
// package, is the published contract.
//
// Bump ContractVersion when the surface changes in a way an existing caller
// cannot absorb: a flag is removed or renamed, its argument grammar changes, or
// its meaning changes. Do NOT bump for additive changes — new flags, new JSON
// fields, new capability names, new accepted flag values — which stay compatible
// by construction; that is why this is a monotonic integer and not semver. When
// a bump *removes* something, raise MinCompatibleContract to the first contract
// that no longer offers it, and update the docs and the tests that pin these
// literals in the same change.
//
// MinCompatibleContract is 0 today because contract 1 only added the document:
// nothing a pre-document caller drives has been taken away. That also makes the
// field's absence safe to read as 0 — "nothing has been removed". The integer is
// deliberately coarse, and raising the floor over-refuses; Capabilities exists so
// a caller can ask about the one surface element it actually drives instead.
const (
	ContractVersion       = 1
	MinCompatibleContract = 0
)

// The capability names carried in Info.Capabilities. Each names one element of
// the CLI surface a provisioner drives, so a caller can test for the thing it
// needs (Info.HasCapability) instead of inferring it from ContractVersion.
//
// Adding a name is additive and does not bump ContractVersion. Removing one is a
// breaking change and does.
const (
	// CapabilityPolicy is the `--policy <path>` flag.
	CapabilityPolicy = "policy"
	// CapabilityInjectService is the `--inject-service <spec>` flag.
	CapabilityInjectService = "inject-service"
	// CapabilityRuntime is the `--runtime <docker|podman>` flag.
	CapabilityRuntime = "runtime"
	// CapabilityUser is the `--user <name>` drop-user flag.
	CapabilityUser = "user"
	// CapabilityRequireLSM is the `--require-lsm` fail-closed flag.
	CapabilityRequireLSM = "require-lsm"
	// CapabilityMachineOutput is the `--machine-output` fd-ownership contract.
	CapabilityMachineOutput = "machine-output"
	// CapabilityVersionJSON is this document itself, emitted by
	// `leash version --json`.
	CapabilityVersionJSON = "version-json"
)

// capabilities is the surface this build offers. Order is stable so the emitted
// document is byte-stable across runs of the same binary.
var capabilities = []string{
	CapabilityPolicy,
	CapabilityInjectService,
	CapabilityRuntime,
	CapabilityUser,
	CapabilityRequireLSM,
	CapabilityMachineOutput,
	CapabilityVersionJSON,
}

// Capabilities returns the surface names this build advertises. The slice is a
// copy: the emitted document must not be mutable by a caller that holds it.
func Capabilities() []string {
	out := make([]string, len(capabilities))
	copy(out, capabilities)
	return out
}

// Info is the document emitted by `leash version --json`. The JSON field names
// are the contract bounded by ContractVersion: renaming or removing one is a
// breaking change, adding one is not. The Go type is not part of any published
// API — see the package comment.
type Info struct {
	Version               string   `json:"version"`
	Commit                string   `json:"commit"`
	BuiltAt               string   `json:"builtAt"`
	Enforcing             bool     `json:"enforcing"`
	ContractVersion       int      `json:"contractVersion"`
	MinCompatibleContract int      `json:"minCompatibleContract"`
	Capabilities          []string `json:"capabilities"`
	OS                    string   `json:"os"`
	Arch                  string   `json:"arch"`
}

// Compatibility is the verdict of comparing a caller's contract against the
// range an installed leash serves. It is a string so a provisioner can log or
// surface it verbatim.
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
// can drive the leash that emitted this document, and says which way a mismatch
// runs so the caller can tell an operator which side to upgrade. Pass 0 for a
// caller written before `version --json` existed.
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

// HasCapability reports whether the document advertises the named surface
// element. Use it when the caller depends on one specific flag: a leash that
// raised minCompatibleContract past the caller's contract for an unrelated
// removal still offers this one, and the integer alone would refuse it.
//
// The empty string is never a capability, even if a malformed document carries
// one in the array, so HasCapability("") is always false rather than a test that
// accidentally passes.
//
// A document from a leash that predates Capabilities decodes with the field
// empty, so this reports false there; fall back to the contract range when it
// does.
func (i Info) HasCapability(name string) bool {
	if name == "" {
		return false
	}
	for _, have := range i.Capabilities {
		if have == name {
			return true
		}
	}
	return false
}

// JSON renders the document with a trailing newline so the output is a
// well-behaved line on a terminal and still parses as a single JSON value.
func (i Info) JSON() ([]byte, error) {
	out, err := json.MarshalIndent(i, "", "  ")
	if err != nil {
		// Info is a flat struct of strings, a bool, ints and a string slice, so
		// this is unreachable in practice; wrap rather than panic to keep the
		// caller in charge.
		return nil, fmt.Errorf("marshal version info: %w", err)
	}
	return append(out, '\n'), nil
}

// requiredFields are the JSON keys that make a document a leash version
// document. `version` is issue #24's AC-1 field set; `contractVersion` is what
// the compatibility gate reads. Anything without both is not this document.
var requiredFields = []string{"version", "contractVersion"}

// Parse decodes the stdout of `leash version --json` into a document. It is the
// entry point a consumer of an installed binary wants: it reads what that binary
// said, which is the only thing that can disagree with the caller's
// expectations.
//
// It rejects non-documents rather than fail open. Plain json.Unmarshal accepts
// `null`, `{}` and `{"foo":1}` without error and leaves a zero Info behind —
// contractVersion 0, minCompatibleContract 0 — which a contract-0 caller reads
// as `compatible`. Since this decision is the documented install gate, "it
// parsed" must mean "it is a leash version document": a JSON object carrying at
// least requiredFields, with a non-negative, non-inverted contract range.
//
// Unparseable output is not a decode error to swallow — per the contract it
// means the binary is contract 0 (or is not a leash at all), so a caller should
// treat an error here as "assume contract 0" rather than as an install failure.
func Parse(document []byte) (Info, error) {
	trimmed := bytes.TrimSpace(document)
	if len(trimmed) == 0 {
		return Info{}, errors.New("parse leash version document: empty output")
	}

	// Decoding into a map first is what rejects a non-object: `null` yields a nil
	// map, and an array, number, string or bool fails outright. Decoding straight
	// into Info would accept all of the object-shaped ones silently.
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &fields); err != nil {
		return Info{}, fmt.Errorf("parse leash version document: %w", err)
	}
	if fields == nil {
		return Info{}, errors.New("parse leash version document: got JSON null, want an object")
	}
	for _, name := range requiredFields {
		if _, ok := fields[name]; !ok {
			return Info{}, fmt.Errorf("parse leash version document: missing required field %q; this is not a leash version document", name)
		}
	}

	var info Info
	if err := json.Unmarshal(trimmed, &info); err != nil {
		return Info{}, fmt.Errorf("parse leash version document: %w", err)
	}
	// A contract is a monotonic counter starting at 0, so a negative bound is not
	// a range this rule can be evaluated against.
	if info.ContractVersion < 0 || info.MinCompatibleContract < 0 {
		return Info{}, fmt.Errorf("parse leash version document: negative contract range [%d,%d]",
			info.MinCompatibleContract, info.ContractVersion)
	}
	// An inverted range serves no caller at all, so it cannot be a document any
	// leash emitted; accepting it would let a garbled value produce verdicts.
	if info.MinCompatibleContract > info.ContractVersion {
		return Info{}, fmt.Errorf("parse leash version document: inverted contract range: minCompatibleContract %d > contractVersion %d",
			info.MinCompatibleContract, info.ContractVersion)
	}
	return info, nil
}

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
// error. (main.version defaults to "dev", and so does `commit` on the build
// paths that fall back when `git rev-parse` fails.)
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
// must run that binary and decode its stdout (Parse). Describe exists to produce
// the document, not to consume one.
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
		ContractVersion:       ContractVersion,
		MinCompatibleContract: MinCompatibleContract,
		Capabilities:          Capabilities(),
		OS:                    goos,
		Arch:                  goarch,
	}
}

// Human renders the three lines `leash --version` has printed since the
// beginning. Kept byte-for-byte identical for every value leash's build paths
// emit, which is also why it shows the bare abbreviated hash and drops any
// "-dirty" marker the JSON document keeps.
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
