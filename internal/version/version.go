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
	"fmt"
	"io"
	"runtime"
	"strings"
)

// ContractVersion identifies the leash CLI surface that external provisioners
// depend on: the `--policy`, `--inject-service`, `--runtime` and `--user`
// flags, plus the shape of the `version --json` document itself. It is
// advertised so `walk install leash` can refuse (or warn) up front on a
// mismatch instead of failing cryptically at run time.
//
// Bump it when that surface changes in a way an existing caller cannot absorb:
// a flag is removed or renamed, its argument grammar changes, or its meaning
// changes. Do NOT bump for additive changes — new flags, new JSON fields, new
// accepted flag values — those stay compatible by construction, which is why
// this is a single monotonic integer and not a semver string: callers only
// ever need "is leash's contract at least the one I was written against?".
//
// Consumers compare numerically: proceed when
// leash.contractVersion >= the minimum the caller requires; a strictly greater
// value means leash has since dropped something, so the caller must be updated.
const ContractVersion = 1

// Enforcing reports whether this build ships the policy-enforcement path (LSM
// hooks plus the intercepting proxy) rather than merely observing. Every leash
// build enforces today, so it is a constant; it is still surfaced as its own
// JSON field so a provisioner can key off one boolean if an observe-only build
// ever ships, instead of inferring it from the version string.
const Enforcing = true

// unknown is what the ldflags default to on a plain `go build`, and what we
// substitute for an empty value so consumers never have to special-case "".
const unknown = "unknown"

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
	Version         string `json:"version"`
	Commit          string `json:"commit"`
	BuiltAt         string `json:"builtAt"`
	Enforcing       bool   `json:"enforcing"`
	ContractVersion int    `json:"contractVersion"`
	OS              string `json:"os"`
	Arch            string `json:"arch"`
}

// Describe turns link-time build values into the reportable document.
func Describe(b Build) Info {
	return Info{
		Version:         orUnknown(b.Version),
		Commit:          shortCommit(b.Commit),
		BuiltAt:         orUnknown(b.BuildDate),
		Enforcing:       Enforcing,
		ContractVersion: ContractVersion,
		OS:              runtime.GOOS,
		Arch:            runtime.GOARCH,
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
// also why it re-truncates the commit (dropping any "-dirty" marker past
// character seven) instead of reusing the JSON form.
func (i Info) Human() string {
	return fmt.Sprintf("version: %s\ngit hash: %s\nbuild date: %s\n",
		i.Version, truncate(i.Commit), i.BuiltAt)
}

// Run implements the `version` subcommand: args are everything after the
// subcommand word. Without a format flag it prints the historical human lines,
// so `leash version` and `leash --version` agree.
func Run(args []string, b Build, out io.Writer) error {
	asJSON, err := wantsJSON(args)
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

// wantsJSON parses the subcommand's only concern: which output format was
// asked for. `--json` is the shorthand; `--output <fmt>` exists so a future
// format can be added without another boolean flag.
func wantsJSON(args []string) (bool, error) {
	asJSON := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--json" || arg == "-json":
			asJSON = true
		case arg == "--output" || arg == "-output":
			if i+1 >= len(args) {
				return false, fmt.Errorf("missing argument for %s", arg)
			}
			i++
			format, err := parseFormat(args[i])
			if err != nil {
				return false, err
			}
			asJSON = format
		case strings.HasPrefix(arg, "--output=") || strings.HasPrefix(arg, "-output="):
			format, err := parseFormat(arg[strings.Index(arg, "=")+1:])
			if err != nil {
				return false, err
			}
			asJSON = format
		default:
			return false, fmt.Errorf("unknown argument %q for version; want --json or --output json|text", arg)
		}
	}
	return asJSON, nil
}

// parseFormat reports whether the requested output format is JSON.
func parseFormat(value string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "json":
		return true, nil
	case "text", "":
		return false, nil
	default:
		return false, fmt.Errorf("unsupported output format %q; want json or text", value)
	}
}

// shortCommit trims a commit to the 7-character prefix the human output has
// always shown, but keeps any "-dirty" marker the Makefile appended: a build
// from a modified tree must not be able to advertise itself to a provisioner
// as the pristine commit it was cut from.
func shortCommit(commit string) string {
	trimmed := strings.TrimSpace(commit)
	if trimmed == "" {
		return unknown
	}
	hash, suffix, found := strings.Cut(trimmed, "-")
	if !found {
		return truncate(trimmed)
	}
	return truncate(hash) + "-" + suffix
}

func truncate(hash string) string {
	if len(hash) > 7 {
		return hash[:7]
	}
	return hash
}

func orUnknown(value string) string {
	if strings.TrimSpace(value) == "" {
		return unknown
	}
	return value
}
