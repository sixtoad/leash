// Package leashversion is the contract half of `leash version --json`: the
// document's Go type, the constants that bound it, and the comparison a caller
// runs to decide whether it can drive an installed leash.
//
// It lives outside internal/ on purpose. The motivating consumer, the walk
// provisioner, is a different Go module (github.com/sixto/walk); Go's internal
// rule would forbid it importing github.com/strongdm/leash/internal/..., so a
// contract published only from there could be read but never used. Nothing in
// this package depends on the rest of leash, so importing it costs a consumer
// one small package and no build tags.
//
// The usual consumer flow is to decode the *installed binary's* stdout:
//
//	out, err := exec.Command(leashPath, "version", "--json").Output()
//	if err != nil {
//	    // See the contract-0 note on MinCompatibleContract before doing this:
//	    // on a pre-feature leash this argv is not a version probe.
//	}
//	info, err := leashversion.Parse(out)
//	if err != nil { ... }
//	if !info.SupportsCaller(myContract) {
//	    return fmt.Errorf("incompatible leash: %s", info.CheckCaller(myContract))
//	}
//
// Note what that does *not* do: it never calls a function that returns the
// calling program's own constants. A caller that compares leash against
// compiled-in values is comparing itself to itself and can only ever pass.
package leashversion

import (
	"encoding/json"
	"fmt"
)

// ContractVersion and MinCompatibleContract bound the leash CLI surface an
// external provisioner can rely on: the flags named by Capabilities plus the
// shape of the `version --json` document itself. They are advertised so
// `walk install leash` can refuse (or warn) up front on a mismatch instead of
// failing cryptically at run time.
//
// ContractVersion is the current surface. MinCompatibleContract is the oldest
// caller contract this build still serves. A caller written against contract C
// proceeds iff
//
//	MinCompatibleContract <= C <= ContractVersion
//
// Both bounds are load-bearing, and the rule is a range rather than a floor:
//
//   - C > ContractVersion means this leash predates the surface C needs, because
//     the surface C was written against had not been introduced yet. Upgrade
//     leash.
//   - C < MinCompatibleContract means this leash has *removed* something C was
//     written against. Upgrade the caller.
//
// So `ContractVersion >= C` alone is not the rule. It is necessary but not
// sufficient: it admits a leash whose ContractVersion is far above C and whose
// MinCompatibleContract has since risen past C, which is exactly the leash that
// dropped C's surface. Info.SupportsCaller and Info.CheckCaller implement the
// full range so callers never hand-roll it.
//
// Bump ContractVersion when the surface changes in a way an existing caller
// cannot absorb: a flag is removed or renamed, its argument grammar changes, or
// its meaning changes. Do NOT bump for additive changes — new flags, new JSON
// fields, new Capabilities entries, new accepted flag values — those stay
// compatible by construction, which is why this is a monotonic integer and not a
// semver string. When a bump *removes* something, raise MinCompatibleContract to
// the first contract that no longer offers it; otherwise leave it alone.
//
// The integer is deliberately coarse, and raising MinCompatibleContract
// over-refuses: it turns away every caller below the new floor, including the
// ones that never touched the removed flag. Capabilities exists so such a caller
// can ask about the one surface element it actually drives (Info.HasCapability)
// instead of being refused by an integer for a removal that does not affect it.
//
// MinCompatibleContract is 0 today because contract 1 only added the document:
// nothing a pre-document caller drives has been taken away. That also makes the
// field's absence safe to interpret — a document decoded into this struct
// without the field yields 0, which is exactly "nothing has been removed".
//
// Contract 0 is a leash with no `version --json` subcommand at all: any build
// from before this feature shipped. Treat a non-zero exit, an unknown-subcommand
// error, or unparseable output as contract 0 rather than as a broken install —
// but see the hazard note below before probing for it.
//
// # Probing an unknown leash safely
//
// On a pre-feature leash, `version` is not a subcommand: the argument falls
// through to the workload CLI, which configures telemetry and can begin runtime
// provisioning. Running `leash version --json` at a binary that might predate
// this feature is therefore not a side-effect-free probe.
//
// Prefer to establish contract 0 without that argv:
//
//   - `leash --version` has been handled by the argument switch in every build
//     and only prints three lines. A provisioner that knows which leash release
//     it installed can map that release to contract 0 vs >= 1 with no other
//     invocation.
//   - If you must run the probe against an unknown binary, run it with
//     LEASH_DISABLE_TELEMETRY=1 and in a disposable working directory, and treat
//     any output that is not a parseable document as contract 0.
//
// From contract 1 onward the probe is well-behaved: `version --json` prints the
// document and exits without touching the runtime.
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
	CapabilityVersionJSON,
}

// Capabilities returns the surface names this build advertises. The slice is a
// copy: the emitted document must not be mutable by a caller that holds it.
func Capabilities() []string {
	out := make([]string, len(capabilities))
	copy(out, capabilities)
	return out
}

// Info is the document emitted by `leash version --json`. Field names are part
// of the contract bounded by ContractVersion: renaming or removing one is a
// breaking change, adding one is not.
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
// A document from a leash that predates Capabilities decodes with the field
// empty, so this reports false there; fall back to the contract range when it
// does.
func (i Info) HasCapability(name string) bool {
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

// Parse decodes the stdout of `leash version --json` into a document. It is the
// entry point a consumer wants: it reads what the *installed binary* said, which
// is the only thing that can disagree with the caller's expectations.
//
// Unparseable output is not a decode error to swallow — per the contract it
// means the binary is contract 0 (or is not a leash at all), so a caller should
// treat an error here as "assume contract 0" rather than as an install failure.
func Parse(document []byte) (Info, error) {
	var info Info
	if err := json.Unmarshal(document, &info); err != nil {
		return Info{}, fmt.Errorf("parse leash version document: %w", err)
	}
	return info, nil
}
