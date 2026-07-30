package version

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"reflect"
	"strings"
	"testing"
)

// testBuild mirrors what the Makefile injects for a tagged release build.
func testBuild() Build {
	return Build{Version: "v0.2.0", Commit: "c686025aa1b2c3", BuildDate: "2026-07-21T10:11:12Z"}
}

// wantCapabilities is the surface this build advertises, written out as literals
// rather than obtained from the code under test, so a silent change to the list
// fails here.
var wantCapabilities = []string{"policy", "inject-service", "runtime", "user", "require-lsm", "version-json"}

// TestEnforcingIsDerivedPerPlatform pins the criterion: `enforcing` says whether
// *this binary* carries an enforcement path. Linux ships the eBPF LSM programs
// plus the MITM proxy; darwin ships and drives the same MITM proxy
// (internal/darwind/runtime_darwin.go builds it with NewMITMProxy and pushes
// policy into it via applyPolicyToProxy), so claiming false there would deny
// enforcement the binary demonstrably performs.
func TestEnforcingIsDerivedPerPlatform(t *testing.T) {
	t.Parallel()

	tests := map[string]bool{
		"linux":   true,
		"darwin":  true,
		"windows": false,
		"freebsd": false,
		"":        false,
	}
	for goos, want := range tests {
		if got := Enforcing(goos); got != want {
			t.Fatalf("Enforcing(%q) = %t, want %t", goos, got, want)
		}
	}
}

// TestDescribeForPinsTheDocument writes out the whole expected document for a
// given build and platform. Nothing on the expected side calls the code under
// test, so the assertion can actually fail.
func TestDescribeForPinsTheDocument(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		build  Build
		goos   string
		goarch string
		want   Info
	}{
		{
			name:  "linux release build",
			build: testBuild(),
			goos:  "linux", goarch: "amd64",
			want: Info{
				Version: "v0.2.0", Commit: "c686025", BuiltAt: "2026-07-21T10:11:12Z",
				Enforcing: true, ContractVersion: 1, MinCompatibleContract: 0,
				Capabilities: wantCapabilities, OS: "linux", Arch: "amd64",
			},
		},
		{
			name:  "darwin build also carries an enforcement path",
			build: testBuild(),
			goos:  "darwin", goarch: "arm64",
			want: Info{
				Version: "v0.2.0", Commit: "c686025", BuiltAt: "2026-07-21T10:11:12Z",
				Enforcing: true, ContractVersion: 1, MinCompatibleContract: 0,
				Capabilities: wantCapabilities, OS: "darwin", Arch: "arm64",
			},
		},
		{
			name:  "a target with no enforcement path says so",
			build: testBuild(),
			goos:  "windows", goarch: "amd64",
			want: Info{
				Version: "v0.2.0", Commit: "c686025", BuiltAt: "2026-07-21T10:11:12Z",
				Enforcing: false, ContractVersion: 1, MinCompatibleContract: 0,
				Capabilities: wantCapabilities, OS: "windows", Arch: "amd64",
			},
		},
		{
			name:  "dirty tree keeps its marker",
			build: Build{Version: "dev-c686025", Commit: "c686025aa1b2c3-dirty", BuildDate: "2026-07-21T10:11:12Z"},
			goos:  "linux", goarch: "amd64",
			want: Info{
				Version: "dev-c686025", Commit: "c686025-dirty", BuiltAt: "2026-07-21T10:11:12Z",
				Enforcing: true, ContractVersion: 1, MinCompatibleContract: 0,
				Capabilities: wantCapabilities, OS: "linux", Arch: "amd64",
			},
		},
		{
			// Only the hash component is abbreviated, so a short hash keeps its
			// marker instead of being cut mid-suffix into "abc-dir".
			name:  "short hash keeps its whole marker",
			build: Build{Version: "dev", Commit: "abc-dirty", BuildDate: "unknown"},
			goos:  "linux", goarch: "amd64",
			want: Info{
				Version: "dev", Commit: "abc-dirty", BuiltAt: "unknown",
				Enforcing: true, ContractVersion: 1, MinCompatibleContract: 0,
				Capabilities: wantCapabilities, OS: "linux", Arch: "amd64",
			},
		},
		{
			// A `git describe` value is not a hash: abbreviating it would name a
			// different build ("v1.2.3-"), so it is reported whole.
			name:  "git describe value is left intact",
			build: Build{Version: "v1.2.3-4-gabc1234", Commit: "v1.2.3-4-gabc1234", BuildDate: "unknown"},
			goos:  "linux", goarch: "amd64",
			want: Info{
				Version: "v1.2.3-4-gabc1234", Commit: "v1.2.3-4-gabc1234", BuiltAt: "unknown",
				Enforcing: true, ContractVersion: 1, MinCompatibleContract: 0,
				Capabilities: wantCapabilities, OS: "linux", Arch: "amd64",
			},
		},
		{
			// A plain `go build` links main.version = "dev" and the other two as
			// "unknown"; the document reports exactly that.
			name:  "plain go build defaults",
			build: Build{Version: "dev", Commit: "unknown", BuildDate: "unknown"},
			goos:  "linux", goarch: "amd64",
			want: Info{
				Version: "dev", Commit: "unknown", BuiltAt: "unknown",
				Enforcing: true, ContractVersion: 1, MinCompatibleContract: 0,
				Capabilities: wantCapabilities, OS: "linux", Arch: "amd64",
			},
		},
		{
			name:  "empty ldflags degrade to unknown",
			build: Build{},
			goos:  "linux", goarch: "amd64",
			want: Info{
				Version: "unknown", Commit: "unknown", BuiltAt: "unknown",
				Enforcing: true, ContractVersion: 1, MinCompatibleContract: 0,
				Capabilities: wantCapabilities, OS: "linux", Arch: "amd64",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := describeFor(tt.build, tt.goos, tt.goarch); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("describeFor(%+v, %q, %q) = %+v, want %+v", tt.build, tt.goos, tt.goarch, got, tt.want)
			}
		})
	}
}

// TestDescribeReportsTheBuildPlatform checks the one thing describeFor cannot:
// that Describe feeds it the platform this binary was compiled for. The expected
// `enforcing` comes from a literal table keyed by the reported OS, so the
// assertion is against a written-down value rather than a second call to
// Enforcing.
func TestDescribeReportsTheBuildPlatform(t *testing.T) {
	t.Parallel()

	enforcingByOS := map[string]bool{"linux": true, "darwin": true, "windows": false}

	got := Describe(testBuild())
	if got.OS == "" || got.Arch == "" {
		t.Fatalf("Describe(...) reported os=%q arch=%q, want the build's GOOS/GOARCH", got.OS, got.Arch)
	}
	want, ok := enforcingByOS[got.OS]
	if !ok {
		t.Fatalf("Describe(...) reported os %q, which this test has no pinned expectation for; add one", got.OS)
	}
	if got.Enforcing != want {
		t.Fatalf("Describe(...).Enforcing = %t on %q, want %t", got.Enforcing, got.OS, want)
	}
}

// TestJSONWireShape pins the wire field names and values a provisioner reads.
// It decodes into a map rather than back into Info, because a struct round-trip
// would not catch a renamed json tag.
func TestJSONWireShape(t *testing.T) {
	t.Parallel()

	encoded, err := describeFor(testBuild(), "linux", "amd64").JSON()
	if err != nil {
		t.Fatalf("JSON() error: %v", err)
	}
	if !bytes.HasSuffix(encoded, []byte("\n")) {
		t.Fatalf("JSON() = %q, want a trailing newline", encoded)
	}

	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal %q: %v", encoded, err)
	}

	want := map[string]any{
		"version":               "v0.2.0",
		"commit":                "c686025",
		"builtAt":               "2026-07-21T10:11:12Z",
		"enforcing":             true,
		"contractVersion":       float64(1), // encoding/json decodes numbers as float64
		"minCompatibleContract": float64(0),
		"capabilities":          []any{"policy", "inject-service", "runtime", "user", "require-lsm", "version-json"},
		"os":                    "linux",
		"arch":                  "amd64",
	}
	if !reflect.DeepEqual(decoded, want) {
		t.Fatalf("JSON() decoded to %v, want %v", decoded, want)
	}
}

// TestHumanIsByteIdenticalForRealBuildValues is the CAP-4 guarantee, written as
// literals: for every commit value leash's build paths actually inject, the
// rendering must be exactly what `leash --version` printed before this package
// existed.
//
// It covers only the values the build paths emit. `abc-dirty` and a `git
// describe` string render differently now — deliberately, since the old
// rendering cut them into fragments naming a build that does not exist — and are
// pinned separately in TestHumanDeManglesPathologicalValues.
func TestHumanIsByteIdenticalForRealBuildValues(t *testing.T) {
	t.Parallel()

	// Makefile, scripts/release.sh, scripts/install-leash.sh, build/publish-docker.sh
	// and .goreleaser.yaml all stamp a hex hash plus an optional "-dirty"; the
	// ldflags default to "unknown" for commit and "dev" for version.
	tests := []struct {
		commit string
		want   string
	}{
		{commit: "c686025", want: "version: v0.2.0\ngit hash: c686025\nbuild date: 2026-07-21T10:11:12Z\n"},
		{commit: "c686025-dirty", want: "version: v0.2.0\ngit hash: c686025\nbuild date: 2026-07-21T10:11:12Z\n"},
		{commit: "c686025aa1b2c3d4e5f60718293a4b5c6d7e8f90", want: "version: v0.2.0\ngit hash: c686025\nbuild date: 2026-07-21T10:11:12Z\n"},
		{commit: "unknown", want: "version: v0.2.0\ngit hash: unknown\nbuild date: 2026-07-21T10:11:12Z\n"},
		{commit: "dev", want: "version: v0.2.0\ngit hash: dev\nbuild date: 2026-07-21T10:11:12Z\n"},
		// A hash at or below the abbreviation length is left alone.
		{commit: "c68602", want: "version: v0.2.0\ngit hash: c68602\nbuild date: 2026-07-21T10:11:12Z\n"},
	}
	for _, tt := range tests {
		build := Build{Version: "v0.2.0", Commit: tt.commit, BuildDate: "2026-07-21T10:11:12Z"}
		if got := describeFor(build, "linux", "amd64").Human(); got != tt.want {
			t.Fatalf("Human() for commit %q = %q, want the pre-change %q", tt.commit, got, tt.want)
		}
	}
}

// TestHumanDeManglesPathologicalValues pins the intentional divergence from the
// pre-change rendering: truncation applies to the hash, never to a composed
// hash+suffix or to a value that is not a hash at all.
func TestHumanDeManglesPathologicalValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		build  Build
		want   string
		wasCut string // what the pre-change seven-character truncation produced
	}{
		{
			name:   "short hash with a marker is not cut mid-suffix",
			build:  Build{Version: "dev", Commit: "abc-dirty", BuildDate: "unknown"},
			want:   "version: dev\ngit hash: abc\nbuild date: unknown\n",
			wasCut: "abc-dir",
		},
		{
			name:   "git describe value is not mangled",
			build:  Build{Version: "v1.2.3", Commit: "v1.2.3-4-gabc1234", BuildDate: "unknown"},
			want:   "version: v1.2.3\ngit hash: v1.2.3-4-gabc1234\nbuild date: unknown\n",
			wasCut: "v1.2.3-",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := describeFor(tt.build, "linux", "amd64").Human()
			if got != tt.want {
				t.Fatalf("Human() = %q, want %q", got, tt.want)
			}
			if strings.Contains(got, "git hash: "+tt.wasCut+"\n") {
				t.Fatalf("Human() = %q, which is the mangled pre-change fragment %q", got, tt.wasCut)
			}
		})
	}
}

const wantHumanOutput = "version: v0.2.0\ngit hash: c686025\nbuild date: 2026-07-21T10:11:12Z\n"

func TestRunFormatSelection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		args     []string
		wantJSON bool
	}{
		{name: "no args prints human lines", args: nil},
		{name: "explicit text output", args: []string{"--output", "text"}},
		{name: "json disabled explicitly", args: []string{"--json=false"}},
		{name: "json flag", args: []string{"--json"}, wantJSON: true},
		{name: "single dash json flag", args: []string{"-json"}, wantJSON: true},
		{name: "json equals true", args: []string{"--json=true"}, wantJSON: true},
		{name: "output json", args: []string{"--output", "json"}, wantJSON: true},
		{name: "output equals json", args: []string{"--output=json"}, wantJSON: true},
		{name: "case insensitive format", args: []string{"--output", "JSON"}, wantJSON: true},
		{name: "agreeing duplicate specs", args: []string{"--json", "--output", "json"}, wantJSON: true},
		{name: "agreeing repeated output", args: []string{"--output", "json", "--output", "json"}, wantJSON: true},
		{name: "agreeing repeated json", args: []string{"--json", "--json=true"}, wantJSON: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var out bytes.Buffer
			if err := Run(tt.args, testBuild(), &out); err != nil {
				t.Fatalf("Run(%v) error: %v", tt.args, err)
			}
			if !tt.wantJSON {
				if got := out.String(); got != wantHumanOutput {
					t.Fatalf("Run(%v) = %q, want %q", tt.args, got, wantHumanOutput)
				}
				return
			}
			var decoded Info
			if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
				t.Fatalf("Run(%v) output %q is not JSON: %v", tt.args, out.String(), err)
			}
			if decoded.Version != "v0.2.0" || decoded.Commit != "c686025" || decoded.BuiltAt != "2026-07-21T10:11:12Z" {
				t.Fatalf("Run(%v) decoded to %+v, want the testBuild values", tt.args, decoded)
			}
			if decoded.ContractVersion != 1 || decoded.MinCompatibleContract != 0 {
				t.Fatalf("Run(%v) decoded contract range [%d,%d], want [0,1]",
					tt.args, decoded.MinCompatibleContract, decoded.ContractVersion)
			}
			if !reflect.DeepEqual(decoded.Capabilities, wantCapabilities) {
				t.Fatalf("Run(%v) decoded capabilities %v, want %v", tt.args, decoded.Capabilities, wantCapabilities)
			}
		})
	}
}

// TestRunRejectsBadFormatSpecs covers every way a caller can ask for a format
// that is malformed, unknown, or self-contradictory. The repeated-flag cases are
// the ones flag.FlagSet.Visit cannot see: it reports a repeated flag once, with
// the last value, so without the occurrence recording these three would silently
// resolve by last-one-wins.
func TestRunRejectsBadFormatSpecs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		args       []string
		wantErrSub string
	}{
		{name: "missing output value", args: []string{"--output"}, wantErrSub: "needs an argument"},
		{name: "unsupported format", args: []string{"--output", "yaml"}, wantErrSub: "unsupported output format"},
		{name: "unknown flag", args: []string{"--verbose"}, wantErrSub: "not defined"},
		{name: "positional argument", args: []string{"json"}, wantErrSub: "unknown argument"},
		{name: "non-boolean json value", args: []string{"--json=maybe"}, wantErrSub: `invalid boolean "maybe"`},

		// Cross-flag contradictions, in either order.
		{name: "json then text", args: []string{"--json", "--output", "text"}, wantErrSub: "conflicting output formats"},
		{name: "text then json", args: []string{"--output", "text", "--json"}, wantErrSub: "conflicting output formats"},
		{name: "json then text with equals", args: []string{"--json", "--output=text"}, wantErrSub: "conflicting output formats"},

		// The same flag repeated with contradictory values, in either order.
		{name: "output json then output text", args: []string{"--output", "json", "--output", "text"}, wantErrSub: "conflicting output formats"},
		{name: "output text then output json", args: []string{"--output", "text", "--output", "json"}, wantErrSub: "conflicting output formats"},
		{name: "json then json false", args: []string{"--json", "--json=false"}, wantErrSub: "conflicting output formats"},
		{name: "json false then json", args: []string{"--json=false", "--json"}, wantErrSub: "conflicting output formats"},

		// An empty format is a caller bug, not a request for the default.
		{name: "empty output with equals", args: []string{"--output="}, wantErrSub: "empty output format"},
		{name: "empty output as a separate word", args: []string{"--output", ""}, wantErrSub: "empty output format"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var out bytes.Buffer
			err := Run(tt.args, testBuild(), &out)
			if err == nil || !strings.Contains(err.Error(), tt.wantErrSub) {
				t.Fatalf("Run(%v) error = %v, want one containing %q", tt.args, err, tt.wantErrSub)
			}
			if out.Len() != 0 {
				t.Fatalf("Run(%v) wrote %q on error, want nothing", tt.args, out.String())
			}
		})
	}
}

// TestRunHelp pins the CLI contract for help: usage on the output stream and
// flag.ErrHelp, which cmd/leash turns into a clean exit rather than a log.Fatal
// timestamp and exit 1.
func TestRunHelp(t *testing.T) {
	t.Parallel()

	for _, arg := range []string{"--help", "-h", "-help"} {
		var out bytes.Buffer
		err := Run([]string{arg}, testBuild(), &out)
		if !errors.Is(err, flag.ErrHelp) {
			t.Fatalf("Run(%q) error = %v, want flag.ErrHelp", arg, err)
		}
		printed := out.String()
		for _, want := range []string{"usage: leash version", "--json", "--output json|text", "capabilities"} {
			if !strings.Contains(printed, want) {
				t.Fatalf("Run(%q) usage = %q, want it to mention %q", arg, printed, want)
			}
		}
		// The flag package's own PrintDefaults renders "  -json" / "  -output",
		// which contradicts the usage line and every doc. We write the block
		// ourselves precisely so it does not.
		for _, unwanted := range []string{"\n  -json", "\n  -output"} {
			if strings.Contains(printed, unwanted) {
				t.Fatalf("Run(%q) usage = %q, want no single-dash-only flag listing %q", arg, printed, unwanted)
			}
		}
		// Help is help: it must not also emit the document.
		if strings.Contains(printed, "build date:") || strings.Contains(printed, "\"builtAt\"") {
			t.Fatalf("Run(%q) printed the version document alongside usage: %q", arg, printed)
		}
	}
}

// TestContractBoundsAreTheLiteralsTheDocsPublish pins the two integers to the
// values CHANGELOG.md, docs/api-contracts-leash-core.md and docs/DEVELOPMENT.md
// print. It is written as literals on purpose: an assertion phrased against the
// constants themselves ("ContractVersion >= 1") compares the constant to itself
// and cannot fail. Changing either number is a contract event — update the docs
// and this test together, deliberately.
func TestContractBoundsAreTheLiteralsTheDocsPublish(t *testing.T) {
	t.Parallel()

	if ContractVersion != 1 {
		t.Fatalf("ContractVersion = %d, want 1 (the value the docs publish); bumping it is a contract change — update the docs and this test", ContractVersion)
	}
	if MinCompatibleContract != 0 {
		t.Fatalf("MinCompatibleContract = %d, want 0 (contract 1 removed nothing); raising it refuses every older caller — update the docs and this test", MinCompatibleContract)
	}
}

// TestCapabilitiesReturnsACopy: the document is read by callers that may hold
// and mutate the slice; the package's own list must not be reachable through it.
func TestCapabilitiesReturnsACopy(t *testing.T) {
	t.Parallel()

	first := Capabilities()
	first[0] = "clobbered"
	if got := Capabilities()[0]; got != "policy" {
		t.Fatalf("Capabilities()[0] = %q after a caller mutated an earlier result, want %q", got, "policy")
	}
}

// TestCheckCallerRange pins the rule the contract documents:
// minCompatibleContract <= callerContract <= contractVersion. The Info is built
// by hand with a range open on both sides, which the real constants ([0,1]) do
// not yet have, so both failure directions are exercised.
func TestCheckCallerRange(t *testing.T) {
	t.Parallel()

	leash := Info{MinCompatibleContract: 2, ContractVersion: 4}

	tests := []struct {
		name           string
		callerContract int
		want           Compatibility
	}{
		{name: "caller below the floor: leash dropped its surface", callerContract: 1, want: "leash-too-new"},
		{name: "caller at the floor", callerContract: 2, want: "compatible"},
		{name: "caller inside the range", callerContract: 3, want: "compatible"},
		{name: "caller at the ceiling", callerContract: 4, want: "compatible"},
		{name: "caller above the ceiling: leash predates its surface", callerContract: 5, want: "leash-too-old"},
		{name: "pre-feature caller is below this floor too", callerContract: 0, want: "leash-too-new"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := leash.CheckCaller(tt.callerContract); got != tt.want {
				t.Fatalf("CheckCaller(%d) = %q, want %q", tt.callerContract, got, tt.want)
			}
			if got, want := leash.SupportsCaller(tt.callerContract), tt.want == "compatible"; got != want {
				t.Fatalf("SupportsCaller(%d) = %t, want %t", tt.callerContract, got, want)
			}
		})
	}
}

// TestCheckCallerAgainstTheDocumentThisBuildEmits uses the shipped bounds, with
// the outcomes written as literals rather than derived from the constants.
// Contract 0 — a caller written before `version --json` existed — is compatible
// with this build because contract 1 removed nothing.
func TestCheckCallerAgainstTheDocumentThisBuildEmits(t *testing.T) {
	t.Parallel()

	info := Info{ContractVersion: ContractVersion, MinCompatibleContract: MinCompatibleContract}

	tests := []struct {
		callerContract int
		want           Compatibility
	}{
		{callerContract: 0, want: "compatible"},
		{callerContract: 1, want: "compatible"},
		{callerContract: 2, want: "leash-too-old"},
	}
	for _, tt := range tests {
		if got := info.CheckCaller(tt.callerContract); got != tt.want {
			t.Fatalf("CheckCaller(%d) = %q, want %q", tt.callerContract, got, tt.want)
		}
	}
}

// TestHasCapability covers the reason the field exists: a caller that drives one
// flag can ask for that flag instead of being refused by an integer bumped for
// an unrelated removal.
func TestHasCapability(t *testing.T) {
	t.Parallel()

	// A hypothetical future leash: it dropped --inject-service and raised the
	// floor past a contract-1 caller, but still offers --policy.
	future := Info{
		ContractVersion:       4,
		MinCompatibleContract: 4,
		Capabilities:          []string{"policy", "runtime", "user", "require-lsm", "version-json"},
	}
	if got := future.CheckCaller(1); got != "leash-too-new" {
		t.Fatalf("CheckCaller(1) = %q, want %q", got, "leash-too-new")
	}
	if !future.HasCapability("policy") {
		t.Fatal(`HasCapability("policy") = false, want true: the integer over-refuses, the capability is the point`)
	}
	if future.HasCapability("inject-service") {
		t.Fatal(`HasCapability("inject-service") = true, want false: it was removed`)
	}

	// A document from a leash that predates the field decodes with it empty.
	var older Info
	if older.HasCapability("policy") {
		t.Fatal(`HasCapability on a document with no capabilities = true, want false`)
	}
}

// TestHasCapabilityRejectsTheEmptyName: "" is not a capability. A caller that
// reaches here with an unset constant, or a garbled document carrying an empty
// entry, must get false rather than an accidental pass.
func TestHasCapabilityRejectsTheEmptyName(t *testing.T) {
	t.Parallel()

	if describeFor(testBuild(), "linux", "amd64").HasCapability("") {
		t.Fatal(`HasCapability("") = true on a real document, want false`)
	}
	malformed := Info{Capabilities: []string{""}}
	if malformed.HasCapability("") {
		t.Fatal(`HasCapability("") = true against a document carrying an empty entry, want false`)
	}
}

// TestParseReadsTheWireDocument is the consumer path: the bytes are a literal of
// what an installed binary prints, not something this package produced, so a
// renamed JSON tag fails here.
func TestParseReadsTheWireDocument(t *testing.T) {
	t.Parallel()

	stdout := []byte(`{
  "version": "v0.2.0",
  "commit": "c686025-dirty",
  "builtAt": "2026-07-21T10:11:12Z",
  "enforcing": true,
  "contractVersion": 3,
  "minCompatibleContract": 2,
  "capabilities": [
    "policy",
    "runtime"
  ],
  "os": "linux",
  "arch": "amd64"
}
`)

	got, err := Parse(stdout)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := Info{
		Version:               "v0.2.0",
		Commit:                "c686025-dirty",
		BuiltAt:               "2026-07-21T10:11:12Z",
		Enforcing:             true,
		ContractVersion:       3,
		MinCompatibleContract: 2,
		Capabilities:          []string{"policy", "runtime"},
		OS:                    "linux",
		Arch:                  "amd64",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Parse(...) = %+v, want %+v", got, want)
	}

	// And the decoded document drives the comparison a provisioner runs.
	if got.SupportsCaller(1) {
		t.Fatal("SupportsCaller(1) = true against a leash whose floor is 2, want false")
	}
	if !got.SupportsCaller(2) {
		t.Fatal("SupportsCaller(2) = false against the range [2,3], want true")
	}
	if !got.HasCapability("policy") {
		t.Fatal(`HasCapability("policy") = false, want true`)
	}
}

// TestParseRoundTripsWhatThisBuildEmits: the emitted document must satisfy the
// decoder's own validation, or the install gate would reject a genuine leash.
func TestParseRoundTripsWhatThisBuildEmits(t *testing.T) {
	t.Parallel()

	emitted := describeFor(testBuild(), "linux", "amd64")
	encoded, err := emitted.JSON()
	if err != nil {
		t.Fatalf("JSON() error: %v", err)
	}
	got, err := Parse(encoded)
	if err != nil {
		t.Fatalf("Parse of this build's own document: %v", err)
	}
	if !reflect.DeepEqual(got, emitted) {
		t.Fatalf("Parse(JSON(%+v)) = %+v", emitted, got)
	}
}

// TestParseRejectsNonDocuments is the install gate. json.Unmarshal alone accepts
// `null`, `{}` and `{"foo":1}` without error and leaves a zero Info — contract
// range [0,0] — which a contract-0 caller reads as `compatible`. That is a
// fail-open decoder on the one decision that is supposed to refuse, so each of
// these must be an error rather than a document.
func TestParseRejectsNonDocuments(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		stdout     string
		wantErrSub string
	}{
		{name: "empty output", stdout: "", wantErrSub: "empty output"},
		{name: "only whitespace", stdout: "  \n\t ", wantErrSub: "empty output"},
		{name: "an unknown-subcommand diagnostic", stdout: "leash: unknown command \"version\"\n", wantErrSub: "parse leash version document"},
		{name: "truncated object", stdout: "{", wantErrSub: "parse leash version document"},
		{name: "JSON null", stdout: "null", wantErrSub: "want an object"},
		{name: "JSON array", stdout: `[{"version":"v1","contractVersion":1}]`, wantErrSub: "parse leash version document"},
		{name: "a bare string", stdout: `"v0.2.0"`, wantErrSub: "parse leash version document"},
		{name: "a bare number", stdout: `1`, wantErrSub: "parse leash version document"},
		{name: "a bare bool", stdout: `true`, wantErrSub: "parse leash version document"},
		{name: "empty object", stdout: `{}`, wantErrSub: `missing required field "version"`},
		{name: "an unrelated object", stdout: `{"foo":1}`, wantErrSub: `missing required field "version"`},
		{name: "the doctor document, not this one", stdout: `{"schema_version":1,"checks":[]}`, wantErrSub: `missing required field "version"`},
		{name: "no contractVersion", stdout: `{"version":"v0.2.0","commit":"c686025"}`, wantErrSub: `missing required field "contractVersion"`},
		{name: "inverted range", stdout: `{"version":"v0.2.0","contractVersion":1,"minCompatibleContract":2}`, wantErrSub: "inverted contract range"},
		{name: "negative contractVersion", stdout: `{"version":"v0.2.0","contractVersion":-1}`, wantErrSub: "negative contract range"},
		{name: "negative floor", stdout: `{"version":"v0.2.0","contractVersion":1,"minCompatibleContract":-3}`, wantErrSub: "negative contract range"},
		{name: "wrong type for a field", stdout: `{"version":"v0.2.0","contractVersion":"one"}`, wantErrSub: "parse leash version document"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := Parse([]byte(tt.stdout))
			if err == nil {
				t.Fatalf("Parse(%q) error = nil, want one; it returned %+v, whose contract range a contract-0 caller reads as %q",
					tt.stdout, got, got.CheckCaller(0))
			}
			if !strings.Contains(err.Error(), tt.wantErrSub) {
				t.Fatalf("Parse(%q) error = %v, want one containing %q", tt.stdout, err, tt.wantErrSub)
			}
			if !reflect.DeepEqual(got, Info{}) {
				t.Fatalf("Parse(%q) returned %+v alongside its error, want the zero Info", tt.stdout, got)
			}
		})
	}
}

// TestParseAcceptsAMinimalDocument: the required set is deliberately small, so a
// document carrying only the two gate fields still decodes. The floor's absence
// means 0 — "nothing has been removed" — which is why it is not required.
func TestParseAcceptsAMinimalDocument(t *testing.T) {
	t.Parallel()

	got, err := Parse([]byte(`{"version":"v0.2.0","contractVersion":1}`))
	if err != nil {
		t.Fatalf("Parse of a minimal document: %v", err)
	}
	if got.MinCompatibleContract != 0 || got.ContractVersion != 1 {
		t.Fatalf("Parse(...) range = [%d,%d], want [0,1]", got.MinCompatibleContract, got.ContractVersion)
	}
	if !got.SupportsCaller(0) || !got.SupportsCaller(1) {
		t.Fatalf("Parse(...) document %+v refuses a caller inside [0,1]", got)
	}
}
