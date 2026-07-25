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

// wantCapabilities is the surface this build advertises, written out rather than
// obtained from the package under test so a silent change to the list fails
// here as well as in pkg/leashversion.
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
	}
	for _, tt := range tests {
		build := Build{Version: "v0.2.0", Commit: tt.commit, BuildDate: "2026-07-21T10:11:12Z"}
		if got := Human(describeFor(build, "linux", "amd64")); got != tt.want {
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

			got := Human(describeFor(tt.build, "linux", "amd64"))
			if got != tt.want {
				t.Fatalf("Human() = %q, want %q", got, tt.want)
			}
			if strings.Contains(got, "git hash: "+tt.wasCut+"\n") {
				t.Fatalf("Human() = %q, which is the mangled pre-change fragment %q", got, tt.wasCut)
			}
		})
	}
}

// TestHumanRendersTheThreeLines covers the ordinary shapes.
func TestHumanRendersTheThreeLines(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		build Build
		want  string
	}{
		{
			name:  "long hash is truncated to seven",
			build: testBuild(),
			want:  "version: v0.2.0\ngit hash: c686025\nbuild date: 2026-07-21T10:11:12Z\n",
		},
		{
			// The human line has never shown the marker; the JSON document does.
			name:  "dirty marker is dropped, as before",
			build: Build{Version: "dev", Commit: "c686025aa1b2c3-dirty", BuildDate: "unknown"},
			want:  "version: dev\ngit hash: c686025\nbuild date: unknown\n",
		},
		{
			name:  "short hash is left alone",
			build: Build{Version: "dev", Commit: "c68602", BuildDate: "unknown"},
			want:  "version: dev\ngit hash: c68602\nbuild date: unknown\n",
		},
		{
			name:  "empty ldflags degrade to unknown",
			build: Build{},
			want:  "version: unknown\ngit hash: unknown\nbuild date: unknown\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := Human(describeFor(tt.build, "linux", "amd64")); got != tt.want {
				t.Fatalf("Human() = %q, want %q", got, tt.want)
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
