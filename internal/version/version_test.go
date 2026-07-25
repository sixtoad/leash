package version

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// testBuild mirrors what the Makefile injects for a tagged release build.
func testBuild() Build {
	return Build{Version: "v0.2.0", Commit: "c686025aa1b2c3", BuildDate: "2026-07-21T10:11:12Z"}
}

// wantInfo is the document testBuild() describes to, with per-case overrides
// applied by the caller.
func wantInfo(version, commit, builtAt string) Info {
	return Info{
		Version:               version,
		Commit:                commit,
		BuiltAt:               builtAt,
		Enforcing:             Enforcing(runtime.GOOS),
		ContractVersion:       ContractVersion,
		MinCompatibleContract: MinCompatibleContract,
		OS:                    runtime.GOOS,
		Arch:                  runtime.GOARCH,
	}
}

func TestContractRangeIsWellFormed(t *testing.T) {
	t.Parallel()

	// The contract is a monotonic integer walk compares against; zero would be
	// indistinguishable from "field missing" once decoded into a Go struct.
	if ContractVersion < 1 {
		t.Fatalf("ContractVersion = %d, want >= 1", ContractVersion)
	}
	// 0 is the contract of a leash with no `version --json` at all, so the floor
	// is meaningful; a negative floor is not.
	if MinCompatibleContract < 0 {
		t.Fatalf("MinCompatibleContract = %d, want >= 0", MinCompatibleContract)
	}
	// An empty range would mean this build serves no caller at all.
	if MinCompatibleContract > ContractVersion {
		t.Fatalf("MinCompatibleContract = %d > ContractVersion = %d: the supported range is empty",
			MinCompatibleContract, ContractVersion)
	}
}

// TestCheckCallerRange pins the rule the contract documents:
// minCompatibleContract <= callerContract <= contractVersion. The Info is built
// by hand rather than from Describe so the range has room on both sides today,
// while the real constants still only span [0, 1].
func TestCheckCallerRange(t *testing.T) {
	t.Parallel()

	leash := Info{MinCompatibleContract: 2, ContractVersion: 4}

	tests := []struct {
		name           string
		callerContract int
		want           Compatibility
	}{
		{name: "caller below the floor: leash dropped its surface", callerContract: 1, want: LeashTooNew},
		{name: "caller at the floor", callerContract: 2, want: Compatible},
		{name: "caller inside the range", callerContract: 3, want: Compatible},
		{name: "caller at the ceiling", callerContract: 4, want: Compatible},
		{name: "caller above the ceiling: leash predates its surface", callerContract: 5, want: LeashTooOld},
		{name: "pre-feature caller is below this floor too", callerContract: 0, want: LeashTooNew},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := leash.CheckCaller(tt.callerContract); got != tt.want {
				t.Fatalf("CheckCaller(%d) = %q, want %q", tt.callerContract, got, tt.want)
			}
			if got, want := leash.SupportsCaller(tt.callerContract), tt.want == Compatible; got != want {
				t.Fatalf("SupportsCaller(%d) = %t, want %t", tt.callerContract, got, want)
			}
		})
	}
}

// TestCheckCallerAgainstThisBuild exercises the same rule against the document
// this build actually emits, including contract 0 — the contract of a leash that
// predates `version --json` entirely, which this build still serves because
// contract 1 removed nothing.
func TestCheckCallerAgainstThisBuild(t *testing.T) {
	t.Parallel()

	info := Describe(testBuild())

	tests := []struct {
		callerContract int
		want           Compatibility
	}{
		{callerContract: 0, want: Compatible},
		{callerContract: ContractVersion, want: Compatible},
		{callerContract: ContractVersion + 1, want: LeashTooOld},
	}

	for _, tt := range tests {
		if got := info.CheckCaller(tt.callerContract); got != tt.want {
			t.Fatalf("Describe(...).CheckCaller(%d) = %q, want %q", tt.callerContract, got, tt.want)
		}
	}
}

// TestEnforcingIsDerivedPerPlatform pins the derivation itself: only the Linux
// build ships the LSM-plus-proxy path, and a darwin build must not advertise it.
func TestEnforcingIsDerivedPerPlatform(t *testing.T) {
	t.Parallel()

	tests := map[string]bool{
		"linux":   true,
		"darwin":  false,
		"windows": false,
		"":        false,
	}
	for goos, want := range tests {
		if got := Enforcing(goos); got != want {
			t.Fatalf("Enforcing(%q) = %t, want %t", goos, got, want)
		}
	}

	// The document reports the platform this binary was built for.
	if got, want := Describe(testBuild()).Enforcing, Enforcing(runtime.GOOS); got != want {
		t.Fatalf("Describe(...).Enforcing = %t on %s, want %t", got, runtime.GOOS, want)
	}
}

func TestDescribe(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		build Build
		want  Info
	}{
		{
			name:  "release build",
			build: testBuild(),
			want:  wantInfo("v0.2.0", "c686025", "2026-07-21T10:11:12Z"),
		},
		{
			name:  "dirty tree keeps its marker",
			build: Build{Version: "dev-c686025", Commit: "c686025aa1b2c3-dirty", BuildDate: "2026-07-21T10:11:12Z"},
			want:  wantInfo("dev-c686025", "c686025-dirty", "2026-07-21T10:11:12Z"),
		},
		{
			// Only the hash component is abbreviated, so a short hash keeps its
			// marker instead of being cut mid-suffix into "abc-dir".
			name:  "short hash keeps its whole marker",
			build: Build{Version: "dev", Commit: "abc-dirty", BuildDate: "unknown"},
			want:  wantInfo("dev", "abc-dirty", "unknown"),
		},
		{
			// A `git describe` value is not a hash: abbreviating it would name a
			// different build ("v1.2.3-"), so it is reported whole.
			name:  "git describe value is left intact",
			build: Build{Version: "v1.2.3-4-gabc1234", Commit: "v1.2.3-4-gabc1234", BuildDate: "unknown"},
			want:  wantInfo("v1.2.3-4-gabc1234", "v1.2.3-4-gabc1234", "unknown"),
		},
		{
			name:  "plain go build defaults",
			build: Build{Version: "dev", Commit: "unknown", BuildDate: "unknown"},
			want:  wantInfo("dev", "unknown", "unknown"),
		},
		{
			name:  "empty ldflags degrade to unknown",
			build: Build{},
			want:  wantInfo("unknown", "unknown", "unknown"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := Describe(tt.build); got != tt.want {
				t.Fatalf("Describe(%+v) = %+v, want %+v", tt.build, got, tt.want)
			}
		})
	}
}

func TestInfoJSONShape(t *testing.T) {
	t.Parallel()

	encoded, err := Describe(testBuild()).JSON()
	if err != nil {
		t.Fatalf("JSON() error: %v", err)
	}
	if !bytes.HasSuffix(encoded, []byte("\n")) {
		t.Fatalf("JSON() = %q, want a trailing newline", encoded)
	}

	// Decode into a map rather than back into Info: the wire field names are the
	// part walk depends on, and a struct round-trip would not catch a rename.
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal %q: %v", encoded, err)
	}

	want := map[string]any{
		"version":               "v0.2.0",
		"commit":                "c686025",
		"builtAt":               "2026-07-21T10:11:12Z",
		"enforcing":             Enforcing(runtime.GOOS),
		"contractVersion":       float64(ContractVersion), // encoding/json decodes numbers as float64
		"minCompatibleContract": float64(MinCompatibleContract),
		"os":                    runtime.GOOS,
		"arch":                  runtime.GOARCH,
	}
	if len(decoded) != len(want) {
		t.Fatalf("JSON() has fields %v, want exactly %v", keys(decoded), keys(want))
	}
	for field, expected := range want {
		got, ok := decoded[field]
		if !ok {
			t.Fatalf("JSON() is missing field %q; got %q", field, encoded)
		}
		if got != expected {
			t.Fatalf("JSON() field %q = %v, want %v", field, got, expected)
		}
	}
}

// legacyGitHash is exactly what cmd/leash's printVersion did before this package
// existed: truncate the raw -X main.commit value at seven characters.
func legacyGitHash(commit string) string {
	if len(commit) > shortHashLen {
		return commit[:shortHashLen]
	}
	return commit
}

// TestHumanIsByteIdenticalForRealBuildValues is the CAP-4 guarantee: for every
// commit value leash's build paths actually inject, the new rendering must match
// the pre-change one byte for byte.
func TestHumanIsByteIdenticalForRealBuildValues(t *testing.T) {
	t.Parallel()

	// Makefile, scripts/release.sh and scripts/install-leash.sh all stamp
	// `git rev-parse --short=7` plus an optional "-dirty"; the ldflags default to
	// "unknown", and the Makefile falls back to "dev" with no git.
	commits := []string{
		"c686025",
		"c686025-dirty",
		"c686025aa1b2c3d4e5f60718293a4b5c6d7e8f90",
		"unknown",
		"dev",
	}
	for _, commit := range commits {
		build := Build{Version: "v0.2.0", Commit: commit, BuildDate: "2026-07-21T10:11:12Z"}
		want := fmt.Sprintf("version: v0.2.0\ngit hash: %s\nbuild date: 2026-07-21T10:11:12Z\n", legacyGitHash(commit))
		if got := Describe(build).Human(); got != want {
			t.Fatalf("Human() for commit %q = %q, want the pre-change %q", commit, got, want)
		}
	}
}

func TestInfoHuman(t *testing.T) {
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
			// Not "abc-dir": truncation applies to the hash, never to the
			// composed hash+suffix string.
			name:  "short hash with a marker is not cut mid-suffix",
			build: Build{Version: "dev", Commit: "abc-dirty", BuildDate: "unknown"},
			want:  "version: dev\ngit hash: abc\nbuild date: unknown\n",
		},
		{
			// Not "v1.2.3-": a describe value is reported whole rather than
			// mangled into the name of a different build.
			name:  "git describe value is not mangled",
			build: Build{Version: "v1.2.3", Commit: "v1.2.3-4-gabc1234", BuildDate: "unknown"},
			want:  "version: v1.2.3\ngit hash: v1.2.3-4-gabc1234\nbuild date: unknown\n",
		},
		{
			name:  "short hash is left alone",
			build: Build{Version: "dev", Commit: "c68602", BuildDate: "unknown"},
			want:  "version: dev\ngit hash: c68602\nbuild date: unknown\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := Describe(tt.build).Human(); got != tt.want {
				t.Fatalf("Human() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRun(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		args       []string
		wantJSON   bool
		wantErrSub string
	}{
		{name: "no args prints human lines", args: nil},
		{name: "explicit text output", args: []string{"--output", "text"}},
		{name: "json flag", args: []string{"--json"}, wantJSON: true},
		{name: "single dash json flag", args: []string{"-json"}, wantJSON: true},
		{name: "output json", args: []string{"--output", "json"}, wantJSON: true},
		{name: "output equals json", args: []string{"--output=json"}, wantJSON: true},
		{name: "case insensitive format", args: []string{"--output", "JSON"}, wantJSON: true},
		{name: "agreeing duplicate specs", args: []string{"--json", "--output", "json"}, wantJSON: true},

		{name: "missing output value", args: []string{"--output"}, wantErrSub: "needs an argument"},
		{name: "unsupported format", args: []string{"--output", "yaml"}, wantErrSub: "unsupported output format"},
		{name: "unknown flag", args: []string{"--verbose"}, wantErrSub: "not defined"},
		{name: "positional argument", args: []string{"json"}, wantErrSub: "unknown argument"},

		// Conflicting specs are rejected in either order rather than silently
		// resolved by last-one-wins.
		{name: "json then text", args: []string{"--json", "--output", "text"}, wantErrSub: "conflicting output formats"},
		{name: "text then json", args: []string{"--output", "text", "--json"}, wantErrSub: "conflicting output formats"},
		{name: "json then text with equals", args: []string{"--json", "--output=text"}, wantErrSub: "conflicting output formats"},

		// An empty format is a caller bug, not a request for the default.
		{name: "empty output with equals", args: []string{"--output="}, wantErrSub: "empty output format"},
		{name: "empty output as a separate word", args: []string{"--output", ""}, wantErrSub: "empty output format"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var out bytes.Buffer
			err := Run(tt.args, testBuild(), &out)
			if tt.wantErrSub != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrSub) {
					t.Fatalf("Run(%v) error = %v, want one containing %q", tt.args, err, tt.wantErrSub)
				}
				if out.Len() != 0 {
					t.Fatalf("Run(%v) wrote %q on error, want nothing", tt.args, out.String())
				}
				return
			}
			if err != nil {
				t.Fatalf("Run(%v) error: %v", tt.args, err)
			}
			if tt.wantJSON {
				var decoded Info
				if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
					t.Fatalf("Run(%v) output %q is not JSON: %v", tt.args, out.String(), err)
				}
				if decoded != Describe(testBuild()) {
					t.Fatalf("Run(%v) decoded to %+v, want %+v", tt.args, decoded, Describe(testBuild()))
				}
				return
			}
			if got, want := out.String(), Describe(testBuild()).Human(); got != want {
				t.Fatalf("Run(%v) = %q, want %q", tt.args, got, want)
			}
		})
	}
}

// TestRunHelp pins the CLI contract for help: usage on the output stream and
// flag.ErrHelp, which cmd/leash turns into a clean exit rather than a
// log.Fatal timestamp and exit 1.
func TestRunHelp(t *testing.T) {
	t.Parallel()

	for _, arg := range []string{"--help", "-h", "-help"} {
		var out bytes.Buffer
		err := Run([]string{arg}, testBuild(), &out)
		if !errors.Is(err, flag.ErrHelp) {
			t.Fatalf("Run(%q) error = %v, want flag.ErrHelp", arg, err)
		}
		printed := out.String()
		for _, want := range []string{"usage: leash version", "--json", "-output", "contractVersion"} {
			if !strings.Contains(printed, want) {
				t.Fatalf("Run(%q) usage = %q, want it to mention %q", arg, printed, want)
			}
		}
		// Help is help: it must not also emit the document.
		if strings.Contains(printed, "build date:") || strings.Contains(printed, "\"builtAt\"") {
			t.Fatalf("Run(%q) printed the version document alongside usage: %q", arg, printed)
		}
	}
}

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
