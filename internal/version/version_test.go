package version

import (
	"bytes"
	"encoding/json"
	"runtime"
	"strings"
	"testing"
)

// testBuild mirrors what the Makefile injects for a tagged release build.
func testBuild() Build {
	return Build{Version: "v0.2.0", Commit: "c686025aa1b2c3", BuildDate: "2026-07-21T10:11:12Z"}
}

func TestContractVersionIsPositive(t *testing.T) {
	t.Parallel()

	// The contract is a monotonic integer walk compares against; zero would be
	// indistinguishable from "field missing" once decoded into a Go struct.
	if ContractVersion < 1 {
		t.Fatalf("ContractVersion = %d, want >= 1", ContractVersion)
	}
	if !Enforcing {
		t.Fatal("Enforcing = false, want true: every leash build ships the enforcement path")
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
			want: Info{
				Version:         "v0.2.0",
				Commit:          "c686025",
				BuiltAt:         "2026-07-21T10:11:12Z",
				Enforcing:       true,
				ContractVersion: ContractVersion,
				OS:              runtime.GOOS,
				Arch:            runtime.GOARCH,
			},
		},
		{
			name:  "dirty tree keeps its marker",
			build: Build{Version: "dev-c686025", Commit: "c686025aa1b2c3-dirty", BuildDate: "2026-07-21T10:11:12Z"},
			want: Info{
				Version:         "dev-c686025",
				Commit:          "c686025-dirty",
				BuiltAt:         "2026-07-21T10:11:12Z",
				Enforcing:       true,
				ContractVersion: ContractVersion,
				OS:              runtime.GOOS,
				Arch:            runtime.GOARCH,
			},
		},
		{
			name:  "plain go build defaults",
			build: Build{Version: "dev", Commit: "unknown", BuildDate: "unknown"},
			want: Info{
				Version:         "dev",
				Commit:          "unknown",
				BuiltAt:         "unknown",
				Enforcing:       true,
				ContractVersion: ContractVersion,
				OS:              runtime.GOOS,
				Arch:            runtime.GOARCH,
			},
		},
		{
			name:  "empty ldflags degrade to unknown",
			build: Build{},
			want: Info{
				Version:         "unknown",
				Commit:          "unknown",
				BuiltAt:         "unknown",
				Enforcing:       true,
				ContractVersion: ContractVersion,
				OS:              runtime.GOOS,
				Arch:            runtime.GOARCH,
			},
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
		"version":         "v0.2.0",
		"commit":          "c686025",
		"builtAt":         "2026-07-21T10:11:12Z",
		"enforcing":       true,
		"contractVersion": float64(ContractVersion), // encoding/json decodes numbers as float64
		"os":              runtime.GOOS,
		"arch":            runtime.GOARCH,
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

func TestInfoHumanMatchesLegacyOutput(t *testing.T) {
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
			// The pre-existing output truncated the raw commit at seven characters,
			// which cut a "-dirty" marker off; keep that byte-for-byte.
			name:  "dirty marker is truncated away, as before",
			build: Build{Version: "dev", Commit: "c686025aa1b2c3-dirty", BuildDate: "unknown"},
			want:  "version: dev\ngit hash: c686025\nbuild date: unknown\n",
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
		{name: "missing output value", args: []string{"--output"}, wantErrSub: "missing argument"},
		{name: "unsupported format", args: []string{"--output", "yaml"}, wantErrSub: "unsupported output format"},
		{name: "unknown flag", args: []string{"--verbose"}, wantErrSub: "unknown argument"},
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

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
