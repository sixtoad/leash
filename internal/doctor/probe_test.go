package doctor

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/strongdm/leash/internal/runner"
)

// No t.Parallel() in this file either: the probeCaps tests swap the package-level
// procSelfStatus path, and Main() reads the real machine.

func TestCapsFromStatus(t *testing.T) {
	cases := []struct {
		name         string
		status       string
		wantBPF      bool
		wantNetAdmin bool
		wantOK       bool
	}{
		{
			name:         "root: full effective set",
			status:       "Name:\tleash\nCapEff:\t000001ffffffffff\nCapBnd:\t000001ffffffffff\n",
			wantBPF:      true,
			wantNetAdmin: true,
			wantOK:       true,
		},
		{
			name:   "unprivileged: empty effective set",
			status: "Name:\tleash\nCapEff:\t0000000000000000\n",
			wantOK: true,
		},
		{
			// setcap cap_bpf,cap_net_admin+ep — the non-root path leash supports.
			name:         "file caps: only bpf + net_admin",
			status:       "CapEff:\t0000008000001000\n",
			wantBPF:      true,
			wantNetAdmin: true,
			wantOK:       true,
		},
		{
			name:         "net_admin without bpf",
			status:       "CapEff:\t0000000000001000\n",
			wantNetAdmin: true,
			wantOK:       true,
		},
		{
			name:   "no CapEff field at all",
			status: "Name:\tleash\nUid:\t1000\t1000\t1000\t1000\n",
			wantOK: false,
		},
		{
			name:   "malformed mask",
			status: "CapEff:\tnot-hex\n",
			wantOK: false,
		},
		{
			name:   "empty input",
			status: "",
			wantOK: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			bpf, netAdmin, ok := capsFromStatus(c.status)
			if ok != c.wantOK {
				t.Fatalf("ok = %v, want %v", ok, c.wantOK)
			}
			if bpf != c.wantBPF || netAdmin != c.wantNetAdmin {
				t.Errorf("caps = (bpf=%v, net_admin=%v), want (bpf=%v, net_admin=%v)", bpf, netAdmin, c.wantBPF, c.wantNetAdmin)
			}
		})
	}
}

// CAP-3: probeCaps used to answer `euid == 0, euid == 0` whenever it could not
// read the status file, which invents CAP_BPF/CAP_NET_ADMIN for root on darwin
// or in a container with a masked /proc. Every unreadable or unparseable source
// must now come back unknown-and-not-held, whatever the uid.
func TestProbeCapsNeverFabricates(t *testing.T) {
	dir := t.TempDir()

	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return path
	}

	cases := []struct {
		name string
		path string

		wantBPF      bool
		wantNetAdmin bool
		wantKnown    bool
	}{
		{
			name: "unreadable: file does not exist",
			path: filepath.Join(dir, "absent"),
		},
		{
			name: "unreadable: path is a directory",
			path: dir,
		},
		{
			name: "missing CapEff",
			path: write("no-capeff", "Name:\tleash\nUid:\t0\t0\t0\t0\n"),
		},
		{
			name: "malformed mask",
			path: write("malformed", "CapEff:\tzzzz\n"),
		},
		{
			name:         "readable and privileged",
			path:         write("full", "CapEff:\t000001ffffffffff\n"),
			wantBPF:      true,
			wantNetAdmin: true,
			wantKnown:    true,
		},
	}

	original := procSelfStatus
	t.Cleanup(func() { procSelfStatus = original })

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			procSelfStatus = c.path
			bpf, netAdmin, known := probeCaps()
			if known != c.wantKnown {
				t.Fatalf("known = %v, want %v", known, c.wantKnown)
			}
			if bpf != c.wantBPF || netAdmin != c.wantNetAdmin {
				t.Errorf("caps = (bpf=%v, net_admin=%v), want (bpf=%v, net_admin=%v)", bpf, netAdmin, c.wantBPF, c.wantNetAdmin)
			}
		})
	}
}

// An unknown capability set must reach the report as unknown, not as "ready".
func TestProbeCapsUnknownIsNotReady(t *testing.T) {
	original := procSelfStatus
	t.Cleanup(func() { procSelfStatus = original })
	procSelfStatus = filepath.Join(t.TempDir(), "nope")

	h := Probe()
	if h.CapsKnown {
		t.Fatal("capabilities should be unknown when the status file is absent")
	}
	if Evaluate(h).Native.Ready() {
		t.Error("native must never be ready on a host whose capabilities could not be read")
	}
}

// Probe touches the real machine, so this only asserts self-consistency — the
// facts themselves differ per host and must not be pinned.
func TestProbeIsSelfConsistent(t *testing.T) {
	h := Probe()
	if h.GOOS == "" {
		t.Error("GOOS should always be populated")
	}
	if h.BPFLSM == runner.LSMActive && strings.TrimSpace(h.BPFLSMAdvice) != "" {
		t.Errorf("an active bpf LSM should carry no remedy, got %q", h.BPFLSMAdvice)
	}
	if h.BPFLSM != runner.LSMActive && strings.TrimSpace(h.BPFLSMAdvice) == "" {
		t.Error("an unavailable or unknown bpf LSM should carry a remedy")
	}
	if h.ContainerEngine == "" && h.ContainerEngineError != "" {
		t.Errorf("no engine should mean no engine error, got %q", h.ContainerEngineError)
	}
	// Whatever the host is, evaluating it must produce a coherent report.
	r := Evaluate(h)
	if r.Container.Ready() && r.Container.Engine == nil {
		t.Error("a ready container runtime must name its engine")
	}
	if r.Container.Ready() && h.ContainerEngineError != "" {
		t.Errorf("an unreachable engine must not be ready: %q", h.ContainerEngineError)
	}
}

func TestMainRejectsUnknownFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Main([]string{"--nope"}, &stdout, &stderr); code != exitUsage {
		t.Errorf("unknown flag exit = %d, want %d", code, exitUsage)
	}
	if stdout.Len() != 0 {
		t.Errorf("usage errors must not pollute stdout (scripts parse it): %q", stdout.String())
	}
}

// CAP-6: `leash doctor extra --json` used to parse as "no flags", printing human
// text on stdout and exiting with a readiness code — a caller piping it into a
// JSON parser would see a parse error and a "healthy" status.
func TestMainRejectsPositionalArgument(t *testing.T) {
	for _, args := range [][]string{{"extra"}, {"extra", "--json"}, {"--json", "extra"}} {
		var stdout, stderr bytes.Buffer
		code := Main(args, &stdout, &stderr)
		if code != exitUsage {
			t.Errorf("Main(%v) exit = %d, want %d", args, code, exitUsage)
		}
		if stdout.Len() != 0 {
			t.Errorf("Main(%v) wrote to stdout: %q", args, stdout.String())
		}
		if !strings.Contains(stderr.String(), "unexpected argument") {
			t.Errorf("Main(%v) stderr should name the offending argument: %q", args, stderr.String())
		}
	}
}

// CAP-6: --help must not hand a provisioner the exit code that means "this
// machine can enforce".
func TestMainHelpIsNotAReadinessVerdict(t *testing.T) {
	for _, arg := range []string{"--help", "-h"} {
		var stdout, stderr bytes.Buffer
		code := Main([]string{arg}, &stdout, &stderr)
		if code == exitReady {
			t.Errorf("Main(%q) exit = %d, which means the machine can enforce", arg, code)
		}
		if code != exitUsage {
			t.Errorf("Main(%q) exit = %d, want %d", arg, code, exitUsage)
		}
		if stdout.Len() != 0 {
			t.Errorf("Main(%q) wrote help to stdout, which carries the machine-readable report: %q", arg, stdout.String())
		}
		if !strings.Contains(stderr.String(), "usage: leash doctor") {
			t.Errorf("Main(%q) should print usage, got %q", arg, stderr.String())
		}
	}
}

// failingWriter fails on the first byte, standing in for a closed pipe.
type failingWriter struct{ n int }

func (w *failingWriter) Write(p []byte) (int, error) {
	w.n++
	return 0, errors.New("broken pipe")
}

// CAP-6: a delivery failure is not a usage error, and nothing partial escapes.
func TestMainOutputFailureIsNotAUsageError(t *testing.T) {
	for _, args := range [][]string{{"--json"}, {}} {
		out := &failingWriter{}
		var stderr bytes.Buffer
		code := Main(args, out, &stderr)
		if code != exitInternal {
			t.Errorf("Main(%v) exit = %d, want %d (an I/O failure is not a usage error)", args, code, exitInternal)
		}
		if out.n != 1 {
			t.Errorf("Main(%v) made %d writes; the report must be rendered whole and written once", args, out.n)
		}
		if !strings.Contains(stderr.String(), "could not write the report") {
			t.Errorf("Main(%v) stderr = %q", args, stderr.String())
		}
	}
}

func TestMainJSONIsParseable(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Main([]string{"--json"}, &stdout, &stderr)
	switch code {
	case exitReady, exitDegraded, exitNoRuntime:
	default:
		t.Fatalf("unexpected exit %d (stderr: %s)", code, stderr.String())
	}

	var doc struct {
		Verdict string `json:"verdict"`
		Native  struct {
			Status string   `json:"status"`
			Ready  bool     `json:"ready"`
			LSMBPF string   `json:"lsm_bpf"`
			Caps   []string `json:"caps"`
			Issues []string `json:"issues"`
		} `json:"native"`
		Container struct {
			Status string   `json:"status"`
			Ready  bool     `json:"ready"`
			Issues []string `json:"issues"`
		} `json:"container"`
		Unchecked []Unchecked `json:"unchecked"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, stdout.String())
	}
	if doc.Verdict == "" {
		t.Error("the document must carry the verdict, not leave it to be re-derived")
	}
	if doc.Native.Caps == nil || doc.Native.Issues == nil || doc.Container.Issues == nil {
		t.Errorf("arrays must never be null: %s", stdout.String())
	}
	if len(doc.Unchecked) == 0 {
		t.Error("the unchecked prerequisites must always be declared")
	}
	// The exit code and the document must tell the same story.
	wantCode := map[string]int{"ready": exitReady, "degraded": exitDegraded, "unavailable": exitNoRuntime}[doc.Verdict]
	if code != wantCode {
		t.Errorf("verdict %q with exit %d, want exit %d", doc.Verdict, code, wantCode)
	}
}

// Item 4: Probe must notice DOCKER_HOST, because the engine client does. This
// mutates the environment, so (like everything else in this file) it must not
// run in parallel with anything.
func TestProbeReadsDockerHost(t *testing.T) {
	t.Setenv("DOCKER_HOST", "  tcp://build-01.internal:2376  ")
	if got := Probe().DockerHost; got != "tcp://build-01.internal:2376" {
		t.Errorf("DockerHost = %q, want the trimmed value", got)
	}

	t.Setenv("DOCKER_HOST", "   ")
	if got := Probe().DockerHost; got != "" {
		t.Errorf("a whitespace-only DOCKER_HOST is not a remote daemon, got %q", got)
	}

	os.Unsetenv("DOCKER_HOST")
	if got := Probe().DockerHost; got != "" {
		t.Errorf("DockerHost = %q with DOCKER_HOST unset", got)
	}
}

// A remote daemon means the kernel doctor just probed is not the kernel the
// workload gets, whatever this host looks like.
func TestProbeWithDockerHostNeverClaimsAContainerLayer1Verdict(t *testing.T) {
	t.Setenv("DOCKER_HOST", "tcp://build-01.internal:2376")

	h := Probe()
	h.ContainerEngine = "docker" // stand in for an engine that is installed...
	h.ContainerEngineError = ""  // ...and whose daemon answers.

	got := Evaluate(h)
	if got.Container.Ready() {
		t.Error("a reachable REMOTE daemon must not borrow this host's Layer 1 verdict")
	}
	if !hasUnchecked(got.Unchecked, "container_kernel") {
		t.Errorf("the remote kernel must be declared unchecked, got %v", got.Unchecked)
	}
}

// The runtime a bare `leash run` selects has to reach the document, or the
// report grades two runtimes without saying which one the caller gets.
func TestProbeReportsTheDefaultRuntime(t *testing.T) {
	if got, want := Probe().DefaultRuntime, runner.DefaultRuntimeName(); got != want {
		t.Errorf("DefaultRuntime = %q, want %q", got, want)
	}
	if Probe().DefaultRuntime == "" {
		t.Error("the default runtime must never be empty: doctor cannot say what a bare `leash run` does")
	}
}
