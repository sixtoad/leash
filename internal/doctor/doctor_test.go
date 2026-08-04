package doctor

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/strongdm/leash/internal/runner"
)

// No t.Parallel() anywhere in this file: the package was written so the
// readiness matrix needs no globals or env at all, and the repo has repeatedly
// been bitten by parallel tests that mutate shared state. Sequential table
// tests here cost microseconds.

// readyHost is the all-good baseline every case mutates one axis away from, so
// each case documents exactly which prerequisite it removes.
func readyHost() Host {
	return Host{
		GOOS:            "linux",
		HasSystemd:      true,
		EUID:            0,
		CapBPF:          true,
		CapNetAdmin:     true,
		CapsKnown:       true,
		BPFLSM:          runner.LSMActive,
		BPFLSMAdvice:    "",
		ContainerEngine: "docker",
	}
}

func TestEvaluateMatrix(t *testing.T) {
	cases := []struct {
		name string
		host func(Host) Host

		wantNative    Status
		wantContainer Status
		wantVerdict   Status
		wantExit      int
		// wantIssueSubstr is checked against the joined issues of whichever
		// runtime is expected to be unready.
		wantNativeIssue    string
		wantContainerIssue string
	}{
		{
			name:          "all good",
			host:          func(h Host) Host { return h },
			wantNative:    StatusReady,
			wantContainer: StatusReady,
			wantVerdict:   StatusReady,
			wantExit:      exitReady,
		},
		{
			name:            "no systemd",
			host:            func(h Host) Host { h.HasSystemd = false; return h },
			wantNative:      StatusUnavailable,
			wantContainer:   StatusReady,
			wantVerdict:     StatusReady,
			wantExit:        exitReady,
			wantNativeIssue: "systemd",
		},
		{
			name: "non-root (and therefore no caps)",
			host: func(h Host) Host {
				h.EUID = 1000
				h.CapBPF = false
				h.CapNetAdmin = false
				return h
			},
			wantNative:      StatusUnavailable,
			wantContainer:   StatusReady,
			wantVerdict:     StatusReady,
			wantExit:        exitReady,
			wantNativeIssue: "root",
		},
		{
			name:            "root but capabilities stripped",
			host:            func(h Host) Host { h.CapBPF = false; return h },
			wantNative:      StatusUnavailable,
			wantContainer:   StatusReady,
			wantVerdict:     StatusReady,
			wantExit:        exitReady,
			wantNativeIssue: "CAP_BPF",
		},
		{
			// CAP-3: an unreadable /proc must not be read as "root, so capable".
			name: "capabilities unknown",
			host: func(h Host) Host {
				h.CapsKnown = false
				h.CapBPF = false
				h.CapNetAdmin = false
				return h
			},
			wantNative:      StatusUnavailable,
			wantContainer:   StatusReady,
			wantVerdict:     StatusReady,
			wantExit:        exitReady,
			wantNativeIssue: "unknown and therefore treated as absent",
		},
		{
			// CAP-1/CAP-2: the bug this PR exists for. The engine is installed
			// and reachable, so containers start — but they share a kernel with
			// no Layer 1, so policy is not enforced.
			name: "bpf LSM inactive degrades BOTH runtimes",
			host: func(h Host) Host {
				h.BPFLSM = runner.LSMInactive
				h.BPFLSMAdvice = "add bpf to the lsm= boot parameter"
				return h
			},
			wantNative:         StatusUnavailable,
			wantContainer:      StatusDegraded,
			wantVerdict:        StatusDegraded,
			wantExit:           exitDegraded,
			wantNativeIssue:    "lsm=",
			wantContainerIssue: "will NOT be enforced",
		},
		{
			// CAP-7: unknown is not the same as inactive, and it must not be
			// reported as ready either.
			name: "bpf LSM unknown degrades the container runtime",
			host: func(h Host) Host {
				h.BPFLSM = runner.LSMUnknown
				h.BPFLSMAdvice = "the active LSM list could not be read"
				return h
			},
			wantNative:         StatusUnavailable,
			wantContainer:      StatusDegraded,
			wantVerdict:        StatusDegraded,
			wantExit:           exitDegraded,
			wantNativeIssue:    "could not be read",
			wantContainerIssue: "could not be read",
		},
		{
			// CAP-4: a client binary on PATH is not a runtime.
			name: "container engine present but daemon unreachable",
			host: func(h Host) Host {
				h.ContainerEngineError = "docker info failed: permission denied while trying to connect to the docker API"
				return h
			},
			wantNative:         StatusReady,
			wantContainer:      StatusUnavailable,
			wantVerdict:        StatusReady,
			wantExit:           exitReady,
			wantContainerIssue: "daemon is not reachable",
		},
		{
			name:               "no container engine",
			host:               func(h Host) Host { h.ContainerEngine = ""; return h },
			wantNative:         StatusReady,
			wantContainer:      StatusUnavailable,
			wantVerdict:        StatusReady,
			wantExit:           exitReady,
			wantContainerIssue: "docker/podman",
		},
		{
			// Off Linux the probed kernel is not the container's, so no Layer 1
			// claim is made from it either way (see unchecked()).
			name:            "not linux — native impossible, container carries the node",
			host:            func(h Host) Host { h.GOOS = "darwin"; h.BPFLSM = runner.LSMUnknown; return h },
			wantNative:      StatusUnavailable,
			wantContainer:   StatusReady,
			wantVerdict:     StatusReady,
			wantExit:        exitReady,
			wantNativeIssue: "requires Linux",
		},
		{
			// The exit-code contract from issue #23: neither runtime usable.
			name: "both unusable",
			host: func(h Host) Host {
				h.HasSystemd = false
				h.ContainerEngine = ""
				return h
			},
			wantNative:         StatusUnavailable,
			wantContainer:      StatusUnavailable,
			wantVerdict:        StatusUnavailable,
			wantExit:           exitNoRuntime,
			wantNativeIssue:    "systemd",
			wantContainerIssue: "docker/podman",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Evaluate(c.host(readyHost()))

			if got.Native.Status != c.wantNative {
				t.Errorf("native.status = %v, want %v (issues: %v)", got.Native.Status, c.wantNative, got.Native.Issues)
			}
			if got.Container.Status != c.wantContainer {
				t.Errorf("container.status = %v, want %v (issues: %v)", got.Container.Status, c.wantContainer, got.Container.Issues)
			}
			if got.Verdict() != c.wantVerdict {
				t.Errorf("verdict = %v, want %v", got.Verdict(), c.wantVerdict)
			}
			if got.ExitCode() != c.wantExit {
				t.Errorf("exit code = %d, want %d", got.ExitCode(), c.wantExit)
			}
			if c.wantNativeIssue != "" && !strings.Contains(strings.Join(got.Native.Issues, "\n"), c.wantNativeIssue) {
				t.Errorf("native issues %q should mention %q", got.Native.Issues, c.wantNativeIssue)
			}
			if c.wantContainerIssue != "" && !strings.Contains(strings.Join(got.Container.Issues, "\n"), c.wantContainerIssue) {
				t.Errorf("container issues %q should mention %q", got.Container.Issues, c.wantContainerIssue)
			}

			// Ready must track the status exactly — the whole point of the
			// third state is that `ready` keeps meaning "enforces".
			if got.Native.Ready() != (got.Native.Status == StatusReady) {
				t.Errorf("native ready=%v disagrees with status=%v", got.Native.Ready(), got.Native.Status)
			}
			if got.Container.Ready() != (got.Container.Status == StatusReady) {
				t.Errorf("container ready=%v disagrees with status=%v", got.Container.Ready(), got.Container.Status)
			}
			// A ready runtime must never carry issues, and anything less than
			// ready must always explain itself — an unactionable failure is the
			// thing this command exists to prevent.
			if got.Native.Ready() != (len(got.Native.Issues) == 0) {
				t.Errorf("native status=%v with issues=%v", got.Native.Status, got.Native.Issues)
			}
			if got.Container.Ready() != (len(got.Container.Issues) == 0) {
				t.Errorf("container status=%v with issues=%v", got.Container.Status, got.Container.Issues)
			}
		})
	}
}

// CAP-1, pinned on its own: this exact combination (engine installed and
// reachable, bpf LSM not active) is what returned container.ready:true and
// exit 0 before this change, on a machine where `leash run --runtime docker`
// silently drops filesystem/exec/socket enforcement.
func TestContainerNotReadyWhenBPFLSMInactive(t *testing.T) {
	h := readyHost()
	h.BPFLSM = runner.LSMInactive
	h.BPFLSMAdvice = "add bpf to the lsm= list and reboot"

	got := Evaluate(h)

	if got.Container.Ready() {
		t.Error("container must not be plainly ready when the shared kernel has no active bpf LSM")
	}
	if got.Container.Status != StatusDegraded {
		t.Errorf("container.status = %v, want %v — it still runs, it just does not enforce Layer 1", got.Container.Status, StatusDegraded)
	}
	if got.Verdict() == StatusReady {
		t.Error("verdict must not be ready when no runtime enforces Layer 1")
	}
	if got.ExitCode() == exitReady {
		t.Error("a degraded-only machine must not exit with the code that means it can enforce")
	}
	if !strings.Contains(strings.Join(got.Container.Issues, "\n"), "will NOT be enforced") {
		t.Errorf("the consequence must be named in issues, got %q", got.Container.Issues)
	}
	// And the old wording must not survive anywhere.
	if strings.Contains(got.Text(), "can enforce with at least one runtime") {
		t.Errorf("degraded machine still claims it can enforce:\n%s", got.Text())
	}
}

// A non-root host should report the single sudo-shaped blocker, not that plus
// the two capability issues sudo would also fix.
func TestNonRootReportsOneBlocker(t *testing.T) {
	h := readyHost()
	h.EUID = 1000
	h.CapBPF = false
	h.CapNetAdmin = false

	got := Evaluate(h).Native
	if len(got.Issues) != 1 {
		t.Fatalf("want a single root issue, got %d: %v", len(got.Issues), got.Issues)
	}
	if len(got.Caps) != 0 {
		t.Errorf("caps should reflect reality (none held), got %v", got.Caps)
	}
}

// CAP-3, at the report level: unknown capabilities are never rendered as held,
// not even for uid 0.
func TestUnknownCapsAreNeverReportedAsHeld(t *testing.T) {
	h := readyHost()
	h.EUID = 0
	h.CapsKnown = false
	h.CapBPF = true // a stale/garbage value must not leak through
	h.CapNetAdmin = true

	got := Evaluate(h)
	if len(got.Native.Caps) != 0 {
		t.Errorf("caps must stay empty when unknown, got %v", got.Native.Caps)
	}
	if got.Native.Ready() {
		t.Error("unknown capabilities must not yield a ready native runtime")
	}
	if !hasUnchecked(got.Unchecked, "capabilities") {
		t.Errorf("unknown capabilities must be declared unchecked, got %v", got.Unchecked)
	}
}

// Non-Linux hosts must not be handed a kernel remedy they cannot act on.
func TestNonLinuxSkipsKernelAdvice(t *testing.T) {
	h := readyHost()
	h.GOOS = "darwin"
	h.BPFLSM = runner.LSMUnknown
	h.BPFLSMAdvice = "add bpf to the lsm= boot parameter"

	joined := strings.Join(Evaluate(h).Native.Issues, "\n")
	if strings.Contains(joined, "lsm=") {
		t.Errorf("darwin host should not get kernel LSM advice: %q", joined)
	}
}

// An unavailable LSM with no probe advice still has to yield an actionable issue.
func TestInactiveLSMAlwaysHasAdvice(t *testing.T) {
	h := readyHost()
	h.BPFLSM = runner.LSMInactive
	h.BPFLSMAdvice = ""

	joined := strings.Join(Evaluate(h).Native.Issues, "\n")
	if !strings.Contains(joined, "CONFIG_BPF_LSM") {
		t.Errorf("want the generic kernel remedy, got %q", joined)
	}
}

// CAP-5: the prerequisites issue #23 names but doctor does not probe are
// declared, not silently omitted — in JSON and in the human output.
func TestNamedPrerequisitesAreDeclaredUnchecked(t *testing.T) {
	got := Evaluate(readyHost())

	for _, name := range []string{"bpf_lsm_attachable", "bpf_d_path_ringbuf", "netns_iptables"} {
		if !hasUnchecked(got.Unchecked, name) {
			t.Errorf("%q must be declared unchecked, got %v", name, got.Unchecked)
		}
	}

	out, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, name := range []string{"bpf_d_path_ringbuf", "netns_iptables"} {
		if !strings.Contains(string(out), name) {
			t.Errorf("JSON must declare %q as unchecked: %s", name, out)
		}
	}

	text := got.Text()
	if !strings.Contains(text, "not checked by doctor:") {
		t.Errorf("human output must declare the unchecked prerequisites:\n%s", text)
	}
	for _, name := range []string{"bpf_d_path_ringbuf", "netns_iptables"} {
		if !strings.Contains(text, name) {
			t.Errorf("human output missing unchecked %q:\n%s", name, text)
		}
	}
}

// Off Linux the container's kernel was not the one probed; say so rather than
// implying the host LSM reading applies to it.
func TestNonLinuxDeclaresContainerKernelUnchecked(t *testing.T) {
	h := readyHost()
	h.GOOS = "darwin"
	h.BPFLSM = runner.LSMUnknown

	got := Evaluate(h)
	if !hasUnchecked(got.Unchecked, "container_kernel") {
		t.Errorf("darwin must declare the container's kernel unchecked, got %v", got.Unchecked)
	}
}

func hasUnchecked(list []Unchecked, name string) bool {
	for _, u := range list {
		if u.Name == name {
			return true
		}
	}
	return false
}

// The JSON shape is the contract walk parses; pin the keys and the
// null-vs-string engine encoding.
func TestJSONShape(t *testing.T) {
	t.Run("engine absent is null and empty lists are []", func(t *testing.T) {
		h := readyHost()
		h.ContainerEngine = ""
		h.GOOS = "darwin" // also drives native issues, leaving caps populated

		out, err := json.Marshal(Evaluate(h))
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		for _, want := range []string{`"engine":null`, `"lsm_bpf":"active"`, `"caps":["bpf","net_admin"]`} {
			if !strings.Contains(string(out), want) {
				t.Errorf("JSON %s missing %s", out, want)
			}
		}
	})

	t.Run("ready host emits empty issue arrays, never null", func(t *testing.T) {
		out, err := json.Marshal(Evaluate(readyHost()))
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if strings.Contains(string(out), "null") {
			t.Errorf("a fully ready report should contain no nulls: %s", out)
		}
		if !strings.Contains(string(out), `"issues":[]`) {
			t.Errorf("issues should marshal as []: %s", out)
		}
		if !strings.Contains(string(out), `"engine":"docker"`) {
			t.Errorf("engine should be reported: %s", out)
		}
	})

	// CAP-8: the guarantees must hold for *any* Report, including one a caller
	// built by hand — that is the case that produced caps:null / issues:null.
	t.Run("zero-value Report is still a complete document", func(t *testing.T) {
		out, err := json.Marshal(Report{})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		got := string(out)
		for _, want := range []string{
			`"verdict":"unavailable"`,
			`"caps":[]`,
			`"issues":[]`,
			`"unchecked":[]`,
			`"ready":false`,
			`"status":"unavailable"`,
			`"lsm_bpf":"unknown"`,
		} {
			if !strings.Contains(got, want) {
				t.Errorf("json.Marshal(Report{}) missing %s: %s", want, got)
			}
		}
		if strings.Contains(got, ":null") && !strings.Contains(got, `"engine":null`) {
			t.Errorf("only engine may be null: %s", got)
		}
	})

	// CAP-8: the verdict is in the document, so a consumer never re-derives it.
	t.Run("verdict is present and matches the runtimes", func(t *testing.T) {
		h := readyHost()
		h.BPFLSM = runner.LSMInactive
		h.BPFLSMAdvice = "reboot with bpf in the lsm list"

		out, err := json.Marshal(Evaluate(h))
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		for _, want := range []string{`"verdict":"degraded"`, `"status":"degraded"`, `"ready":false`} {
			if !strings.Contains(string(out), want) {
				t.Errorf("JSON missing %s: %s", want, out)
			}
		}
	})
}

func TestTextMirrorsJSON(t *testing.T) {
	cases := []struct {
		name     string
		host     Host
		wantSubs []string
	}{
		{
			name:     "all good",
			host:     readyHost(),
			wantSubs: []string{"native runtime:    READY", "container runtime: READY", "engine:          docker", "bpf LSM:         active", "can enforce with at least one runtime"},
		},
		{
			name: "degraded",
			host: func() Host {
				h := readyHost()
				h.BPFLSM = runner.LSMInactive
				h.BPFLSMAdvice = "reboot with bpf in the lsm list"
				return h
			}(),
			wantSubs: []string{"container runtime: DEGRADED (runs, Layer 1 off)", "bpf LSM:         inactive", "result: DEGRADED"},
		},
		{
			name: "nothing works",
			host: func() Host {
				h := readyHost()
				h.HasSystemd = false
				h.ContainerEngine = ""
				return h
			}(),
			wantSubs: []string{"NOT USABLE", "engine:          none found", "cannot enforce with ANY runtime", "  issues:"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			text := Evaluate(c.host).Text()
			for _, want := range c.wantSubs {
				if !strings.Contains(text, want) {
					t.Errorf("text output missing %q:\n%s", want, text)
				}
			}
		})
	}
}

// Multi-line remedies must stay indented under their bullet, or the human
// output turns into an unreadable wall.
func TestTextIndentsMultiLineAdvice(t *testing.T) {
	h := readyHost()
	h.BPFLSM = runner.LSMInactive
	h.BPFLSMAdvice = "first line\nsecond line"

	text := Evaluate(h).Text()
	if !strings.Contains(text, "    - first line\n      second line\n") {
		t.Errorf("continuation line not aligned under the bullet:\n%s", text)
	}
}
