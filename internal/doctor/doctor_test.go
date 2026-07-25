package doctor

import (
	"encoding/json"
	"strings"
	"testing"
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
		BPFLSMActive:    true,
		BPFLSMAdvice:    "",
		ContainerEngine: "docker",
	}
}

func TestEvaluateMatrix(t *testing.T) {
	cases := []struct {
		name string
		host func(Host) Host

		wantNativeReady    bool
		wantContainerReady bool
		wantExit           int
		// wantIssueSubstr is checked against the joined issues of whichever
		// runtime is expected to be unready.
		wantNativeIssue    string
		wantContainerIssue string
	}{
		{
			name:               "all good",
			host:               func(h Host) Host { return h },
			wantNativeReady:    true,
			wantContainerReady: true,
			wantExit:           0,
		},
		{
			name:               "no systemd",
			host:               func(h Host) Host { h.HasSystemd = false; return h },
			wantNativeReady:    false,
			wantContainerReady: true,
			wantExit:           0,
			wantNativeIssue:    "systemd",
		},
		{
			name: "non-root (and therefore no caps)",
			host: func(h Host) Host {
				h.EUID = 1000
				h.CapBPF = false
				h.CapNetAdmin = false
				return h
			},
			wantNativeReady:    false,
			wantContainerReady: true,
			wantExit:           0,
			wantNativeIssue:    "root",
		},
		{
			name:               "root but capabilities stripped",
			host:               func(h Host) Host { h.CapBPF = false; return h },
			wantNativeReady:    false,
			wantContainerReady: true,
			wantExit:           0,
			wantNativeIssue:    "CAP_BPF",
		},
		{
			name: "bpf LSM inactive",
			host: func(h Host) Host {
				h.BPFLSMActive = false
				h.BPFLSMAdvice = "add bpf to the lsm= boot parameter"
				return h
			},
			wantNativeReady:    false,
			wantContainerReady: true,
			wantExit:           0,
			wantNativeIssue:    "lsm=",
		},
		{
			name:               "no container engine",
			host:               func(h Host) Host { h.ContainerEngine = ""; return h },
			wantNativeReady:    true,
			wantContainerReady: false,
			wantExit:           0,
			wantContainerIssue: "docker/podman",
		},
		{
			name:               "not linux — native impossible, container carries the node",
			host:               func(h Host) Host { h.GOOS = "darwin"; return h },
			wantNativeReady:    false,
			wantContainerReady: true,
			wantExit:           0,
			wantNativeIssue:    "requires Linux",
		},
		{
			// The exit-code contract from issue #23: neither runtime usable.
			name: "both unusable",
			host: func(h Host) Host {
				h.HasSystemd = false
				h.ContainerEngine = ""
				return h
			},
			wantNativeReady:    false,
			wantContainerReady: false,
			wantExit:           1,
			wantNativeIssue:    "systemd",
			wantContainerIssue: "docker/podman",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Evaluate(c.host(readyHost()))

			if got.Native.Ready != c.wantNativeReady {
				t.Errorf("native.ready = %v, want %v (issues: %v)", got.Native.Ready, c.wantNativeReady, got.Native.Issues)
			}
			if got.Container.Ready != c.wantContainerReady {
				t.Errorf("container.ready = %v, want %v (issues: %v)", got.Container.Ready, c.wantContainerReady, got.Container.Issues)
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

			// A ready runtime must never carry issues, and an unready one must
			// always explain itself — an unactionable failure is the thing this
			// command exists to prevent.
			if got.Native.Ready != (len(got.Native.Issues) == 0) {
				t.Errorf("native ready=%v with issues=%v", got.Native.Ready, got.Native.Issues)
			}
			if got.Container.Ready != (len(got.Container.Issues) == 0) {
				t.Errorf("container ready=%v with issues=%v", got.Container.Ready, got.Container.Issues)
			}
		})
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

// Non-Linux hosts must not be handed a kernel remedy they cannot act on.
func TestNonLinuxSkipsKernelAdvice(t *testing.T) {
	h := readyHost()
	h.GOOS = "darwin"
	h.BPFLSMActive = false
	h.BPFLSMAdvice = "add bpf to the lsm= boot parameter"

	joined := strings.Join(Evaluate(h).Native.Issues, "\n")
	if strings.Contains(joined, "lsm=") {
		t.Errorf("darwin host should not get kernel LSM advice: %q", joined)
	}
}

// An inactive LSM with no probe advice still has to yield an actionable issue.
func TestInactiveLSMAlwaysHasAdvice(t *testing.T) {
	h := readyHost()
	h.BPFLSMActive = false
	h.BPFLSMAdvice = ""

	joined := strings.Join(Evaluate(h).Native.Issues, "\n")
	if !strings.Contains(joined, "CONFIG_BPF_LSM") {
		t.Errorf("want the generic kernel remedy, got %q", joined)
	}
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
		for _, want := range []string{`"engine":null`, `"lsm_bpf":true`, `"caps":["bpf","net_admin"]`} {
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
			wantSubs: []string{"native runtime:    READY", "container runtime: READY", "engine:          docker", "can enforce with at least one runtime"},
		},
		{
			name: "nothing works",
			host: func() Host {
				h := readyHost()
				h.HasSystemd = false
				h.ContainerEngine = ""
				return h
			}(),
			wantSubs: []string{"NOT READY", "engine:          none found", "cannot enforce with ANY runtime", "  issues:"},
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
	h.BPFLSMActive = false
	h.BPFLSMAdvice = "first line\nsecond line"

	text := Evaluate(h).Text()
	if !strings.Contains(text, "    - first line\n      second line\n") {
		t.Errorf("continuation line not aligned under the bullet:\n%s", text)
	}
}
