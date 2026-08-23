package doctor

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/strongdm/leash/internal/macext"
	"github.com/strongdm/leash/internal/runner"
)

// No t.Parallel() anywhere in this file: the package was written so the
// readiness matrix needs no globals or env at all, and the repo has repeatedly
// been bitten by parallel tests that mutate shared state. Sequential table
// tests here cost microseconds.

// readyHost is the all-good baseline the single-axis cases mutate one field
// away from, so each of those documents exactly which prerequisite it removes.
//
// One-field mutation is NOT sufficient on its own, and this file no longer
// pretends otherwise: two review rounds passed with a green suite while darwin
// reported `ready` and a Linux host with no Layer 1 reported "cannot enforce
// with ANY runtime", because neither state is one field away from this
// baseline. TestEvaluateAxisMatrix below spells its hosts out in full.
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
		DefaultRuntime:  "native",
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
			// no Layer 1, so policy is not enforced. Native is degraded for the
			// same reason and not worse: root + systemd is all a real native
			// start requires, and an inactive LSM only warns there.
			name: "bpf LSM inactive degrades BOTH runtimes",
			host: func(h Host) Host {
				h.BPFLSM = runner.LSMInactive
				h.BPFLSMAdvice = "add bpf to the lsm= boot parameter"
				return h
			},
			wantNative:         StatusDegraded,
			wantContainer:      StatusDegraded,
			wantVerdict:        StatusDegraded,
			wantExit:           exitDegraded,
			wantNativeIssue:    "lsm=",
			wantContainerIssue: "will NOT be enforced",
		},
		{
			// CAP-7: unknown is not the same as inactive, and it must not be
			// reported as ready either.
			name: "bpf LSM unknown degrades both runtimes",
			host: func(h Host) Host {
				h.BPFLSM = runner.LSMUnknown
				h.BPFLSMAdvice = "the active LSM list could not be read"
				return h
			},
			wantNative:         StatusDegraded,
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
			// CAP-1, the second false `ready`: off Linux the probed kernel is
			// not the container's, and an UNPROBED kernel must never carry a
			// ready verdict. This case previously asserted exactly the wrong
			// answer (container ready, verdict ready, exit 0) in a report that
			// simultaneously declared container_kernel unchecked.
			name:               "not linux — native impossible, container unverified",
			host:               func(h Host) Host { h.GOOS = "darwin"; h.BPFLSM = runner.LSMUnknown; return h },
			wantNative:         StatusUnavailable,
			wantContainer:      StatusDegraded,
			wantVerdict:        StatusDegraded,
			wantExit:           exitDegraded,
			wantNativeIssue:    "requires Linux",
			wantContainerIssue: "unverified",
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
	// The first line of each issue takes the bullet; every later line of the
	// same issue is indented to sit under it.
	if !strings.Contains(text, "    - "+layer1Consequence+"\n      first line\n      second line\n") {
		t.Errorf("continuation lines not aligned under the bullet:\n%s", text)
	}
}

// ---------------------------------------------------------------------------
// The multi-axis matrix.
//
// Every case above this point is readyHost() with one field changed, and that
// shape is why two rounds of review shipped two false verdicts: darwin +
// reachable docker read as `ready` (the probed kernel is not the container's),
// and a Linux host with root, systemd and no active bpf LSM read as "cannot
// enforce with ANY runtime" (a real `leash run` starts it proxy-only). Neither
// host is one field from the baseline, so no single-axis case could see them.
//
// These cases therefore spell the host out in full, across
// {linux,darwin,windows} × {systemd,no} × {root,non-root} × {caps
// known,unknown} × {LSM active,inactive,unknown} × {engine ready,unreachable,
// absent} × {local,DOCKER_HOST}, and assert the whole verdict rather than one
// field of it.
// ---------------------------------------------------------------------------

// hostAxes is a fully-specified host: no defaults, so a case cannot silently
// inherit a fact it did not mean to assert.
type hostAxes struct {
	goos        string
	systemd     bool
	euid        int
	capBPF      bool
	capNetAdmin bool
	capsKnown   bool
	lsm         runner.LSMState
	engine      string
	engineErr   string
	dockerHost  string
}

func (a hostAxes) host() Host {
	advice := ""
	if a.lsm != runner.LSMActive {
		advice = "add bpf to the lsm= list built from THIS host's LSMs and reboot"
	}
	return Host{
		GOOS:                 a.goos,
		HasSystemd:           a.systemd,
		EUID:                 a.euid,
		CapBPF:               a.capBPF,
		CapNetAdmin:          a.capNetAdmin,
		CapsKnown:            a.capsKnown,
		BPFLSM:               a.lsm,
		BPFLSMAdvice:         advice,
		ContainerEngine:      a.engine,
		ContainerEngineError: a.engineErr,
		DockerHost:           a.dockerHost,
		DefaultRuntime:       "native",
	}
}

// rootLinux is the privileged Linux half of an axis tuple, so the cases below
// vary only what they are actually about.
func rootLinux() hostAxes {
	return hostAxes{goos: "linux", systemd: true, euid: 0, capBPF: true, capNetAdmin: true, capsKnown: true}
}

// unprivileged is the shape every non-Linux host really has: no systemd, no
// readable Linux capability set, no readable LSM list.
func unprivileged(goos string, euid int) hostAxes {
	return hostAxes{goos: goos, systemd: false, euid: euid, capsKnown: false, lsm: runner.LSMUnknown}
}

func TestEvaluateAxisMatrix(t *testing.T) {
	withLSM := func(a hostAxes, s runner.LSMState) hostAxes { a.lsm = s; return a }
	withEngine := func(a hostAxes, engine string) hostAxes { a.engine = engine; return a }

	cases := []struct {
		name string
		axes hostAxes

		wantNative    Status
		wantContainer Status
		wantVerdict   Status
		wantExit      int
		wantSubstr    []string // checked against the joined issues of BOTH runtimes
	}{
		{
			name:          "linux root systemd caps, LSM active, docker ready",
			axes:          withEngine(withLSM(rootLinux(), runner.LSMActive), "docker"),
			wantNative:    StatusReady,
			wantContainer: StatusReady,
			wantVerdict:   StatusReady,
			wantExit:      exitReady,
		},
		{
			name:          "linux root systemd caps, LSM active, podman ready",
			axes:          withEngine(withLSM(rootLinux(), runner.LSMActive), "podman"),
			wantNative:    StatusReady,
			wantContainer: StatusReady,
			wantVerdict:   StatusReady,
			wantExit:      exitReady,
		},
		{
			// The false NOT-ready. A real `leash run` starts here: native needs
			// Linux+systemd+root, and decideBPFLSM only WARNS about the LSM
			// unless --require-lsm. Reporting exit 1 / "cannot enforce with ANY
			// runtime" told the operator to go fix a machine that works.
			name:          "linux root systemd caps, LSM inactive, NO engine — degraded, not dead",
			axes:          withLSM(rootLinux(), runner.LSMInactive),
			wantNative:    StatusDegraded,
			wantContainer: StatusUnavailable,
			wantVerdict:   StatusDegraded,
			wantExit:      exitDegraded,
			wantSubstr:    []string{"will NOT be enforced", "no docker/podman on PATH"},
		},
		{
			name:          "linux root systemd caps, LSM unknown, NO engine — degraded",
			axes:          withLSM(rootLinux(), runner.LSMUnknown),
			wantNative:    StatusDegraded,
			wantContainer: StatusUnavailable,
			wantVerdict:   StatusDegraded,
			wantExit:      exitDegraded,
		},
		{
			name:          "linux root systemd caps, LSM inactive, docker ready — both degraded",
			axes:          withEngine(withLSM(rootLinux(), runner.LSMInactive), "docker"),
			wantNative:    StatusDegraded,
			wantContainer: StatusDegraded,
			wantVerdict:   StatusDegraded,
			wantExit:      exitDegraded,
		},
		{
			// CAP-3 on the report axis: root, but the capability set could not
			// be read. Never "root, so capable".
			name: "linux root systemd, caps UNKNOWN, LSM active, docker ready",
			axes: func() hostAxes {
				a := withEngine(withLSM(rootLinux(), runner.LSMActive), "docker")
				a.capBPF, a.capNetAdmin, a.capsKnown = false, false, false
				return a
			}(),
			wantNative:    StatusUnavailable,
			wantContainer: StatusReady,
			wantVerdict:   StatusReady,
			wantExit:      exitReady,
			wantSubstr:    []string{"unknown and therefore treated as absent"},
		},
		{
			name: "linux root systemd, CAP_BPF stripped, LSM active, docker ready",
			axes: func() hostAxes {
				a := withEngine(withLSM(rootLinux(), runner.LSMActive), "docker")
				a.capBPF = false
				return a
			}(),
			wantNative:    StatusUnavailable,
			wantContainer: StatusReady,
			wantVerdict:   StatusReady,
			wantExit:      exitReady,
			wantSubstr:    []string{"missing CAP_BPF"},
		},
		{
			name: "linux NON-ROOT systemd, LSM active, docker ready",
			axes: func() hostAxes {
				a := withEngine(withLSM(rootLinux(), runner.LSMActive), "docker")
				a.euid, a.capBPF, a.capNetAdmin = 1000, false, false
				return a
			}(),
			wantNative:    StatusUnavailable,
			wantContainer: StatusReady,
			wantVerdict:   StatusReady,
			wantExit:      exitReady,
			wantSubstr:    []string{"requires root"},
		},
		{
			// Item 6's host: the verdict is ready and a bare `leash run` still
			// fails, because the default runtime is the one that is dead. The
			// document has to say so somewhere — see TestDefaultRuntimeIsReported.
			name: "linux root NO systemd, LSM active, docker ready",
			axes: func() hostAxes {
				a := withEngine(withLSM(rootLinux(), runner.LSMActive), "docker")
				a.systemd = false
				return a
			}(),
			wantNative:    StatusUnavailable,
			wantContainer: StatusReady,
			wantVerdict:   StatusReady,
			wantExit:      exitReady,
			wantSubstr:    []string{"requires systemd"},
		},
		{
			name: "linux root systemd caps, LSM active, docker daemon UNREACHABLE",
			axes: func() hostAxes {
				a := withEngine(withLSM(rootLinux(), runner.LSMActive), "docker")
				a.engineErr = "docker info failed: Cannot connect to the Docker daemon"
				return a
			}(),
			wantNative:    StatusReady,
			wantContainer: StatusUnavailable,
			wantVerdict:   StatusReady,
			wantExit:      exitReady,
			wantSubstr:    []string{"daemon is not reachable"},
		},
		{
			name: "linux NON-ROOT no systemd, LSM unknown, no engine — nothing works",
			axes: hostAxes{goos: "linux", euid: 1000, lsm: runner.LSMUnknown},

			wantNative:    StatusUnavailable,
			wantContainer: StatusUnavailable,
			wantVerdict:   StatusUnavailable,
			wantExit:      exitNoRuntime,
		},
		{
			// CAP-1, the darwin half. Docker Desktop answers, so the engine is
			// fine — but its LinuxKit kernel was never probed and does not
			// carry bpf. `ready` here is a claim about a kernel doctor has not
			// seen.
			name:          "darwin non-root, docker ready — never plainly ready",
			axes:          withEngine(unprivileged("darwin", 501), "docker"),
			wantNative:    StatusUnavailable,
			wantContainer: StatusDegraded,
			wantVerdict:   StatusDegraded,
			wantExit:      exitDegraded,
			wantSubstr:    []string{"requires Linux", "unverified", "LinuxKit"},
		},
		{
			name:          "darwin ROOT, docker ready — root changes nothing off Linux",
			axes:          withEngine(unprivileged("darwin", 0), "docker"),
			wantNative:    StatusUnavailable,
			wantContainer: StatusDegraded,
			wantVerdict:   StatusDegraded,
			wantExit:      exitDegraded,
		},
		{
			name: "darwin non-root, docker daemon unreachable",
			axes: func() hostAxes {
				a := withEngine(unprivileged("darwin", 501), "docker")
				a.engineErr = "docker info failed: Cannot connect to the Docker daemon"
				return a
			}(),
			wantNative:    StatusUnavailable,
			wantContainer: StatusUnavailable,
			wantVerdict:   StatusUnavailable,
			wantExit:      exitNoRuntime,
		},
		{
			name:          "darwin non-root, no engine",
			axes:          unprivileged("darwin", 501),
			wantNative:    StatusUnavailable,
			wantContainer: StatusUnavailable,
			wantVerdict:   StatusUnavailable,
			wantExit:      exitNoRuntime,
		},
		{
			// windows had zero coverage before this round.
			name:          "windows admin, docker ready — same unprobed-kernel rule",
			axes:          withEngine(unprivileged("windows", 0), "docker"),
			wantNative:    StatusUnavailable,
			wantContainer: StatusDegraded,
			wantVerdict:   StatusDegraded,
			wantExit:      exitDegraded,
			wantSubstr:    []string{"requires Linux", "on windows"},
		},
		{
			name:          "windows, no engine",
			axes:          unprivileged("windows", 0),
			wantNative:    StatusUnavailable,
			wantContainer: StatusUnavailable,
			wantVerdict:   StatusUnavailable,
			wantExit:      exitNoRuntime,
		},
		{
			// DOCKER_HOST: the engine answers, but the kernel that answers is
			// not the kernel doctor read. Native still describes this host, so
			// it keeps its verdict.
			name: "linux root, LSM active, DOCKER_HOST set — container claim withheld",
			axes: func() hostAxes {
				a := withEngine(withLSM(rootLinux(), runner.LSMActive), "docker")
				a.dockerHost = "tcp://build-01.internal:2376"
				return a
			}(),
			wantNative:    StatusReady,
			wantContainer: StatusDegraded,
			wantVerdict:   StatusReady,
			wantExit:      exitReady,
			wantSubstr:    []string{"DOCKER_HOST is set", "remote daemon"},
		},
		{
			// ...and with native out of the picture, the withheld claim is the
			// whole verdict: no runtime is known to enforce here.
			name: "linux non-root, LSM active, DOCKER_HOST set — degraded overall",
			axes: func() hostAxes {
				a := withEngine(withLSM(rootLinux(), runner.LSMActive), "docker")
				a.euid, a.capBPF, a.capNetAdmin = 1000, false, false
				a.dockerHost = "ssh://deploy@build-01.internal"
				return a
			}(),
			wantNative:    StatusUnavailable,
			wantContainer: StatusDegraded,
			wantVerdict:   StatusDegraded,
			wantExit:      exitDegraded,
		},
		{
			// The remote daemon is unreachable: that is a stronger fact than
			// "we cannot see its kernel", and it must win.
			name: "DOCKER_HOST set and unreachable — unavailable beats unverified",
			axes: func() hostAxes {
				a := withEngine(withLSM(rootLinux(), runner.LSMActive), "docker")
				a.dockerHost = "tcp://build-01.internal:2376"
				a.engineErr = "docker info failed: error during connect: dial tcp: i/o timeout"
				return a
			}(),
			wantNative:    StatusReady,
			wantContainer: StatusUnavailable,
			wantVerdict:   StatusReady,
			wantExit:      exitReady,
			wantSubstr:    []string{"daemon is not reachable"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Evaluate(c.axes.host())

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
				t.Errorf("exit = %d, want %d", got.ExitCode(), c.wantExit)
			}
			joined := strings.Join(append(append([]string{}, got.Native.Issues...), got.Container.Issues...), "\n")
			for _, want := range c.wantSubstr {
				if !strings.Contains(joined, want) {
					t.Errorf("issues should mention %q:\n%s", want, joined)
				}
			}

			// Invariants that hold for every host, however it is assembled.
			if got.Native.Ready() != (len(got.Native.Issues) == 0) {
				t.Errorf("native status=%v with issues=%v", got.Native.Status, got.Native.Issues)
			}
			if got.Container.Ready() != (len(got.Container.Issues) == 0) {
				t.Errorf("container status=%v with issues=%v", got.Container.Status, got.Container.Issues)
			}
			// No runtime may be called ready on a kernel doctor never read.
			if c.axes.goos != "linux" || c.axes.dockerHost != "" {
				if got.Container.Ready() {
					t.Errorf("container ready on an unprobed kernel (goos=%s, DOCKER_HOST=%q)", c.axes.goos, c.axes.dockerHost)
				}
				if !hasUnchecked(got.Unchecked, "container_kernel") {
					t.Errorf("an unprobed container kernel must be declared unchecked, got %v", got.Unchecked)
				}
			}
			if got.Verdict() == StatusReady && got.ExitCode() != exitReady {
				t.Errorf("verdict %v with exit %d", got.Verdict(), got.ExitCode())
			}
		})
	}
}

// CAP-2, pinned on its own: the exact host from the review. A real `leash run`
// on it starts and enforces proxy-only, so "this machine cannot enforce with
// ANY runtime" + exit 1 was a false negative — the mirror image of the false
// `ready` this PR exists to remove.
func TestNativeDegradesRatherThanDying(t *testing.T) {
	h := hostAxes{
		goos: "linux", systemd: true, euid: 0,
		capBPF: true, capNetAdmin: true, capsKnown: true,
		lsm:    runner.LSMInactive,
		engine: "", // no docker at all: native is the only runtime in play
	}.host()

	got := Evaluate(h)

	if got.Native.Status != StatusDegraded {
		t.Errorf("native.status = %v, want %v", got.Native.Status, StatusDegraded)
	}
	if got.Native.Ready() {
		t.Error("degraded is not ready: Layer 1 is off")
	}
	if got.ExitCode() != exitDegraded {
		t.Errorf("exit = %d, want %d", got.ExitCode(), exitDegraded)
	}
	if !strings.Contains(strings.Join(got.Native.Issues, "\n"), "will NOT be enforced") {
		t.Errorf("the consequence must be named: %v", got.Native.Issues)
	}
	if strings.Contains(got.Text(), "cannot enforce with ANY runtime") {
		t.Errorf("a machine leash will happily start on must not be declared dead:\n%s", got.Text())
	}
}

// CAP-1, pinned on its own: darwin + a reachable docker. Docker Desktop's
// LinuxKit kernel has no bpf LSM, and doctor never probed it either way.
func TestDarwinWithReachableDockerIsNotReady(t *testing.T) {
	got := Evaluate(hostAxes{goos: "darwin", euid: 501, lsm: runner.LSMUnknown, engine: "docker"}.host())

	if got.Container.Ready() {
		t.Error("container ready on darwin: the kernel that would run it was never probed")
	}
	if got.Verdict() == StatusReady || got.ExitCode() == exitReady {
		t.Errorf("verdict %v / exit %d on an unprobed kernel", got.Verdict(), got.ExitCode())
	}
	if !hasUnchecked(got.Unchecked, "container_kernel") {
		t.Error("the document declares container_kernel unchecked; the verdict must agree with it")
	}
	if strings.Contains(got.Text(), "can enforce with at least one runtime") {
		t.Errorf("darwin still claims enforcement:\n%s", got.Text())
	}
}

// Item 4: DOCKER_HOST substitutes a kernel doctor cannot see. runner's own
// preflight already bails out on it ("the kernel that matters is not this
// host's"); doctor had no such guard.
func TestRemoteDockerHostWithholdsTheContainerVerdict(t *testing.T) {
	a := hostAxes{goos: "linux", systemd: true, euid: 0, capBPF: true, capNetAdmin: true, capsKnown: true, lsm: runner.LSMActive, engine: "docker"}

	local := Evaluate(a.host())
	if local.Container.Status != StatusReady {
		t.Fatalf("baseline: local container should be ready, got %v (%v)", local.Container.Status, local.Container.Issues)
	}

	a.dockerHost = "tcp://build-01.internal:2376"
	remote := Evaluate(a.host())

	if remote.Container.Ready() {
		t.Error("a remote daemon's containers do not run on the kernel doctor probed")
	}
	if remote.Container.Status != StatusDegraded {
		t.Errorf("container.status = %v, want %v", remote.Container.Status, StatusDegraded)
	}
	if !hasUnchecked(remote.Unchecked, "container_kernel") {
		t.Errorf("the remote kernel must be declared unchecked, got %v", remote.Unchecked)
	}
	// Honest reporting only: no modelling of the remote host (an explicit
	// non-goal), and no leaking of a value that can carry a user@host.
	for _, u := range remote.Unchecked {
		if strings.Contains(u.Reason, "build-01.internal") {
			t.Errorf("DOCKER_HOST's value should not be echoed into the report: %q", u.Reason)
		}
	}
	if remote.Native.Status != local.Native.Status {
		t.Errorf("DOCKER_HOST changed the native verdict (%v -> %v); it describes THIS host either way", local.Native.Status, remote.Native.Status)
	}
}

// Item 6: the verdict is "the best any runtime reaches", which is the right
// answer to "can this machine enforce" — but `leash run` with no --runtime
// picks one runtime and never falls back. The document names it, and the human
// output says out loud when the default is not the runtime being praised.
func TestDefaultRuntimeIsReported(t *testing.T) {
	// A host where the verdict is ready and a bare `leash run` still fails.
	a := hostAxes{goos: "linux", systemd: false, euid: 0, capBPF: true, capNetAdmin: true, capsKnown: true, lsm: runner.LSMActive, engine: "docker"}
	got := Evaluate(a.host())

	if got.Verdict() != StatusReady || got.Native.Status != StatusUnavailable {
		t.Fatalf("baseline: want ready verdict from the container runtime with native dead, got verdict=%v native=%v", got.Verdict(), got.Native.Status)
	}

	out, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(out), `"default_runtime":"native"`) {
		t.Errorf("the document must name the runtime a bare `leash run` selects: %s", out)
	}

	text := got.Text()
	if !strings.Contains(text, "no --runtime uses the native runtime") {
		t.Errorf("human output must name the default runtime:\n%s", text)
	}
	if !strings.Contains(text, "NOTE:") || !strings.Contains(text, "never falls back") {
		t.Errorf("a ready verdict the default runtime cannot deliver must be qualified:\n%s", text)
	}

	// When the default IS the runtime carrying the verdict, it is stated
	// plainly rather than warned about.
	ok := Evaluate(hostAxes{goos: "linux", systemd: true, euid: 0, capBPF: true, capNetAdmin: true, capsKnown: true, lsm: runner.LSMActive, engine: "docker"}.host()).Text()
	if strings.Contains(ok, "NOTE:") {
		t.Errorf("no warning is due when the default runtime is ready:\n%s", ok)
	}
	if !strings.Contains(ok, "no --runtime uses the native runtime (READY above)") {
		t.Errorf("the default runtime should still be named:\n%s", ok)
	}
}

// Item 5: a Go consumer that decodes this document must get the report it was
// sent. Report used to be marshal-only — json.Unmarshal errored, and a caller
// that ignored the error held a zero Report, which re-encodes as
// `verdict: unavailable, ready: false` from a document that said ready.
func TestReportJSONRoundTrip(t *testing.T) {
	hosts := map[string]Host{
		"ready":                readyHost(),
		"degraded both":        hostAxes{goos: "linux", systemd: true, euid: 0, capBPF: true, capNetAdmin: true, capsKnown: true, lsm: runner.LSMInactive, engine: "docker"}.host(),
		"darwin unverified":    hostAxes{goos: "darwin", euid: 501, lsm: runner.LSMUnknown, engine: "docker"}.host(),
		"nothing works":        hostAxes{goos: "windows", euid: 0, lsm: runner.LSMUnknown}.host(),
		"remote docker daemon": hostAxes{goos: "linux", systemd: true, euid: 0, capBPF: true, capNetAdmin: true, capsKnown: true, lsm: runner.LSMActive, engine: "docker", dockerHost: "tcp://elsewhere:2376"}.host(),
		// The macOS section has states (and two enum types) of its own, so it
		// gets its own round trips rather than riding on the Linux hosts.
		"mac ready": macHost(),
		"mac degraded": func() Host {
			h := macHost()
			h.Darwin.ProxyExtension = macext.StateDisabled
			h.Darwin.FullDiskAccess = macext.FDAUnknown
			return h
		}(),
		"mac unavailable": func() Host {
			h := macHost()
			h.Darwin.ESExtension = macext.StateUnknown
			h.Darwin.LeashCLIPresent = false
			h.Darwin.DaemonUp = false
			h.Darwin.ComponentsKnown = false
			h.Darwin.Components = nil
			return h
		}(),
	}

	for name, h := range hosts {
		t.Run(name, func(t *testing.T) {
			want := Evaluate(h)

			encoded, err := json.Marshal(want)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}

			var got Report
			if err := json.Unmarshal(encoded, &got); err != nil {
				t.Fatalf("a document this package emitted must decode back into a Report: %v\n%s", err, encoded)
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("round trip lost information:\n got %#v\nwant %#v", got, want)
			}

			// The derived fields must survive too, which they only do if the
			// statuses did: a decoded report that re-encodes differently is the
			// fabricated verdict in slow motion.
			reencoded, err := json.Marshal(got)
			if err != nil {
				t.Fatalf("re-marshal: %v", err)
			}
			if string(reencoded) != string(encoded) {
				t.Errorf("re-encoding differs:\n got %s\nwant %s", reencoded, encoded)
			}
			if got.Verdict() != want.Verdict() || got.ExitCode() != want.ExitCode() {
				t.Errorf("decoded verdict/exit = %v/%d, want %v/%d", got.Verdict(), got.ExitCode(), want.Verdict(), want.ExitCode())
			}
		})
	}
}

// A document from a future leash must not decode into a confident wrong answer.
func TestReportRejectsUnknownStates(t *testing.T) {
	for _, doc := range []string{
		`{"verdict":"ready","native":{"status":"perfect"}}`,
		`{"verdict":"ready","native":{"lsm_bpf":"maybe"}}`,
		`{"verdict":"ready","container":{"status":7}}`,
	} {
		var r Report
		if err := json.Unmarshal([]byte(doc), &r); err == nil {
			t.Errorf("decoding %s should fail rather than yield %#v", doc, r)
		}
	}
}

// Item 5's drift guard. jsonReport & friends are hand-mirrored onto Report, so
// a field added to one side and forgotten on the other silently disappears from
// the wire (or, worse, stops round-tripping). Compare them structurally rather
// than trusting a reviewer to notice.
func TestJSONMirrorCoversEveryReportField(t *testing.T) {
	cases := []struct {
		source, mirror reflect.Type
		// derived names the mirror-only fields: values computed at encode time
		// from the source's own fields, which is why they are not stored.
		derived []string
	}{
		{reflect.TypeOf(Report{}), reflect.TypeOf(jsonReport{}), []string{"Verdict"}},
		{reflect.TypeOf(NativeReport{}), reflect.TypeOf(jsonNative{}), []string{"Ready"}},
		{reflect.TypeOf(ContainerReport{}), reflect.TypeOf(jsonContainer{}), []string{"Ready"}},
		{reflect.TypeOf(DarwinReport{}), reflect.TypeOf(jsonDarwin{}), []string{"Ready"}},
	}

	for _, c := range cases {
		t.Run(c.source.Name(), func(t *testing.T) {
			if got, want := c.mirror.NumField(), c.source.NumField()+len(c.derived); got != want {
				t.Errorf("%s has %d fields, %s has %d + %d derived = %d: the mirror has drifted",
					c.mirror.Name(), got, c.source.Name(), c.source.NumField(), len(c.derived), want)
			}
			for i := 0; i < c.source.NumField(); i++ {
				src := c.source.Field(i)
				mir, ok := c.mirror.FieldByName(src.Name)
				if !ok {
					t.Errorf("%s.%s has no counterpart in %s, so it never reaches the JSON document", c.source.Name(), src.Name, c.mirror.Name())
					continue
				}
				if src.Tag.Get("json") != mir.Tag.Get("json") {
					t.Errorf("%s.%s is tagged %q but the mirror emits %q", c.source.Name(), src.Name, src.Tag.Get("json"), mir.Tag.Get("json"))
				}
			}
			for _, name := range c.derived {
				if _, ok := c.mirror.FieldByName(name); !ok {
					t.Errorf("%s should carry the derived field %s", c.mirror.Name(), name)
				}
			}
		})
	}
}
