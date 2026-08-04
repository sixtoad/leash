// Package doctor answers one question — "can this machine actually enforce?" —
// per runtime, in a machine-readable shape.
//
// It exists because provisioning tools (walk `install leash`, CI images) were
// re-deriving leash's prerequisites with their own coarse probes: grep
// /sys/kernel/security/lsm for "bpf", LookPath docker. Those guesses drift from
// what leash really needs. Everything decided here therefore delegates to the
// same pure classifiers a real run uses (internal/runner), so a "ready: true"
// from doctor and a successful `leash run` cannot disagree.
//
// The split in this package is deliberate: doctor.go is pure — it turns an
// already-probed Host into a Report and never touches the filesystem, PATH, or
// the process's identity — while probe.go does the touching. That keeps the
// whole readiness matrix unit-testable without a real kernel or root.
package doctor

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/strongdm/leash/internal/runner"
)

// Host is the set of facts a readiness decision is made from. Probe() fills it
// from the live machine; tests fill it by hand.
type Host struct {
	GOOS       string // runtime.GOOS
	HasSystemd bool   // systemd-run + systemctl on PATH
	EUID       int    // effective uid of this process

	// CapBPF/CapNetAdmin are the effective capabilities leash's native path
	// needs: CAP_BPF to load and attach the LSM programs, CAP_NET_ADMIN to
	// build the workload's network namespace for the fail-closed proxy.
	// They are only meaningful when CapsKnown is true.
	CapBPF      bool
	CapNetAdmin bool

	// CapsKnown records whether the capability set was actually read. False
	// means /proc/self/status was unreadable or unparseable — on darwin, or in
	// a container with a masked /proc. An unread capability set is never
	// inferred from euid: a root process whose caps we cannot see is exactly
	// the case where guessing "root has everything" invents enforcement that
	// is not there.
	CapsKnown bool

	// BPFLSM and BPFLSMAdvice come from runner.ProbeBPFLSM: the tri-state
	// availability of leash's Layer 1 (eBPF LSM) on this kernel, and the
	// kernel-specific remedy when it is not available (which embeds the host's
	// actual LSM list, so it has to be probed rather than derived here).
	BPFLSM       runner.LSMState
	BPFLSMAdvice string

	// ContainerEngine is the container CLI a default `leash run` would drive
	// ("docker", "podman"), or "" when none is installed.
	ContainerEngine string

	// ContainerEngineError is the daemon-reachability failure for
	// ContainerEngine, or "" when the daemon answered. Only meaningful when
	// ContainerEngine is non-empty.
	ContainerEngineError string
}

// Status is the three-state readiness of one runtime. Two states were not
// enough: a Linux host with a container engine but no active bpf LSM *will*
// start a workload, and leash will enforce the fail-closed proxy (Layer 2)
// while filesystem/exec/socket policy (Layer 1) is silently off. Calling that
// "ready" is the false assurance this command exists to prevent; calling it
// "not ready" hides that the machine still runs workloads under partial
// enforcement. It gets its own name.
//
// The zero value is StatusUnavailable, so a Report that was never filled in
// cannot claim readiness. The ordering is meaningful: Verdict is the best
// status any runtime achieves.
type Status int

const (
	StatusUnavailable Status = iota // leash cannot run through this runtime at all
	StatusDegraded                  // runs, but Layer 1 (eBPF LSM) is unavailable
	StatusReady                     // runs with both enforcement layers
)

// String is the wire form used in JSON and human output.
func (s Status) String() string {
	switch s {
	case StatusReady:
		return "ready"
	case StatusDegraded:
		return "degraded"
	default:
		return "unavailable"
	}
}

// MarshalJSON emits the string form. Integers would make the payload's meaning
// depend on a constant table the consumer does not have.
func (s Status) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

// Unchecked names a prerequisite doctor does *not* verify. Issue #23 lists
// prerequisites (attachability, bpf_d_path/ringbuf, netns+iptables) that this
// command does not probe; omitting them silently would let a consumer read a
// "ready" verdict as a stronger guarantee than it is. Name is stable for
// machines, Reason is the sentence a human needs.
type Unchecked struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// Report is the `leash doctor --json` document. The field names are the
// contract consumers parse, so treat them as API: additive changes only.
//
// Verdict and the per-runtime Ready flags are derived, not stored, so the
// document can never contradict itself — see MarshalJSON.
type Report struct {
	Native    NativeReport
	Container ContainerReport
	Unchecked []Unchecked
}

// NativeReport covers the container-free runtime (leashd as a host process in a
// systemd scope). lsm_bpf and caps are reported even when the runtime is not
// ready, so a provisioner can see how far the host got rather than just that it
// failed. lsm_bpf describes this host's kernel, which is also the kernel a
// local container shares.
type NativeReport struct {
	Status Status
	LSMBPF runner.LSMState
	Caps   []string
	Issues []string
}

// ContainerReport covers the docker/podman runtime. Engine is a pointer so an
// absent engine marshals as JSON null (per issue #23) rather than "".
type ContainerReport struct {
	Status Status
	Engine *string
	Issues []string
}

// Ready is true only for a runtime that enforces with both layers. It is
// deliberately *not* widened to include StatusDegraded: `ready` is the field a
// provisioner gates on, and redefining it to mean "partly enforcing" would
// reintroduce the false assurance in a new place.
func (n NativeReport) Ready() bool { return n.Status == StatusReady }

// Ready mirrors NativeReport.Ready.
func (c ContainerReport) Ready() bool { return c.Status == StatusReady }

// Capability names as they appear in the JSON "caps" array — lowercase, without
// the CAP_ prefix, matching the shape in issue #23.
const (
	capNameBPF      = "bpf"
	capNameNetAdmin = "net_admin"
)

// Fallback for the (unlikely) case where the LSM probe reports unavailable
// without producing advice; an issue with no remedy would be worse than a
// generic one.
const genericLSMAdvice = `the eBPF LSM (Layer 1) is not active on this kernel: "bpf" must be in the active LSM list (/sys/kernel/security/lsm).
Add bpf to the lsm= kernel boot parameter and reboot, on a kernel built with CONFIG_BPF_LSM=y (Linux >= 5.7).`

// The Layer 1 consequence, named once and used by both runtimes: this sentence
// is the whole point of the degraded state.
const layer1Consequence = "eBPF LSM enforcement (Layer 1) is unavailable, so filesystem, exec and socket policy will NOT be enforced; only the fail-closed egress proxy (Layer 2) applies."

// Prerequisites issue #23 names that this command does not verify. Declared
// rather than silently omitted, so "ready" is read for exactly what it means.
var alwaysUnchecked = []Unchecked{
	{
		Name:   "bpf_lsm_attachable",
		Reason: "doctor reads the active LSM list (/sys/kernel/security/lsm); it does not load and attach a probe program, so an active-but-unattachable BPF LSM would still report active (leash issue #52).",
	},
	{
		Name:   "bpf_d_path_ringbuf",
		Reason: "availability of the bpf_d_path helper and BPF ring buffer, which leash's LSM programs need, is not probed.",
	},
	{
		Name:   "netns_iptables",
		Reason: "the network-namespace and iptables prerequisites for forcing egress through the proxy are not probed.",
	},
}

// Evaluate is the whole decision. Pure by construction: every input arrives in
// Host, and the runner helpers it calls are themselves pure classifiers.
func Evaluate(h Host) Report {
	return Report{
		Native:    evaluateNative(h),
		Container: evaluateContainer(h),
		Unchecked: unchecked(h),
	}
}

func evaluateNative(h Host) NativeReport {
	n := NativeReport{
		LSMBPF: h.BPFLSM,
		Caps:   []string{},
		Issues: []string{},
	}
	if h.CapsKnown {
		if h.CapBPF {
			n.Caps = append(n.Caps, capNameBPF)
		}
		if h.CapNetAdmin {
			n.Caps = append(n.Caps, capNameNetAdmin)
		}
	}

	// Platform, systemd and root come from the classifier a real
	// `--runtime native` start uses, so doctor can never call a host ready that
	// leash would refuse. That classifier reports one blocker at a time, which
	// is the right shape here too: on a non-Linux host the systemd and root
	// questions are meaningless.
	rootBlocked := false
	if advice := runner.NativeRuntimeAdvice(h.GOOS, h.HasSystemd, h.EUID); advice != "" {
		n.Issues = append(n.Issues, advice)
		rootBlocked = true
	}
	// Root already implies both capabilities, so only inspect them once the
	// root gate has passed — otherwise every unprivileged host reports three
	// issues that a single sudo fixes. Non-root hosts still get their caps
	// listed above; it is the redundant *issues* we suppress, not the facts.
	if !rootBlocked {
		switch {
		case !h.CapsKnown:
			n.Issues = append(n.Issues, "cannot read this process's effective capabilities (/proc/self/status): CAP_BPF and CAP_NET_ADMIN are unknown and therefore treated as absent.\nRun doctor on the host (not inside a container with a masked /proc) so the capability set can be read.")
		default:
			if !h.CapBPF {
				n.Issues = append(n.Issues, "missing CAP_BPF: leash cannot load or attach its eBPF LSM programs.\nRun as root, or grant the leash binary cap_bpf (setcap cap_bpf,cap_net_admin+ep).")
			}
			if !h.CapNetAdmin {
				n.Issues = append(n.Issues, "missing CAP_NET_ADMIN: leash cannot create the workload's network namespace, so egress cannot be forced through the fail-closed proxy.\nRun as root, or grant the leash binary cap_net_admin (setcap cap_bpf,cap_net_admin+ep).")
			}
		}
	}
	// The LSM question only means something on Linux — elsewhere the "not
	// linux" issue above already says everything, and a kernel remedy would be
	// noise.
	if h.GOOS == "linux" && h.BPFLSM != runner.LSMActive {
		n.Issues = append(n.Issues, lsmAdvice(h))
	}

	// Native is all-or-nothing: without root there is neither an LSM nor a
	// netns for the proxy, so decideNativeRuntime refuses to start at all.
	// There is no partial state to report here.
	if len(n.Issues) == 0 {
		n.Status = StatusReady
	}
	return n
}

func evaluateContainer(h Host) ContainerReport {
	c := ContainerReport{Issues: []string{}}
	engine := strings.TrimSpace(h.ContainerEngine)
	if engine == "" {
		c.Issues = append(c.Issues, "no docker/podman on PATH: install a container engine, or use the native runtime (Linux + systemd + root).")
		return c
	}
	// Copied into a local so the pointer never aliases the caller's Host.
	name := engine
	c.Engine = &name

	// A client binary on PATH is not a runtime. An engine whose daemon does not
	// answer cannot start anything, so it is unavailable, not degraded.
	if failure := strings.TrimSpace(h.ContainerEngineError); failure != "" {
		c.Issues = append(c.Issues, fmt.Sprintf("%s is installed but its daemon is not reachable, so no container can be started.\n%s\nStart the engine (e.g. systemctl start docker), or ensure this user may reach its socket.", engine, failure))
		return c
	}

	// The container shares the host kernel, so Layer 1 availability here is the
	// same fact the native path reports — an engine that runs is not an engine
	// that enforces. Off Linux the container's kernel is a VM's, not the one
	// probed, so no Layer 1 claim is made either way (see unchecked()).
	if h.GOOS == "linux" && h.BPFLSM != runner.LSMActive {
		c.Status = StatusDegraded
		c.Issues = append(c.Issues, fmt.Sprintf("%s can start containers, but they share this host's kernel: %s\n%s", engine, layer1Consequence, lsmAdvice(h)))
		return c
	}

	c.Status = StatusReady
	return c
}

// lsmAdvice picks the probe's kernel-specific remedy, falling back to a generic
// one so an unavailable Layer 1 is never reported without a next step.
func lsmAdvice(h Host) string {
	if advice := strings.TrimSpace(h.BPFLSMAdvice); advice != "" {
		return advice
	}
	return genericLSMAdvice
}

// unchecked lists the prerequisites this run did not verify: the fixed ones
// issue #23 names, plus whatever this particular host hid from the probes.
func unchecked(h Host) []Unchecked {
	out := append([]Unchecked{}, alwaysUnchecked...)
	if !h.CapsKnown {
		out = append(out, Unchecked{
			Name:   "capabilities",
			Reason: "/proc/self/status could not be read or parsed, so CAP_BPF/CAP_NET_ADMIN were not observed (reported as absent, never assumed).",
		})
	}
	if h.GOOS != "linux" {
		out = append(out, Unchecked{
			Name:   "container_kernel",
			Reason: "doctor probed this host's kernel; on this platform containers run against a VM kernel that was not probed, so Layer 1 availability inside them is unverified.",
		})
	}
	return out
}

// Verdict is the best state any runtime reaches. It is in the JSON document
// (CAP-8) so a consumer never re-implements leash's own readiness policy and
// then drifts from it.
func (r Report) Verdict() Status {
	if r.Container.Status > r.Native.Status {
		return r.Container.Status
	}
	return r.Native.Status
}

// Usable reports whether at least one runtime can run a workload at all,
// including under degraded (proxy-only) enforcement.
func (r Report) Usable() bool { return r.Verdict() != StatusUnavailable }

// ExitCode is the script-facing verdict.
//
//	0  a runtime enforces with both layers
//	3  a runtime will run, but only with proxy-only enforcement (degraded)
//	1  no runtime can run at all
//
// Degraded is non-zero on purpose. Exit 0 is the answer to "can this machine
// enforce?", and a machine with Layer 1 off cannot enforce filesystem, exec or
// socket policy — a provisioner that gates on `leash doctor && ...` must fail
// closed there. It gets its own code rather than collapsing into 1 because the
// remedy differs completely: 1 means "install/repair a runtime", 3 means "the
// runtime is fine, the kernel is not".
func (r Report) ExitCode() int {
	switch r.Verdict() {
	case StatusReady:
		return exitReady
	case StatusDegraded:
		return exitDegraded
	default:
		return exitNoRuntime
	}
}

// jsonReport is the marshalled shape. Building it explicitly (rather than
// tagging Report) is what makes the CAP-8 guarantees unconditional: verdict and
// the ready flags are computed at encode time, and the slices are replaced with
// empty ones, so even json.Marshal(Report{}) emits a complete, self-consistent
// document with [] rather than null.
type jsonReport struct {
	Verdict   Status        `json:"verdict"`
	Native    jsonNative    `json:"native"`
	Container jsonContainer `json:"container"`
	Unchecked []Unchecked   `json:"unchecked"`
}

type jsonNative struct {
	Status Status          `json:"status"`
	Ready  bool            `json:"ready"`
	LSMBPF runner.LSMState `json:"lsm_bpf"`
	Caps   []string        `json:"caps"`
	Issues []string        `json:"issues"`
}

type jsonContainer struct {
	Status Status   `json:"status"`
	Ready  bool     `json:"ready"`
	Engine *string  `json:"engine"`
	Issues []string `json:"issues"`
}

// MarshalJSON renders the document consumers parse.
func (r Report) MarshalJSON() ([]byte, error) {
	return json.Marshal(jsonReport{
		Verdict: r.Verdict(),
		Native: jsonNative{
			Status: r.Native.Status,
			Ready:  r.Native.Ready(),
			LSMBPF: r.Native.LSMBPF,
			Caps:   strings0(r.Native.Caps),
			Issues: strings0(r.Native.Issues),
		},
		Container: jsonContainer{
			Status: r.Container.Status,
			Ready:  r.Container.Ready(),
			Engine: r.Container.Engine,
			Issues: strings0(r.Container.Issues),
		},
		Unchecked: unchecked0(r.Unchecked),
	})
}

// strings0 turns a nil slice into an empty one so it marshals as [], never
// null: issue #23's contract shows arrays, and a consumer that has to handle
// both forms will eventually handle one of them wrong.
func strings0(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func unchecked0(u []Unchecked) []Unchecked {
	if u == nil {
		return []Unchecked{}
	}
	return u
}

// Text renders the human-readable default output. It mirrors the JSON exactly —
// same facts, same order — so a reader debugging by eye and a script parsing
// --json never see different stories.
func (r Report) Text() string {
	var b strings.Builder
	b.WriteString("leash doctor\n")

	fmt.Fprintf(&b, "\nnative runtime:    %s\n", statusWord(r.Native.Status))
	fmt.Fprintf(&b, "  bpf LSM:         %s\n", r.Native.LSMBPF)
	fmt.Fprintf(&b, "  capabilities:    %s\n", listOrNone(r.Native.Caps))
	writeIssues(&b, r.Native.Issues)

	engine := "none found"
	if r.Container.Engine != nil {
		engine = *r.Container.Engine
	}
	fmt.Fprintf(&b, "\ncontainer runtime: %s\n", statusWord(r.Container.Status))
	fmt.Fprintf(&b, "  engine:          %s\n", engine)
	writeIssues(&b, r.Container.Issues)

	if len(r.Unchecked) > 0 {
		b.WriteString("\nnot checked by doctor:\n")
		for _, u := range r.Unchecked {
			fmt.Fprintf(&b, "  - %s: %s\n", u.Name, u.Reason)
		}
	}

	b.WriteString("\n")
	switch r.Verdict() {
	case StatusReady:
		b.WriteString("result: this machine can enforce with at least one runtime.\n")
	case StatusDegraded:
		b.WriteString("result: DEGRADED — this machine can run workloads, but no runtime enforces Layer 1.\n        " + layer1Consequence + "\n")
	default:
		b.WriteString("result: this machine cannot enforce with ANY runtime — resolve the issues above.\n")
	}
	return b.String()
}

// writeIssues indents multi-line advice under its bullet so remedies that span
// several lines (the kernel ones do) stay visually attached to their issue.
func writeIssues(b *strings.Builder, issues []string) {
	if len(issues) == 0 {
		return
	}
	b.WriteString("  issues:\n")
	for _, issue := range issues {
		for i, line := range strings.Split(strings.TrimRight(issue, "\n"), "\n") {
			bullet := "    - "
			if i > 0 {
				bullet = "      "
			}
			b.WriteString(bullet + line + "\n")
		}
	}
}

func statusWord(s Status) string {
	switch s {
	case StatusReady:
		return "READY"
	case StatusDegraded:
		return "DEGRADED (runs, Layer 1 off)"
	default:
		return "NOT USABLE"
	}
}

func listOrNone(items []string) string {
	if len(items) == 0 {
		return "(none)"
	}
	return strings.Join(items, ", ")
}
