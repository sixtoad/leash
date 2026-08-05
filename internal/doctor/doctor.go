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

	"github.com/strongdm/leash/internal/lsm"
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

	// CapsNamespaced records that the capability set was readable but belongs
	// to a user namespace, so it says nothing about host capability. Implies
	// CapsKnown is false; kept separate only so the report can name the reason,
	// because the remedy differs (setcap cannot help inside a namespace).
	CapsNamespaced bool

	// BPFLSM and BPFLSMAdvice come from runner.ProbeBPFLSM: the tri-state
	// availability of leash's Layer 1 (eBPF LSM) on this kernel, and the
	// kernel-specific remedy when it is not available (which embeds the host's
	// actual LSM list, so it has to be probed rather than derived here).
	BPFLSM       runner.LSMState
	BPFLSMAdvice string

	// BPFLSMAttach is what the kernel said when leash's real LSM programs were
	// loaded, verified and attached (lsm.ProbeAttachable). BPFLSM above is a
	// proxy for this — a kernel can list "bpf" and still refuse the programs —
	// so an observation here supersedes the list, and only when there is one:
	// the state is unknown whenever the probe was skipped or could not reach a
	// verdict, and Detail then names which.
	BPFLSMAttach lsm.AttachProbe

	// ContainerEngine is the container CLI `leash run --runtime docker/podman`
	// would drive ("docker", "podman"), or "" when none is installed. It is not
	// necessarily the runtime a bare `leash run` selects — see DefaultRuntime.
	ContainerEngine string

	// ContainerEngineError is the daemon-reachability failure for
	// ContainerEngine, or "" when the daemon answered. Only meaningful when
	// ContainerEngine is non-empty.
	ContainerEngineError string

	// DockerHost is $DOCKER_HOST, or "" when unset. When it is set the engine
	// talks to a daemon somewhere else, so the containers it starts run on that
	// host's kernel — not the one probed into BPFLSM. The real run path already
	// refuses to draw a Layer 1 conclusion in that case
	// (runner.preflightHostKernel), and doctor must not draw one either.
	DockerHost string

	// DefaultRuntime is runner.DefaultRuntimeName(): the runtime a `leash run`
	// with neither --runtime nor LEASH_RUNTIME selects. Reported, not graded —
	// see Report.DefaultRuntime.
	DefaultRuntime string
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

// UnmarshalJSON is the exact inverse. It exists because a type with only half
// the pair is a trap: decoding a doctor document into a Report silently left
// every Status at its zero value, and the zero value is a *verdict*
// (unavailable). An unrecognised word is an error rather than a fallback, for
// the same reason — a status this build does not know is not a status it may
// quietly downgrade.
func (s *Status) UnmarshalJSON(data []byte) error {
	var word string
	if err := json.Unmarshal(data, &word); err != nil {
		return fmt.Errorf("doctor status must be a JSON string: %w", err)
	}
	switch word {
	case "ready":
		*s = StatusReady
	case "degraded":
		*s = StatusDegraded
	case "unavailable":
		*s = StatusUnavailable
	default:
		return fmt.Errorf("unknown doctor status %q (want ready, degraded or unavailable)", word)
	}
	return nil
}

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
//
// The json tags mirror the wire names even though MarshalJSON/UnmarshalJSON do
// the work: they are what keeps the mirror honest for a reader, and the
// TestJSONMirrorCoversEveryReportField guard compares them field by field.
type Report struct {
	Native    NativeReport    `json:"native"`
	Container ContainerReport `json:"container"`
	Unchecked []Unchecked     `json:"unchecked"`

	// DefaultRuntime is the runtime a bare `leash run` selects on this build
	// ("native"). It is reported rather than graded: Verdict stays "the best
	// any runtime reaches", because a machine where `--runtime docker` fully
	// enforces is not a machine that cannot enforce. But that verdict alone
	// hides that the caller must pass a flag to reach the runtime that works,
	// so the document names the default and Text() says so out loud when the
	// default is not the runtime carrying the verdict.
	DefaultRuntime string `json:"default_runtime"`
}

// NativeReport covers the container-free runtime (leashd as a host process in a
// systemd scope). lsm_bpf and caps are reported even when the runtime is not
// ready, so a provisioner can see how far the host got rather than just that it
// failed. lsm_bpf describes this host's kernel, which is also the kernel a
// local container shares.
type NativeReport struct {
	Status Status          `json:"status"`
	LSMBPF runner.LSMState `json:"lsm_bpf"`

	// LSMBPFAttachable is the observed answer to the question lsm_bpf only
	// approximates: attachable / unattachable / unknown. It is additive — the
	// list-based lsm_bpf stays, because it is the cheap signal and the --quick
	// answer — and it is "unknown" unless the kernel was actually asked.
	LSMBPFAttachable lsm.AttachState `json:"lsm_bpf_attachable"`

	Caps   []string `json:"caps"`
	Issues []string `json:"issues"`
}

// ContainerReport covers the docker/podman runtime. Engine is a pointer so an
// absent engine marshals as JSON null (per issue #23) rather than "".
type ContainerReport struct {
	Status Status   `json:"status"`
	Engine *string  `json:"engine"`
	Issues []string `json:"issues"`
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
		Native:         evaluateNative(h),
		Container:      evaluateContainer(h),
		Unchecked:      unchecked(h),
		DefaultRuntime: strings.TrimSpace(h.DefaultRuntime),
	}
}

func evaluateNative(h Host) NativeReport {
	n := NativeReport{
		LSMBPF:           h.BPFLSM,
		LSMBPFAttachable: h.BPFLSMAttach.State,
		Caps:             []string{},
		Issues:           []string{},
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
		case h.CapsNamespaced:
			n.Issues = append(n.Issues, "this process is in a user namespace, so its effective capabilities describe that namespace, not the host: CAP_BPF and CAP_NET_ADMIN are unknown and therefore treated as absent.\nCAP_BPF held in a user namespace does not permit loading leash's eBPF LSM programs, so setcap cannot help here — run doctor on the host itself.")
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
	// Everything appended so far stops the native runtime from starting at all:
	// classifyNativeRuntime refuses without Linux/systemd/root, and without
	// readable capabilities leash can attach neither the LSM (Layer 1) nor the
	// netns the proxy (Layer 2) needs. Layer 1, below, is the one axis that
	// leaves a runtime that still runs.
	blockers := len(n.Issues)

	// The LSM question only means something on Linux — elsewhere the "not
	// linux" issue above already says everything, and a kernel remedy would be
	// noise.
	layer1Down := false
	if h.GOOS == "linux" {
		var remedy string
		layer1Down, remedy = layer1Unavailable(h)
		if layer1Down {
			n.Issues = append(n.Issues, fmt.Sprintf("%s\n%s", layer1Consequence, remedy))
		}
	}

	// Native gets the same three-state treatment as the container runtime, on
	// the same axis, because the real code paths behave the same way: an
	// inactive bpf LSM is a *warning* in decideBPFLSM (only --require-lsm makes
	// it fatal) and classifyNativeRuntime never consults the LSM at all. So on
	// a Linux host with systemd, root and no Layer 1, `leash run` starts and
	// enforces proxy-only. Reporting that as "cannot enforce with ANY runtime"
	// (which is what the all-or-nothing rule did) is a false negative of
	// exactly the kind CAP-1 forbids in the other direction.
	switch {
	case blockers > 0:
		n.Status = StatusUnavailable
	case layer1Down:
		n.Status = StatusDegraded
	default:
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

	// A local Linux container shares the host kernel, so Layer 1 availability
	// here is the same fact the native path reports — an engine that runs is
	// not an engine that enforces.
	//
	// The other two branches are the cases where the kernel this probe read is
	// simply not the kernel the workload will get. Neither may reach
	// StatusReady. "Ready" is a claim that both enforcement layers work, and an
	// unprobed kernel supports no such claim: Docker Desktop's LinuxKit VM, for
	// one, does not carry bpf in its active LSM list, so darwin + a reachable
	// docker used to answer `verdict: ready, exit 0` in the very same document
	// that listed container_kernel as unchecked. Degraded is the honest floor —
	// Layer 2 (the fail-closed proxy) runs inside the container either way, so
	// the workload really is enforced to that extent; what is missing is
	// evidence for Layer 1, and unchecked() says which evidence.
	switch {
	case strings.TrimSpace(h.DockerHost) != "":
		// Mirrors runner.preflightHostKernel, which bails out on DOCKER_HOST
		// with "the kernel that matters is not this host's". Doctor had no such
		// guard, so a reachable remote daemon quietly borrowed the local
		// kernel's verdict. No remote topology is modelled here (that is an
		// explicit non-goal) — the claim is simply withheld.
		c.Status = StatusDegraded
		c.Issues = append(c.Issues, fmt.Sprintf("DOCKER_HOST is set, so %s starts containers on a remote daemon and they run on that host's kernel, not this one. doctor probed THIS host, so Layer 1 (eBPF LSM) availability where the workload will run is unverified.\nRun leash doctor on the daemon's host to get a Layer 1 verdict for it.", engine))
	case h.GOOS != "linux":
		c.Status = StatusDegraded
		c.Issues = append(c.Issues, fmt.Sprintf("%s can start containers, but on %s they run against a virtual machine's kernel that doctor did not probe, so Layer 1 (eBPF LSM) availability inside them is unverified. In particular Docker Desktop's LinuxKit kernel does not carry \"bpf\" in its active LSM list.\nRun leash doctor on a Linux host (or inside the VM) to get a Layer 1 verdict.", engine, h.GOOS))
	default:
		// A local container shares this host's kernel, so it inherits the same
		// Layer 1 answer the native runtime got — including an *observed*
		// attach failure, which is the whole point of probing: a kernel that
		// lists "bpf" but refuses leash's programs must not be reported as
		// enforcing here either.
		down, remedy := layer1Unavailable(h)
		if !down {
			c.Status = StatusReady
			break
		}
		c.Status = StatusDegraded
		c.Issues = append(c.Issues, fmt.Sprintf("%s can start containers, but they share this host's kernel: %s\n%s", engine, layer1Consequence, remedy))
	}
	return c
}

// layer1Unavailable is the single Layer 1 verdict both runtimes read, and the
// only place the observation is weighed against the guess.
//
// An observation supersedes the active-LSM list, in both directions: a kernel
// that lists "bpf" and still refuses leash's programs is not enforcing (the
// case issue #52 exists for), and a kernel that actually attached them is
// enforcing whatever the list said. An unknown observation changes nothing —
// the list stays the answer, exactly as before this probe existed.
func layer1Unavailable(h Host) (down bool, remedy string) {
	switch h.BPFLSMAttach.State {
	case lsm.AttachAttachable:
		return false, ""
	case lsm.AttachUnattachable:
		return true, attachAdvice(h)
	default:
		if h.BPFLSM == runner.LSMActive {
			return false, ""
		}
		return true, lsmAdvice(h)
	}
}

// attachAdvice renders the remedy for an observed attach failure. The stage is
// what selects it: a verifier rejection means this kernel cannot run leash's
// programs at all, while an attach rejection means the programs are fine and
// the kernel is not accepting BPF LSM attachments. Different fixes, so they are
// never collapsed into one sentence. The kernel's own text is quoted in both,
// because it is the part that actually says which helper or limit was hit.
func attachAdvice(h Host) string {
	detail := strings.TrimSpace(h.BPFLSMAttach.Detail)
	if detail == "" {
		detail = "(the kernel gave no reason)"
	}
	if h.BPFLSMAttach.Stage == lsm.AttachStageVerify {
		return fmt.Sprintf(`doctor loaded leash's own eBPF LSM programs and this kernel's verifier rejected them (observed, not inferred):
  %s
That is a kernel capability gap rather than a configuration one — typically missing BTF, no bpf_d_path helper, or a program over the verifier's instruction limit.
Boot a kernel built with CONFIG_BPF_LSM=y and CONFIG_DEBUG_INFO_BTF=y (Linux >= 5.7); the message above names what was actually missing.`, detail)
	}
	remedy := strings.TrimSpace(h.BPFLSMAdvice)
	if remedy == "" {
		// The active-LSM list said "bpf" is there and the kernel still refused,
		// so no remedy derived from that list is trustworthy here. Say so
		// rather than printing the generic "add bpf to lsm=" advice, which
		// would tell the operator to add something already present.
		remedy = `"bpf" IS in the active LSM list (/sys/kernel/security/lsm), so the list is not the whole story on this kernel and the message above is the authoritative reason.`
	}
	return fmt.Sprintf(`doctor loaded leash's own eBPF LSM programs — they verified, and this kernel refused to attach them (observed, not inferred):
  %s
%s`, detail, remedy)
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
	out := []Unchecked{}
	// Attachability leaves this list only when the kernel was actually asked
	// and answered. Anything else — skipped, not privileged enough, timed out —
	// is still an unverified prerequisite, and the entry names which. It stays
	// first, where it has always been.
	if h.BPFLSMAttach.State == lsm.AttachUnknown {
		out = append(out, Unchecked{
			Name:   "bpf_lsm_attachable",
			Reason: attachUncheckedReason(h),
		})
	}
	out = append(out, alwaysUnchecked...)
	if !h.CapsKnown {
		out = append(out, Unchecked{
			Name:   "capabilities",
			Reason: capsUncheckedReason(h),
		})
	}
	// container_kernel is declared once, for whichever reason applies: the
	// remote daemon is named first because it holds even on Linux, where the
	// platform reason would not have fired at all.
	switch {
	case strings.TrimSpace(h.DockerHost) != "":
		out = append(out, Unchecked{
			Name:   "container_kernel",
			Reason: "DOCKER_HOST is set, so containers run on a remote daemon's kernel; doctor probed this host's kernel, which is not the one that will run the workload. (The value is not echoed here: it can carry a user@host.)",
		})
	case h.GOOS != "linux":
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
	Verdict        Status        `json:"verdict"`
	Native         jsonNative    `json:"native"`
	Container      jsonContainer `json:"container"`
	Unchecked      []Unchecked   `json:"unchecked"`
	DefaultRuntime string        `json:"default_runtime"`
}

type jsonNative struct {
	Status           Status          `json:"status"`
	Ready            bool            `json:"ready"`
	LSMBPF           runner.LSMState `json:"lsm_bpf"`
	LSMBPFAttachable lsm.AttachState `json:"lsm_bpf_attachable"`
	Caps             []string        `json:"caps"`
	Issues           []string        `json:"issues"`
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
			Status:           r.Native.Status,
			Ready:            r.Native.Ready(),
			LSMBPF:           r.Native.LSMBPF,
			LSMBPFAttachable: r.Native.LSMBPFAttachable,
			Caps:             strings0(r.Native.Caps),
			Issues:           strings0(r.Native.Issues),
		},
		Container: jsonContainer{
			Status: r.Container.Status,
			Ready:  r.Container.Ready(),
			Engine: r.Container.Engine,
			Issues: strings0(r.Container.Issues),
		},
		Unchecked:      unchecked0(r.Unchecked),
		DefaultRuntime: r.DefaultRuntime,
	})
}

// UnmarshalJSON decodes a document this package produced back into a Report.
//
// It exists because a marshal-only type is worse than no type at all for the Go
// consumer this document is aimed at. json.Unmarshal into a Report used to fail
// outright (the fields carried no tags and the mirror is unexported), and a
// caller that ignored the error was left holding a zero Report — whose zero
// values spell `verdict: unavailable, ready: false` even when the document it
// came from said ready. A fabricated verdict is the one failure mode this
// command exists to prevent, so the pair is closed.
//
// The derived fields in the document (verdict, the two ready flags) are not
// stored back: they are recomputed by Verdict()/Ready() from the statuses, so a
// tampered or stale document cannot smuggle in a verdict its own statuses do
// not support. Round-tripping is therefore identity for any Report this package
// builds.
func (r *Report) UnmarshalJSON(data []byte) error {
	var doc jsonReport
	if err := json.Unmarshal(data, &doc); err != nil {
		return err
	}
	*r = Report{
		Native: NativeReport{
			Status:           doc.Native.Status,
			LSMBPF:           doc.Native.LSMBPF,
			LSMBPFAttachable: doc.Native.LSMBPFAttachable,
			Caps:             strings0(doc.Native.Caps),
			Issues:           strings0(doc.Native.Issues),
		},
		Container: ContainerReport{
			Status: doc.Container.Status,
			Engine: doc.Container.Engine,
			Issues: strings0(doc.Container.Issues),
		},
		Unchecked:      unchecked0(doc.Unchecked),
		DefaultRuntime: doc.DefaultRuntime,
	}
	return nil
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
	fmt.Fprintf(&b, "  attachable:      %s\n", r.Native.LSMBPFAttachable)
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
	if note := r.defaultRuntimeNote(); note != "" {
		b.WriteString(note)
	}
	return b.String()
}

// defaultRuntimeNote spells out the gap between the verdict and what a caller
// gets by default. Verdict is the best any runtime reaches, which is the right
// answer to "can this machine enforce" — but `leash run` with no --runtime
// picks exactly one runtime and never falls back, so on a host where only the
// *other* runtime works, a bare `leash run` fails on a machine doctor called
// ready. Naming the default (rather than folding it into the verdict) keeps
// doctor's per-runtime report intact and still leaves nothing for the reader to
// infer.
func (r Report) defaultRuntimeNote() string {
	name := strings.TrimSpace(r.DefaultRuntime)
	if name == "" {
		return ""
	}
	status, known := r.statusOf(name)
	if !known {
		return fmt.Sprintf("        `leash run` with no --runtime uses %q, which doctor does not grade.\n", name)
	}
	if status == r.Verdict() {
		return fmt.Sprintf("        `leash run` with no --runtime uses the %s runtime (%s above).\n", name, statusShort(status))
	}
	return fmt.Sprintf("        NOTE: `leash run` with no --runtime uses the %s runtime, which is %s here — leash never falls back on its own.\n        Pass --runtime (or set LEASH_RUNTIME) to reach the runtime this verdict is about.\n", name, statusShort(status))
}

// statusOf maps a runtime name to the section of the report that grades it.
// known is false for a runtime doctor has no section for, which is honest
// rather than silent: this build's default is per-OS and only the Linux native
// backend is wired.
func (r Report) statusOf(name string) (s Status, known bool) {
	switch name {
	case "native":
		return r.Native.Status, true
	case "docker", "podman":
		return r.Container.Status, true
	default:
		return StatusUnavailable, false
	}
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
	if s == StatusDegraded {
		// The section header is the one place with room to say what the state
		// costs, and "degraded" alone has been read as "slightly worse".
		return "DEGRADED (runs, Layer 1 off)"
	}
	return statusShort(s)
}

// statusShort is the same word without the gloss, for the places that refer
// back to a section rather than heading one.
func statusShort(s Status) string {
	switch s {
	case StatusReady:
		return "READY"
	case StatusDegraded:
		return "DEGRADED"
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

// capsUncheckedReason names why the capability set was not established, so a
// consumer can tell "masked /proc" from "namespaced and therefore meaningless".
func capsUncheckedReason(h Host) string {
	if h.CapsNamespaced {
		return "this process is in a user namespace, so /proc/self/status reports namespaced capabilities that do not permit loading BPF-LSM programs; CAP_BPF/CAP_NET_ADMIN were not established for the host (reported as absent, never assumed)."
	}
	return "/proc/self/status could not be read or parsed, so CAP_BPF/CAP_NET_ADMIN were not observed (reported as absent, never assumed)."
}

// attachUncheckedReason explains why attachability is still a guess on this
// run. The base sentence is the one doctor has always printed — the active-LSM
// list is a proxy, and an active-but-unattachable BPF LSM would read as active —
// followed by the specific reason the probe did not settle it.
func attachUncheckedReason(h Host) string {
	const base = "doctor fell back to the active LSM list (/sys/kernel/security/lsm), which is a proxy: an active-but-unattachable BPF LSM still reads as active (leash issue #52)."
	reason := strings.TrimSpace(h.BPFLSMAttach.Detail)
	if reason == "" {
		reason = "the attachability probe did not reach a verdict"
	}
	return base + " " + strings.TrimRight(reason, ".") + "."
}
