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
	CapBPF      bool
	CapNetAdmin bool

	// BPFLSMActive and BPFLSMAdvice come from runner.ProbeBPFLSM: whether an
	// eBPF LSM program can attach at all, and the kernel-specific remedy when
	// it cannot (which embeds the host's actual LSM list, so it has to be
	// probed rather than derived here).
	BPFLSMActive bool
	BPFLSMAdvice string

	// ContainerEngine is the container CLI found on PATH ("docker", "podman"),
	// or "" when none is installed.
	ContainerEngine string
}

// Report is the `leash doctor --json` document. The field names and the
// null-when-absent engine are the contract consumers parse, so treat them as
// API: additive changes only.
type Report struct {
	Native    NativeReport    `json:"native"`
	Container ContainerReport `json:"container"`
}

// NativeReport covers the container-free runtime (leashd as a host process in a
// systemd scope). lsm_bpf and caps are reported even when ready is false, so a
// provisioner can see how far the host got rather than just that it failed.
type NativeReport struct {
	Ready  bool     `json:"ready"`
	LSMBPF bool     `json:"lsm_bpf"`
	Caps   []string `json:"caps"`
	Issues []string `json:"issues"`
}

// ContainerReport covers the docker/podman runtime. Engine is a pointer so an
// absent engine marshals as JSON null (per issue #23) rather than "".
type ContainerReport struct {
	Ready  bool     `json:"ready"`
	Engine *string  `json:"engine"`
	Issues []string `json:"issues"`
}

// Capability names as they appear in the JSON "caps" array — lowercase, without
// the CAP_ prefix, matching the shape in issue #23.
const (
	capNameBPF      = "bpf"
	capNameNetAdmin = "net_admin"
)

// Fallback for the (unlikely) case where the LSM probe reports inactive without
// producing advice; an issue with no remedy would be worse than a generic one.
const genericLSMAdvice = `the eBPF LSM (Layer 1) is not active on this kernel: "bpf" must be in the active LSM list (/sys/kernel/security/lsm).
Add bpf to the lsm= kernel boot parameter and reboot, on a kernel built with CONFIG_BPF_LSM=y (Linux >= 5.7).`

// Evaluate is the whole decision. Pure by construction: every input arrives in
// Host, and the runner helpers it calls are themselves pure classifiers.
func Evaluate(h Host) Report {
	return Report{
		Native:    evaluateNative(h),
		Container: evaluateContainer(h),
	}
}

func evaluateNative(h Host) NativeReport {
	n := NativeReport{
		LSMBPF: h.BPFLSMActive,
		Caps:   []string{},
		Issues: []string{},
	}
	if h.CapBPF {
		n.Caps = append(n.Caps, capNameBPF)
	}
	if h.CapNetAdmin {
		n.Caps = append(n.Caps, capNameNetAdmin)
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
		if !h.CapBPF {
			n.Issues = append(n.Issues, "missing CAP_BPF: leash cannot load or attach its eBPF LSM programs.\nRun as root, or grant the leash binary cap_bpf (setcap cap_bpf,cap_net_admin+ep).")
		}
		if !h.CapNetAdmin {
			n.Issues = append(n.Issues, "missing CAP_NET_ADMIN: leash cannot create the workload's network namespace, so egress cannot be forced through the fail-closed proxy.\nRun as root, or grant the leash binary cap_net_admin (setcap cap_bpf,cap_net_admin+ep).")
		}
	}
	// The LSM question only means something on Linux — elsewhere the "not
	// linux" issue above already says everything, and a kernel remedy would be
	// noise.
	if h.GOOS == "linux" && !h.BPFLSMActive {
		advice := strings.TrimSpace(h.BPFLSMAdvice)
		if advice == "" {
			advice = genericLSMAdvice
		}
		n.Issues = append(n.Issues, advice)
	}

	n.Ready = len(n.Issues) == 0
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
	c.Ready = true
	return c
}

// Usable reports whether at least one runtime can enforce. It is the exit-code
// predicate: a machine with neither is not a leash node, which is the signal a
// provisioner scripts against.
func (r Report) Usable() bool { return r.Native.Ready || r.Container.Ready }

// ExitCode is 0 while any runtime can enforce, 1 when none can.
func (r Report) ExitCode() int {
	if r.Usable() {
		return exitUsable
	}
	return exitNoRuntime
}

// Text renders the human-readable default output. It mirrors the JSON exactly —
// same facts, same order — so a reader debugging by eye and a script parsing
// --json never see different stories.
func (r Report) Text() string {
	var b strings.Builder
	b.WriteString("leash doctor\n")

	fmt.Fprintf(&b, "\nnative runtime:    %s\n", readyWord(r.Native.Ready))
	fmt.Fprintf(&b, "  bpf LSM active:  %s\n", yesNo(r.Native.LSMBPF))
	fmt.Fprintf(&b, "  capabilities:    %s\n", listOrNone(r.Native.Caps))
	writeIssues(&b, r.Native.Issues)

	engine := "none found"
	if r.Container.Engine != nil {
		engine = *r.Container.Engine
	}
	fmt.Fprintf(&b, "\ncontainer runtime: %s\n", readyWord(r.Container.Ready))
	fmt.Fprintf(&b, "  engine:          %s\n", engine)
	writeIssues(&b, r.Container.Issues)

	b.WriteString("\n")
	if r.Usable() {
		b.WriteString("result: this machine can enforce with at least one runtime.\n")
	} else {
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

func readyWord(ready bool) string {
	if ready {
		return "READY"
	}
	return "NOT READY"
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func listOrNone(items []string) string {
	if len(items) == 0 {
		return "(none)"
	}
	return strings.Join(items, ", ")
}
