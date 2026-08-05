package doctor

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/strongdm/leash/internal/lsm"
	"github.com/strongdm/leash/internal/runner"
)

// No t.Parallel() in this file: the tests at the bottom run the real probe
// against the real machine.

// verifierRejected and attachRefused are the two shapes of an observed "no",
// which exist separately because their remedies do.
func verifierRejected(detail string) lsm.AttachProbe {
	return lsm.AttachProbe{State: lsm.AttachUnattachable, Stage: lsm.AttachStageVerify, Detail: detail}
}

func attachRefused(detail string) lsm.AttachProbe {
	return lsm.AttachProbe{State: lsm.AttachUnattachable, Stage: lsm.AttachStageAttach, Detail: detail}
}

// CAP-1 and the spec's success signal: the host issue #52 was filed about is a
// host whose active-LSM list says "bpf" and whose kernel still refuses leash's
// programs. Before the probe it read as ready; it must now read as degraded,
// with the kernel's own reason in the report.
func TestObservedRejectionOverridesAnActiveLSMList(t *testing.T) {
	const kernelSaid = "program lsm_open: load program: BPF program is too large: processed 1000001 insns"

	h := readyHost()
	h.BPFLSM = runner.LSMActive
	h.BPFLSMAttach = verifierRejected(kernelSaid)

	got := Evaluate(h)
	if got.Native.Ready() {
		t.Error("a kernel that refuses leash's programs is not ready, whatever the LSM list says")
	}
	if got.Native.Status != StatusDegraded {
		t.Errorf("native status = %v, want degraded (the runtime still runs proxy-only)", got.Native.Status)
	}
	if got.Container.Status != StatusDegraded {
		t.Errorf("container status = %v, want degraded: a local container shares this kernel", got.Container.Status)
	}
	if got.Verdict() != StatusDegraded {
		t.Errorf("verdict = %v, want degraded", got.Verdict())
	}

	joined := strings.Join(got.Native.Issues, "\n")
	if !strings.Contains(joined, kernelSaid) {
		t.Errorf("the kernel's reason is the actionable part and must be preserved verbatim:\n%s", joined)
	}
}

// CAP-3: the two rejections are told apart, because "this kernel cannot run
// leash's programs" and "this kernel will not accept BPF LSM attachments" have
// nothing to do with each other.
func TestVerifierRejectionAndAttachRejectionCarryDifferentRemedies(t *testing.T) {
	verify := readyHost()
	verify.BPFLSMAttach = verifierRejected("no BTF found for kernel version")
	verifyAdvice := strings.Join(Evaluate(verify).Native.Issues, "\n")

	attach := readyHost()
	attach.BPFLSMAttach = attachRefused("attach lsm: invalid argument")
	attachAdvice := strings.Join(Evaluate(attach).Native.Issues, "\n")

	if verifyAdvice == attachAdvice {
		t.Fatal("a verifier rejection and an attach rejection produced the same advice; the remedies differ")
	}
	if !strings.Contains(verifyAdvice, "verifier rejected") {
		t.Errorf("a verifier rejection must say the verifier rejected the programs:\n%s", verifyAdvice)
	}
	if !strings.Contains(verifyAdvice, "CONFIG_DEBUG_INFO_BTF") {
		t.Errorf("a verifier rejection points at the kernel build:\n%s", verifyAdvice)
	}
	if !strings.Contains(attachAdvice, "they verified") {
		t.Errorf("an attach rejection must say the programs themselves were fine:\n%s", attachAdvice)
	}
}

// An attach refused on a host whose list *does* contain bpf must not print the
// stock "add bpf to lsm=" remedy: it is already there, and telling the operator
// to add it again sends them to edit a boot line for nothing.
func TestAttachRefusedWithBPFListedDoesNotAdviseAddingBPF(t *testing.T) {
	h := readyHost()
	h.BPFLSM = runner.LSMActive
	h.BPFLSMAdvice = "" // an active list carries no remedy
	h.BPFLSMAttach = attachRefused("attach lsm: operation not supported")

	joined := strings.Join(Evaluate(h).Native.Issues, "\n")
	if strings.Contains(joined, "lsm=") {
		t.Errorf("bpf is already in the list; this advice tells the operator to add it again:\n%s", joined)
	}
	if !strings.Contains(joined, "IS in the active LSM list") {
		t.Errorf("say that the list and the kernel disagree, and which one to believe:\n%s", joined)
	}
}

// The other direction of "supersedes when observed": programs that actually
// loaded and attached are Layer 1 working, even if the list read did not say so.
func TestObservedAttachOverridesTheListReading(t *testing.T) {
	h := readyHost()
	h.BPFLSM = runner.LSMUnknown
	h.BPFLSMAdvice = "the active LSM list could not be read"
	h.BPFLSMAttach = lsm.AttachProbe{State: lsm.AttachAttachable}

	got := Evaluate(h)
	if !got.Native.Ready() {
		t.Errorf("leash's programs attached on this kernel; that is Layer 1 working: %v", got.Native.Issues)
	}
	if hasUnchecked(got.Unchecked, "bpf_lsm_attachable") {
		t.Error("attachability was observed, so it must leave the unchecked list")
	}
}

// CAP-2/CAP-4: unknown changes nothing. The list stays the answer and the
// prerequisite stays declared — an unprivileged run must not be able to move
// the verdict in either direction.
func TestUnknownAttachabilityFallsBackToTheList(t *testing.T) {
	cases := []struct {
		name      string
		state     runner.LSMState
		wantReady bool
	}{
		{"active list, probe could not run", runner.LSMActive, true},
		{"inactive list, probe could not run", runner.LSMInactive, false},
		{"unreadable list, probe could not run", runner.LSMUnknown, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := readyHost()
			h.BPFLSM = c.state
			if c.state != runner.LSMActive {
				h.BPFLSMAdvice = "add bpf to the lsm= boot parameter"
			}
			h.BPFLSMAttach = lsm.SkippedAttachProbe("this process is not privileged enough")

			got := Evaluate(h)
			if got.Native.Ready() != c.wantReady {
				t.Errorf("native ready = %v, want %v (unknown attachability must not shift the verdict)", got.Native.Ready(), c.wantReady)
			}
			if got.Native.LSMBPFAttachable != lsm.AttachUnknown {
				t.Errorf("attachable = %v, want unknown", got.Native.LSMBPFAttachable)
			}
			if !hasUnchecked(got.Unchecked, "bpf_lsm_attachable") {
				t.Error("an unknown attachability is still an unverified prerequisite and must stay declared")
			}
		})
	}
}

// CAP-4: when it stays unchecked, the entry names WHY — the two reasons call
// for different responses (pass no --quick; re-run with privilege).
func TestUncheckedAttachabilityNamesItsReason(t *testing.T) {
	cases := []struct {
		name  string
		probe lsm.AttachProbe
		want  string
	}{
		{"quick", lsm.SkippedAttachProbe("--quick was passed, so doctor did not load and attach a probe program"), "--quick"},
		{"privilege", lsm.SkippedAttachProbe("this process is not privileged enough to load a BPF LSM program (needs root, or CAP_BPF)"), "CAP_BPF"},
		{"timeout", lsm.AttachProbe{State: lsm.AttachUnknown, Detail: "the attachability probe did not finish within 10s"}, "did not finish"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := readyHost()
			h.BPFLSMAttach = c.probe

			var reason string
			for _, u := range Evaluate(h).Unchecked {
				if u.Name == "bpf_lsm_attachable" {
					reason = u.Reason
				}
			}
			if reason == "" {
				t.Fatal("bpf_lsm_attachable must be declared unchecked")
			}
			if !strings.Contains(reason, c.want) {
				t.Errorf("the reason must name %q, got %q", c.want, reason)
			}
		})
	}
}

// The new signal is additive: lsm_bpf keeps its meaning and its name, and the
// observation arrives beside it under a new key.
func TestAttachabilityAppearsInTheDocumentAndTheText(t *testing.T) {
	h := readyHost()
	h.BPFLSMAttach = lsm.AttachProbe{State: lsm.AttachAttachable}
	got := Evaluate(h)

	out, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(out), `"lsm_bpf_attachable":"attachable"`) {
		t.Errorf("the document must carry the observation: %s", out)
	}
	if !strings.Contains(string(out), `"lsm_bpf":"active"`) {
		t.Errorf("the list-based signal stays exactly as it shipped: %s", out)
	}
	if !strings.Contains(got.Text(), "attachable:      attachable") {
		t.Errorf("the human output mirrors the document:\n%s", got.Text())
	}

	// The pair has to stay closed, or a Go consumer decoding the document gets
	// the zero value — which claims nothing was observed.
	var back Report
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Native.LSMBPFAttachable != lsm.AttachAttachable {
		t.Errorf("round trip lost the observation: got %v", back.Native.LSMBPFAttachable)
	}
}

// CAP-4 on the real machine: --quick skips the probe, and says so.
func TestQuickSkipsTheProbe(t *testing.T) {
	h := ProbeWithOptions(ProbeOptions{Quick: true})

	if h.BPFLSMAttach.State != lsm.AttachUnknown {
		t.Errorf("--quick must not produce an observation, got %v", h.BPFLSMAttach.State)
	}
	if h.BPFLSMAttach.Stage != lsm.AttachStageSkipped {
		t.Errorf("--quick skips rather than fails, got stage %q", h.BPFLSMAttach.Stage)
	}
	if !strings.Contains(h.BPFLSMAttach.Detail, "--quick") {
		t.Errorf("the reason must name the flag, got %q", h.BPFLSMAttach.Detail)
	}
	if !hasUnchecked(Evaluate(h).Unchecked, "bpf_lsm_attachable") {
		t.Error("a skipped probe leaves the prerequisite unchecked")
	}
}

// CAP-4 on the real machine: the default is the probe, gated only on being able
// to run it at all. Whatever this host is, the result must be self-consistent —
// and an unprivileged host must land on unknown rather than on a verdict.
func TestDefaultProbeIsSelfConsistent(t *testing.T) {
	h := Probe()

	if h.BPFLSMAttach.State == lsm.AttachUnknown && strings.TrimSpace(h.BPFLSMAttach.Detail) == "" {
		t.Error("an unknown attachability must say why")
	}
	if !privilegedEnoughToProbe(h.CapBPF, h.CapsKnown) && h.BPFLSMAttach.State != lsm.AttachUnknown {
		t.Errorf("a process that cannot load BPF programs cannot have observed anything, got %v", h.BPFLSMAttach.State)
	}

	report := Evaluate(h)
	if report.Native.LSMBPFAttachable != h.BPFLSMAttach.State {
		t.Errorf("the report says %v where the probe said %v", report.Native.LSMBPFAttachable, h.BPFLSMAttach.State)
	}
	observed := h.BPFLSMAttach.State != lsm.AttachUnknown
	if observed == hasUnchecked(report.Unchecked, "bpf_lsm_attachable") {
		t.Errorf("bpf_lsm_attachable must be unchecked exactly when nothing was observed (state %v)", h.BPFLSMAttach.State)
	}
	t.Logf("this host: attachable=%s stage=%q detail=%q", h.BPFLSMAttach.State, h.BPFLSMAttach.Stage, h.BPFLSMAttach.Detail)
}
