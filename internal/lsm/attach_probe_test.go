package lsm

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// No t.Parallel() anywhere in this file: these tests run the real probe against
// the real kernel and count this process's file descriptors, which is process
// state by definition.

// CAP-2: the wire words are the contract `leash doctor --json` publishes, and
// the zero value has to be the one that claims nothing.
func TestAttachStateWireForm(t *testing.T) {
	var zero AttachState
	if zero != AttachUnknown {
		t.Errorf("the zero AttachState is %v; it must be unknown so an unfilled value cannot claim an observation", zero)
	}

	for state, want := range map[AttachState]string{
		AttachUnknown:      "unknown",
		AttachUnattachable: "unattachable",
		AttachAttachable:   "attachable",
	} {
		if got := state.String(); got != want {
			t.Errorf("String() = %q, want %q", got, want)
		}
		encoded, err := json.Marshal(state)
		if err != nil {
			t.Fatalf("marshal %v: %v", state, err)
		}
		if got, wantJSON := string(encoded), `"`+want+`"`; got != wantJSON {
			t.Errorf("marshal %v = %s, want %s", state, got, wantJSON)
		}
		var back AttachState
		if err := json.Unmarshal(encoded, &back); err != nil {
			t.Fatalf("unmarshal %s: %v", encoded, err)
		}
		if back != state {
			t.Errorf("round trip of %v gave %v", state, back)
		}
	}
}

// A state this build does not know is not one it may quietly reinterpret as
// unknown — that would be a fabricated verdict in the payload.
func TestAttachStateRejectsUnknownWords(t *testing.T) {
	for _, doc := range []string{`"maybe"`, `7`, `null`} {
		var s AttachState
		if err := json.Unmarshal([]byte(doc), &s); err == nil {
			t.Errorf("decoding %s should fail rather than yield %v", doc, s)
		}
	}
}

// CAP-2: EPERM/EACCES says something about this process, not about the kernel,
// so it must never reach a verdict of unattachable.
func TestPermissionErrorsAreNotVerdicts(t *testing.T) {
	permission := []error{
		syscall.EPERM,
		syscall.EACCES,
		os.ErrPermission,
		fmt.Errorf("create map: %w", syscall.EPERM),
		fmt.Errorf("load program: %w", syscall.EACCES),
		&os.PathError{Op: "open", Path: "/sys/fs/bpf", Err: syscall.EACCES},
		// A library that renders the errno into its text without wrapping it.
		errors.New("map create: operation not permitted"),
		errors.New("bpf syscall: Permission denied"),
	}
	for _, err := range permission {
		if !isProbePermissionError(err) {
			t.Errorf("%v must be classified as a privilege problem (unknown), not as an unattachable kernel", err)
		}
	}

	verdicts := []error{
		nil,
		errors.New("program lsm_open: load program: invalid argument: last insn is not an exit or jmp"),
		errors.New("program lsm_link: BPF program is too large: processed 1000001 insns"),
		fmt.Errorf("attach lsm: %w", syscall.EINVAL),
		errors.New("no BTF found for kernel version"),
	}
	for _, err := range verdicts {
		if isProbePermissionError(err) {
			t.Errorf("%v is the kernel judging leash's programs; it must not be excused as a privilege problem", err)
		}
	}
}

// CAP-6: a probe that hangs degrades to unknown and lets doctor finish. It must
// not be an error, and it must not be a verdict.
func TestProbeThatHangsDegradesToUnknown(t *testing.T) {
	blocked := make(chan struct{})
	t.Cleanup(func() { close(blocked) })

	got := probeAttachableWithin(10*time.Millisecond, func() AttachProbe {
		<-blocked
		return AttachProbe{State: AttachAttachable}
	})

	if got.State != AttachUnknown {
		t.Fatalf("a probe that never returns must be unknown, got %v", got.State)
	}
	if !strings.Contains(got.Detail, "did not finish") {
		t.Errorf("the timeout must say so: %q", got.Detail)
	}
}

// CAP-6: a panic anywhere in the probe is contained and reported as unknown —
// a readiness command must still produce a report.
func TestProbeThatPanicsDegradesToUnknown(t *testing.T) {
	got := probeAttachableWithin(time.Minute, func() AttachProbe {
		panic("verifier log parser exploded")
	})

	if got.State != AttachUnknown {
		t.Fatalf("a panicking probe must be unknown, got %v", got.State)
	}
	if !strings.Contains(got.Detail, "verifier log parser exploded") {
		t.Errorf("the contained panic must be named: %q", got.Detail)
	}
}

// SkippedAttachProbe is the shape a caller that never ran the probe reports, so
// the reason survives into the report's `unchecked` entry.
func TestSkippedProbeIsUnknownWithItsReason(t *testing.T) {
	got := SkippedAttachProbe("--quick was passed")
	if got.State != AttachUnknown {
		t.Errorf("a skipped probe is unknown, got %v", got.State)
	}
	if got.Stage != AttachStageSkipped {
		t.Errorf("a skipped probe is staged %q, got %q", AttachStageSkipped, got.Stage)
	}
	if got.Detail != "--quick was passed" {
		t.Errorf("the reason must survive verbatim, got %q", got.Detail)
	}
}

// The real probe against the real kernel. What it answers depends on the host,
// so this pins the invariants that must hold on every host instead: it always
// terminates, it always returns one of the three states, and it never claims a
// verdict without saying why.
func TestProbeAttachableIsSelfConsistent(t *testing.T) {
	got := ProbeAttachable()

	switch got.State {
	case AttachAttachable:
		if got.Detail != "" {
			t.Errorf("a successful attach carries no failure detail, got %q", got.Detail)
		}
	case AttachUnattachable:
		if strings.TrimSpace(got.Detail) == "" {
			t.Error("an unattachable verdict must preserve the kernel's reason; it is the actionable part")
		}
		if got.Stage != AttachStageVerify && got.Stage != AttachStageAttach {
			t.Errorf("an unattachable verdict comes from verify or attach, got stage %q", got.Stage)
		}
	case AttachUnknown:
		if strings.TrimSpace(got.Detail) == "" {
			t.Error("an unknown result must say why no verdict was reached")
		}
	default:
		t.Fatalf("unexpected state %v", got.State)
	}
	t.Logf("probe on this host: state=%s stage=%q detail=%q", got.State, got.Stage, got.Detail)
}

// CAP-5: a readiness command does not leak kernel objects. Every collection,
// link and descriptor the probe opens must be released on the path this host
// actually takes — whichever that is — so running it repeatedly cannot grow the
// process's descriptor table.
func TestProbeLeaksNoFileDescriptors(t *testing.T) {
	// One warm-up first: the ebpf library and the Go runtime open things once
	// (BTF handles, the netpoller) that are not per-probe and would otherwise
	// be counted as growth.
	ProbeAttachable()

	before, err := openFDCount()
	if err != nil {
		t.Skipf("cannot count this process's descriptors: %v", err)
	}

	const iterations = 25
	for i := 0; i < iterations; i++ {
		ProbeAttachable()
	}

	after, err := openFDCount()
	if err != nil {
		t.Fatalf("cannot count this process's descriptors: %v", err)
	}
	if after > before {
		t.Errorf("descriptor count grew from %d to %d over %d probes: the probe is leaking (+%d)",
			before, after, iterations, after-before)
	}
	t.Logf("descriptors: %d before, %d after %d probes", before, after, iterations)
}

// openFDCount reports how many descriptors this process holds. /proc/self/fd is
// Linux-only; elsewhere the test that uses it skips, because a non-Linux probe
// opens nothing to leak in the first place.
func openFDCount() (int, error) {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return 0, err
	}
	// The directory handle opened to read this is itself in the listing, and it
	// is closed on return — counted identically in both snapshots, so it
	// cancels out.
	return len(entries), nil
}
