package lsm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// An attach that succeeds on a kernel where "bpf" is absent from the active LSM
// stack enforces nothing — the hook is never invoked. Reporting that as
// "attachable" is the false assurance behind leash issue #56, observed on a real
// PVE 9.1.8 node whose probe attached cleanly with enforcement impossible.

func withActiveLSM(t *testing.T, content string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "lsm")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	old := activeLSMPath
	activeLSMPath = p
	t.Cleanup(func() { activeLSMPath = old })
}

func TestBPFInActiveLSMStack(t *testing.T) {
	tests := []struct {
		name          string
		content       string
		active, known bool
	}{
		{"bpf present", "lockdown,capability,yama,apparmor,bpf,ima,evm\n", true, true},
		{"bpf absent (PVE)", "lockdown,capability,yama,apparmor,ima,evm\n", false, true},
		{"bpf only", "bpf", true, true},
		{"empty", "", false, true},
		{"whitespace padded", " lockdown , bpf , yama \n", true, true},
		{"substring must not match", "lockdown,bpfx,yama", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withActiveLSM(t, tt.content)
			active, known := bpfInActiveLSMStack()
			if active != tt.active || known != tt.known {
				t.Fatalf("bpfInActiveLSMStack() = (%v,%v), want (%v,%v)", active, known, tt.active, tt.known)
			}
		})
	}
}

func TestUnreadableLSMListLeavesTheVerdictAlone(t *testing.T) {
	old := activeLSMPath
	activeLSMPath = filepath.Join(t.TempDir(), "missing")
	t.Cleanup(func() { activeLSMPath = old })
	if _, known := bpfInActiveLSMStack(); known {
		t.Fatal("an unreadable list must report known=false so the attach verdict is never downgraded on a guess")
	}
}

func TestAttachInertWireForm(t *testing.T) {
	if got := AttachInert.String(); got != "inert" {
		t.Fatalf("AttachInert.String() = %q, want %q", got, "inert")
	}
	b, err := json.Marshal(AttachInert)
	if err != nil || string(b) != `"inert"` {
		t.Fatalf("marshal = %s (err %v), want \"inert\"", b, err)
	}
	var back AttachState
	if err := json.Unmarshal([]byte(`"inert"`), &back); err != nil || back != AttachInert {
		t.Fatalf("round-trip = %v (err %v), want AttachInert", back, err)
	}
	// A state this build does not know must error, never silently decode to a verdict.
	if err := json.Unmarshal([]byte(`"attachable_but_inert"`), &back); err == nil {
		t.Fatal("an unrecognised state must be rejected, not defaulted")
	}
}

func TestInertIsDistinctFromBothVerdicts(t *testing.T) {
	if AttachInert == AttachAttachable || AttachInert == AttachUnattachable || AttachInert == AttachUnknown {
		t.Fatal("AttachInert must be its own state: the kernel accepted the attach (not unattachable) but nothing enforces (not attachable)")
	}
}
