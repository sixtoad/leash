package enforcement

import (
	"errors"
	"strings"
	"testing"
)

// Only "lsm" releases a workload: Layer 1 unavailable is refused whether or
// not the L7 proxy is up.
func TestStatusCheck(t *testing.T) {
	if err := Describe(true, true).Check(); err != nil {
		t.Fatalf("lsm must pass: %v", err)
	}
	if err := Describe(true, false).Check(); err != nil {
		t.Fatalf("lsm with the proxy off (--lsm-only) must pass: %v", err)
	}
	if err := Describe(false, true).Check(); err == nil {
		t.Fatal("Layer 1 unavailable with the proxy up must be refused")
	}
	if err := Describe(false, false).Check(); err == nil {
		t.Fatal("Layer 1 unavailable with the proxy off must be refused")
	}
	if err := (Status{Enforcement: "proxy-only", Layer1: LayerUnavailable, Layer2: LayerActive}).Check(); err == nil {
		t.Fatal("a proxy-only marker from an older leashd must be refused")
	}
}

func TestDescribe(t *testing.T) {
	cases := []struct {
		l1, l2 bool
		want   Status
	}{
		{true, true, Status{LevelLSM, LayerActive, LayerActive, true, "", ""}},
		{true, false, Status{LevelLSM, LayerActive, LayerDisabled, true, "", ""}},
		{false, true, Status{LevelNone, LayerUnavailable, LayerActive, true, "", ""}},
		{false, false, Status{LevelNone, LayerUnavailable, LayerDisabled, true, "", ""}},
	}
	for _, tc := range cases {
		got := Describe(tc.l1, tc.l2)
		if got != tc.want {
			t.Errorf("Describe(%v,%v) = %+v, want %+v", tc.l1, tc.l2, got, tc.want)
		}
		if got.Enforcement == "proxy-only" {
			t.Errorf("Describe(%v,%v) produced proxy-only", tc.l1, tc.l2)
		}
	}
}

func TestClassifyLSMList(t *testing.T) {
	cases := []struct {
		name string
		data string
		err  error
		want LSMListState
	}{
		{"bpf active", "lockdown,capability,landlock,yama,apparmor,bpf\n", nil, LSMListActive},
		// Ubuntu 24.04 default: CONFIG_BPF_LSM=y but bpf not active.
		{"bpf compiled but inactive", "lockdown,capability,landlock,yama,apparmor\n", nil, LSMListInactive},
		{"bpf-like name is not bpf", "bpfx,apparmor", nil, LSMListInactive},
		{"empty list", "  \n", nil, LSMListUnknown},
		{"unreadable", "", errors.New("permission denied"), LSMListUnknown},
	}
	for _, tc := range cases {
		got, reason := ClassifyLSMList([]byte(tc.data), tc.err)
		if got != tc.want {
			t.Errorf("%s: state = %v, want %v", tc.name, got, tc.want)
		}
		if (got == LSMListActive) != (reason == "") {
			t.Errorf("%s: reason %q inconsistent with state %v", tc.name, reason, got)
		}
	}
}

// The refusal names the reason without stray punctuation, carries the
// remedy, and never suggests the removed opt-out.
func TestCheckMessages(t *testing.T) {
	_, inactive := ClassifyLSMList([]byte("lockdown,capability,yama,apparmor"), nil)

	for _, l2 := range []bool{true, false} {
		st := Describe(false, l2)
		st.Reason = inactive
		err := st.Check()
		if err == nil {
			t.Fatal("Layer 1 unavailable must be refused")
		}
		msg := err.Error()
		for _, want := range []string{
			`(layer1=unavailable layer2=`,
			`"bpf" is not among the active LSMs`,
			"boot parameter; fail-closed, refusing to run the workload",
			FailClosedRemedy,
		} {
			if !strings.Contains(msg, want) {
				t.Fatalf("message missing %q:\n%s", want, msg)
			}
		}
		for _, bad := range []string{";:", ";;", ".;", "--allow-proxy-only", "pass --allow"} {
			if strings.Contains(msg, bad) {
				t.Fatalf("message contains %q:\n%s", bad, msg)
			}
		}
	}

	// No reason: no dangling colon.
	bare := Describe(false, false)
	if msg := bare.Check().Error(); !strings.HasPrefix(msg, "enforcement=none (layer1=unavailable layer2=disabled); fail-closed") {
		t.Fatalf("bare message: %s", msg)
	}
}

func TestNarrowNeverRaises(t *testing.T) {
	full := Describe(true, true)
	n := full.Narrow("client preflight: bpf inactive")
	if n.Enforcement != LevelNone || n.Layer1 != LayerUnavailable || n.Reason == "" {
		t.Fatalf("narrowed = %+v", n)
	}
	if err := n.Check(); err == nil || !strings.Contains(err.Error(), "bpf inactive") {
		t.Fatalf("narrowed status must be refused with the reason: %v", err)
	}
	down := Describe(false, true)
	down.Reason = "orig"
	if got := down.Narrow("other"); got != down {
		t.Fatalf("Narrow must not change an already-unavailable layer: %+v", got)
	}
	if got := Describe(true, false).Narrow("x"); got.Enforcement != LevelNone {
		t.Fatalf("narrowing lsm-only must give none, got %+v", got)
	}
}
