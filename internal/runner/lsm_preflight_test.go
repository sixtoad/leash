package runner

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClassifyBPFLSM(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		active []string
		config string
		want   bpfLSMStatus
	}{
		{"active wins regardless of config", []string{"apparmor", "bpf", "yama"}, "n", bpfLSMActive},
		{"active with empty config", []string{"bpf"}, "", bpfLSMActive},
		{"inactive but compiled y", []string{"apparmor", "yama"}, "y", bpfLSMInactiveCompiled},
		{"inactive but compiled m", []string{"apparmor"}, "m", bpfLSMInactiveCompiled},
		{"not compiled", []string{"apparmor"}, "n", bpfLSMNotCompiled},
		{"unknown when config unreadable", []string{"apparmor"}, "", bpfLSMUnknown},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := classifyBPFLSM(tc.active, tc.config); got != tc.want {
				t.Fatalf("classifyBPFLSM(%v, %q) = %d, want %d", tc.active, tc.config, got, tc.want)
			}
		})
	}
}

func TestParseConfigValue(t *testing.T) {
	t.Parallel()

	cfg := `# Automatically generated
CONFIG_BPF=y
CONFIG_BPF_LSM=y
# CONFIG_SOMETHING_ELSE is not set
`
	if v, ok := parseConfigValue(strings.NewReader(cfg), "CONFIG_BPF_LSM"); !ok || v != "y" {
		t.Fatalf("parseConfigValue =(%q,%v), want (y,true)", v, ok)
	}

	notSet := "# CONFIG_BPF_LSM is not set\n"
	if v, ok := parseConfigValue(strings.NewReader(notSet), "CONFIG_BPF_LSM"); !ok || v != "n" {
		t.Fatalf("parseConfigValue(not set) =(%q,%v), want (n,true)", v, ok)
	}

	absent := "CONFIG_BPF=y\n"
	if _, ok := parseConfigValue(strings.NewReader(absent), "CONFIG_BPF_LSM"); ok {
		t.Fatal("parseConfigValue(absent) returned ok=true, want false")
	}
}

func TestBPFLSMAdvice(t *testing.T) {
	t.Parallel()

	active := []string{"lockdown", "yama", "apparmor"}

	if a := bpfLSMAdvice(bpfLSMActive, active); a != "" {
		t.Fatalf("bpfLSMActive should yield empty advice, got: %q", a)
	}

	compiled := bpfLSMAdvice(bpfLSMInactiveCompiled, active)
	if !strings.Contains(compiled, "CONFIG_BPF_LSM=y") ||
		!strings.Contains(compiled, "lsm=lockdown,yama,apparmor,bpf") ||
		!strings.Contains(compiled, "reboot") {
		t.Fatalf("inactive-compiled advice not actionable: %q", compiled)
	}

	if a := bpfLSMAdvice(bpfLSMNotCompiled, active); !strings.Contains(a, "without CONFIG_BPF_LSM") {
		t.Fatalf("not-compiled advice missing guidance: %q", a)
	}

	if a := bpfLSMAdvice(bpfLSMUnknown, active); !strings.Contains(a, "could not be read") {
		t.Fatalf("unknown advice missing guidance: %q", a)
	}
}

func TestDecideBPFLSM(t *testing.T) {
	t.Parallel()

	active := []string{"lockdown", "apparmor"}

	if err := decideBPFLSM(bpfLSMActive, active); err != nil {
		t.Fatalf("active: got %v, want nil", err)
	}

	// bpf inactive (or unknown): always a hard error, never a warning.
	for _, status := range []bpfLSMStatus{bpfLSMInactiveCompiled, bpfLSMUnknown} {
		err := decideBPFLSM(status, active)
		if err == nil {
			t.Fatalf("status %v: an unavailable LSM must refuse to start", status)
		}
		if !strings.Contains(err.Error(), "fail-closed") || strings.Contains(err.Error(), "allow-proxy-only") {
			t.Fatalf("status %v: unexpected error: %v", status, err)
		}
	}
	if err := decideBPFLSM(bpfLSMInactiveCompiled, active); !strings.Contains(err.Error(), "CONFIG_BPF_LSM=y") {
		t.Fatalf("error should carry the advice: %v", err)
	}
}

// --require-lsm stays accepted as a no-op (Walk passes it); there is no
// proxy-only flag, so --allow-proxy-only is an unknown flag.
func TestParseArgsPostureFlags(t *testing.T) {
	t.Parallel()

	if _, err := parseArgs([]string{"--require-lsm", "claude"}); err != nil {
		t.Fatalf("--require-lsm must stay accepted: %v", err)
	}
	if _, err := parseArgs([]string{"--require-lsm=true"}); err == nil {
		t.Fatal("--require-lsm= should be rejected (takes no value)")
	}
	if _, err := parseArgs([]string{"--allow-proxy-only", "claude"}); err == nil || !strings.Contains(err.Error(), "unknown flag") {
		t.Fatalf("--allow-proxy-only must be an unknown flag, got %v", err)
	}
}
func TestEnforcementMarkerReport(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "enforcement.ready")
	if err := os.WriteFile(path, []byte(`{"enforcement":"lsm","layer1":"active","layer2":"disabled","requireLSM":true}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, ok := readEnforcementStatus(path)
	if !ok {
		t.Fatal("JSON marker should decode")
	}
	if got, want := formatEnforcementLine(st), "leash: enforcement=lsm layer1=active layer2=disabled"; got != want {
		t.Fatalf("line = %q, want %q", got, want)
	}
	// An older leashd writes a bare "ready" line: no status, nothing reported.
	if err := os.WriteFile(path, []byte("ready\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := readEnforcementStatus(path); ok {
		t.Fatal("legacy marker must not decode as a status")
	}
}

// CAP-7: the remedy must never be harmful to follow. ProbeBPFLSM used to
// swallow the readActiveLSMs error into a nil list, which classifies as
// "compiled but inactive" whenever CONFIG_BPF_LSM=y and then renders the empty
// list into `lsm=,bpf` — a leading-comma list that REPLACES the host's LSM
// stack, silently disabling AppArmor/SELinux.
func TestDecideLSMStateUnreadableListIsUnknownAndSafe(t *testing.T) {
	t.Parallel()

	for _, config := range []string{"y", "m", "n", ""} {
		state, advice := decideLSMState(nil, errors.New("no such file or directory"), config)
		if state != LSMUnknown {
			t.Errorf("config %q: state = %v, want LSMUnknown", config, state)
		}
		if strings.TrimSpace(advice) == "" {
			t.Errorf("config %q: unknown state still needs a next step", config)
		}
		if strings.Contains(advice, "lsm=") {
			t.Errorf("config %q: advice proposes an lsm= boot parameter built from a list we could not read:\n%s", config, advice)
		}
	}
}

// CAP-7, the half the first fix missed. readActiveLSMs splits the file on ",",
// so an EMPTY or whitespace-only /sys/kernel/security/lsm returns
// ([]string{""}, nil) — a successful read of a list that names nothing. The
// readErr-only guard let that through to classifyBPFLSM, which answers
// "compiled but inactive" whenever CONFIG_BPF_LSM=y, and bpfLSMAdvice rendered
// the empty list as `lsm=,bpf`. Reproduced on the development host.
func TestDecideLSMStateEmptyListIsUnknownAndSafe(t *testing.T) {
	t.Parallel()

	// Exactly what readActiveLSMs produces for these file contents.
	read := func(contents string) []string {
		return strings.Split(strings.TrimSpace(contents), ",")
	}

	for _, contents := range []string{"", " ", "\n", "\t\n  ", ",", " , , "} {
		for _, config := range []string{"y", "m", "n", ""} {
			state, advice := decideLSMState(read(contents), nil, config)
			if state != LSMUnknown {
				t.Errorf("contents %q, config %q: state = %v, want LSMUnknown — reading nothing tells us nothing", contents, config, state)
			}
			if strings.TrimSpace(advice) == "" {
				t.Errorf("contents %q, config %q: unknown state still needs a next step", contents, config)
			}
			if strings.Contains(advice, "lsm=") {
				t.Errorf("contents %q, config %q: advice proposes an lsm= boot parameter built from a list that names nothing — following it REPLACES the host LSM stack:\n%s", contents, config, advice)
			}
		}
	}
}

// bpfLSMAdvice is shared with the real run path (preflightHostKernel ->
// decideBPFLSM), which classifies rather than going through decideLSMState. It
// therefore has to refuse the dangerous template itself, not rely on its
// callers having guarded first.
func TestBPFLSMAdviceNeverEmitsAnEmptyLSMList(t *testing.T) {
	t.Parallel()

	empties := [][]string{nil, {}, {""}, {" "}, {"", ""}, {"", "  ", ""}}
	statuses := []bpfLSMStatus{bpfLSMInactiveCompiled, bpfLSMNotCompiled, bpfLSMUnknown}

	for _, active := range empties {
		for _, status := range statuses {
			advice := bpfLSMAdvice(status, active)
			if strings.TrimSpace(advice) == "" {
				t.Errorf("status %d, active %#v: no remedy at all", status, active)
			}
			if strings.Contains(advice, "lsm=") {
				t.Errorf("status %d, active %#v: advice contains an lsm= line:\n%s", status, active, advice)
			}
		}
		// The same guard has to hold on the run path's own decision.
		if err := decideBPFLSM(bpfLSMInactiveCompiled, active); err == nil {
			t.Error("an inactive bpf LSM must fail")
		} else if strings.Contains(err.Error(), "lsm=") {
			t.Errorf("run-path error proposes lsm= from an empty list:\n%v", err)
		}
	}

	// Whitespace around real entries is trimmed, not treated as an entry.
	advice := bpfLSMAdvice(bpfLSMInactiveCompiled, []string{" lockdown ", "", "apparmor"})
	if !strings.Contains(advice, "lsm=lockdown,apparmor,bpf") {
		t.Errorf("a real list must still produce a real lsm= line:\n%s", advice)
	}
}

// LSMState is decoded by anything parsing `leash doctor --json` into Go, so the
// marshal/unmarshal pair has to be exact — a half-implemented pair silently
// yields LSMUnknown for every document.
func TestLSMStateJSONRoundTrip(t *testing.T) {
	t.Parallel()

	for _, state := range []LSMState{LSMUnknown, LSMInactive, LSMActive} {
		out, err := json.Marshal(state)
		if err != nil {
			t.Fatalf("marshal %v: %v", state, err)
		}
		var got LSMState
		if err := json.Unmarshal(out, &got); err != nil {
			t.Fatalf("unmarshal %s: %v", out, err)
		}
		if got != state {
			t.Errorf("round trip %v -> %s -> %v", state, out, got)
		}
	}

	for _, bad := range []string{`"enabled"`, `""`, `2`, `null`} {
		var got LSMState
		if err := json.Unmarshal([]byte(bad), &got); err == nil {
			t.Errorf("unmarshal(%s) should fail rather than decode as %v", bad, got)
		}
	}
}

func TestDecideLSMState(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		active    []string
		config    string
		want      LSMState
		wantJSON  string
		hasAdvice bool
	}{
		{"active", []string{"apparmor", "bpf"}, "y", LSMActive, `"active"`, false},
		{"inactive but compiled", []string{"apparmor"}, "y", LSMInactive, `"inactive"`, true},
		{"not compiled", []string{"apparmor"}, "n", LSMInactive, `"inactive"`, true},
		{"inactive, config unreadable", []string{"apparmor"}, "", LSMInactive, `"inactive"`, true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			state, advice := decideLSMState(tc.active, nil, tc.config)
			if state != tc.want {
				t.Fatalf("state = %v, want %v", state, tc.want)
			}
			if (strings.TrimSpace(advice) != "") != tc.hasAdvice {
				t.Errorf("advice = %q, wanted advice: %v", advice, tc.hasAdvice)
			}
			out, err := json.Marshal(state)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if string(out) != tc.wantJSON {
				t.Errorf("json = %s, want %s", out, tc.wantJSON)
			}
		})
	}

	// The zero value must read as "unknown", never as a claim of availability.
	if got := LSMState(0).String(); got != "unknown" {
		t.Errorf("zero LSMState = %q, want %q", got, "unknown")
	}
}
