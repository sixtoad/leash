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

	// Active: no warning, no error, regardless of requireLSM.
	if w, err := decideBPFLSM(bpfLSMActive, active, true); w != "" || err != nil {
		t.Fatalf("active: got (%q, %v), want empty/nil", w, err)
	}

	// Default (not requiring): warn and continue, no error.
	w, err := decideBPFLSM(bpfLSMInactiveCompiled, active, false)
	if err != nil {
		t.Fatalf("default degrade should not error, got: %v", err)
	}
	if !strings.Contains(w, "WARNING") || !strings.Contains(w, "proxy-only") || !strings.Contains(w, "CONFIG_BPF_LSM=y") {
		t.Fatalf("degrade warning not informative: %q", w)
	}

	// require-lsm: hard error, no warning string.
	w, err = decideBPFLSM(bpfLSMInactiveCompiled, active, true)
	if err == nil {
		t.Fatal("require-lsm should error when LSM unavailable")
	}
	if w != "" {
		t.Fatalf("require-lsm should not also emit a warning, got: %q", w)
	}
	if !strings.Contains(err.Error(), "--require-lsm") {
		t.Fatalf("require-lsm error should mention the flag: %v", err)
	}
}

func TestParseArgsRequireLSM(t *testing.T) {
	t.Parallel()

	opts, err := parseArgs([]string{"--require-lsm", "claude"})
	if err != nil {
		t.Fatalf("parseArgs error: %v", err)
	}
	if !opts.requireLSM {
		t.Fatal("--require-lsm should set requireLSM")
	}

	if _, err := parseArgs([]string{"--require-lsm=true"}); err == nil {
		t.Fatal("--require-lsm= should be rejected (takes no value)")
	}

	off, err := parseArgs([]string{"claude"})
	if err != nil {
		t.Fatalf("parseArgs error: %v", err)
	}
	if off.requireLSM || off.allowProxyOnly {
		t.Fatal("no flag should record neither explicit choice (the fail-closed default is applied in loadConfig)")
	}
}

func TestParseArgsAllowProxyOnly(t *testing.T) {
	t.Parallel()

	opts, err := parseArgs([]string{"--allow-proxy-only", "claude"})
	if err != nil {
		t.Fatalf("parseArgs error: %v", err)
	}
	if !opts.allowProxyOnly || opts.requireLSM {
		t.Fatalf("--allow-proxy-only should set only allowProxyOnly: %+v", opts)
	}
	if _, err := parseArgs([]string{"--allow-proxy-only=1"}); err == nil {
		t.Fatal("--allow-proxy-only= should be rejected (takes no value)")
	}
}

// Issue #117: fail closed by default; proxy-only only by explicit opt-out.
func TestLoadConfigResolvesFailClosedDefault(t *testing.T) {
	cases := []struct {
		name    string
		opts    options
		env     map[string]string
		want    bool
		wantErr bool
	}{
		{name: "default fails closed", want: true},
		{name: "--require-lsm is redundant", opts: options{requireLSM: true}, want: true},
		{name: "--allow-proxy-only opts out", opts: options{allowProxyOnly: true}, want: false},
		{name: "LEASH_ALLOW_PROXY_ONLY opts out", env: map[string]string{"LEASH_ALLOW_PROXY_ONLY": "1"}, want: false},
		{name: "falsy LEASH_REQUIRE_LSM does not opt out", env: map[string]string{"LEASH_REQUIRE_LSM": "0"}, want: true},
		{name: "flag beats env", opts: options{allowProxyOnly: true}, env: map[string]string{"LEASH_REQUIRE_LSM": "1"}, want: false},
		{name: "both flags conflict", opts: options{requireLSM: true, allowProxyOnly: true}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("LEASH_REQUIRE_LSM", "")
			t.Setenv("LEASH_ALLOW_PROXY_ONLY", "")
			t.Setenv("LEASH_WORK_DIR", t.TempDir())
			t.Setenv("LEASH_HOME", t.TempDir())
			t.Setenv("XDG_CONFIG_HOME", t.TempDir())
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			cfg, _, err := loadConfig(t.TempDir(), tc.opts)
			if tc.wantErr {
				if err == nil {
					t.Fatal("want an error for conflicting flags")
				}
				return
			}
			if err != nil {
				t.Fatalf("loadConfig: %v", err)
			}
			if cfg.requireLSM != tc.want {
				t.Fatalf("requireLSM = %v, want %v", cfg.requireLSM, tc.want)
			}
		})
	}
}

func TestEnforcementMarkerReport(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "enforcement.ready")
	if err := os.WriteFile(path, []byte(`{"enforcement":"proxy-only","layer1":"unavailable","layer2":"active","requireLSM":false,"allowProxyOnly":true}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, ok := readEnforcementStatus(path)
	if !ok {
		t.Fatal("JSON marker should decode")
	}
	if got, want := formatEnforcementLine(st), "leash: enforcement=proxy-only layer1=unavailable layer2=active"; got != want {
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
		warn, err := decideBPFLSM(bpfLSMInactiveCompiled, active, false)
		if err != nil {
			t.Fatalf("default degrade should not error: %v", err)
		}
		if strings.Contains(warn, "lsm=") {
			t.Errorf("run-path warning proposes lsm= from an empty list:\n%s", warn)
		}
		if _, err := decideBPFLSM(bpfLSMInactiveCompiled, active, true); err == nil {
			t.Error("require-lsm should still fail")
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
