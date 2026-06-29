package runner

import (
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
	if off.requireLSM {
		t.Fatal("requireLSM should default to false")
	}
}
