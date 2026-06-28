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

func TestBPFLSMError(t *testing.T) {
	t.Parallel()

	active := []string{"lockdown", "yama", "apparmor"}

	if err := bpfLSMError(bpfLSMActive, active); err != nil {
		t.Fatalf("bpfLSMActive should yield nil error, got: %v", err)
	}

	compiled := bpfLSMError(bpfLSMInactiveCompiled, active)
	if compiled == nil || !strings.Contains(compiled.Error(), "CONFIG_BPF_LSM=y") ||
		!strings.Contains(compiled.Error(), "lsm=lockdown,yama,apparmor,bpf") ||
		!strings.Contains(compiled.Error(), "reboot") {
		t.Fatalf("inactive-compiled message not actionable: %v", compiled)
	}

	notCompiled := bpfLSMError(bpfLSMNotCompiled, active)
	if notCompiled == nil || !strings.Contains(notCompiled.Error(), "without CONFIG_BPF_LSM") {
		t.Fatalf("not-compiled message missing guidance: %v", notCompiled)
	}

	unknown := bpfLSMError(bpfLSMUnknown, active)
	if unknown == nil || !strings.Contains(unknown.Error(), "could not be read") {
		t.Fatalf("unknown message missing guidance: %v", unknown)
	}
}
