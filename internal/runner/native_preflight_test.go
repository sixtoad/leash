package runner

import (
	"strings"
	"testing"
)

func TestClassifyNativeRuntime(t *testing.T) {
	cases := []struct {
		goos       string
		hasSystemd bool
		euid       int
		want       nativeViability
	}{
		{"linux", true, 0, nativeViable},
		{"linux", true, 1000, nativeNeedsRoot},
		{"linux", false, 0, nativeNoSystemd},
		{"darwin", true, 0, nativeNotLinux},
		{"windows", true, 0, nativeNotLinux},
	}
	for _, c := range cases {
		if got := classifyNativeRuntime(c.goos, c.hasSystemd, c.euid); got != c.want {
			t.Errorf("classify(%q,%v,%d) = %d, want %d", c.goos, c.hasSystemd, c.euid, got, c.want)
		}
	}
}

func TestDecideNativeRuntime(t *testing.T) {
	if err := decideNativeRuntime(nativeViable); err != nil {
		t.Fatalf("viable should be nil, got %v", err)
	}
	// Every non-viable state is fatal (no boundary survives) and must never
	// suggest a silent docker fallback — docker is opt-in.
	for _, v := range []nativeViability{nativeNotLinux, nativeNoSystemd, nativeNeedsRoot} {
		err := decideNativeRuntime(v)
		if err == nil {
			t.Fatalf("state %d should be fatal", v)
		}
		msg := err.Error()
		if !strings.Contains(msg, "--runtime docker") {
			t.Errorf("state %d advice should mention the explicit docker opt-in: %q", v, msg)
		}
		if strings.Contains(msg, "falling back") || strings.Contains(msg, "using docker") {
			t.Errorf("state %d must not imply an automatic docker fallback: %q", v, msg)
		}
	}
}

func TestNeedsRootAdviceMentionsSudo(t *testing.T) {
	if !strings.Contains(nativeRuntimeAdvice(nativeNeedsRoot), "sudo") {
		t.Fatal("needs-root advice should mention sudo")
	}
}
