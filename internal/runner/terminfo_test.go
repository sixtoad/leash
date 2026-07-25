package runner

import (
	"os"
	"testing"
)

// These tests mutate the process-global TERM env var and assert on it, so they
// must NOT be parallel — two parallel tests racing on the same env var was flaky
// (one's restore landing between the other's normalize and assert). t.Setenv
// enforces this: it save/restores TERM and panics if t.Parallel was called.

func TestNormalizeTERMForBubbleTeaGhostty(t *testing.T) {
	t.Setenv("TERM", "xterm-ghostty")

	restore := normalizeTERMForBubbleTea()
	defer restore()

	if got := os.Getenv("TERM"); got != "xterm-256color" {
		t.Fatalf("TERM = %q, want xterm-256color", got)
	}
}

func TestNormalizeTERMForBubbleTeaPassthrough(t *testing.T) {
	const original = "xterm-256color"
	t.Setenv("TERM", original)

	restore := normalizeTERMForBubbleTea()
	defer restore()

	if got := os.Getenv("TERM"); got != original {
		t.Fatalf("TERM changed to %q, want %q", got, original)
	}
}
