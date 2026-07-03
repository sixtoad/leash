package runner

import "testing"

// DOWNSTREAM: the default runtime is native on every OS (the intent is the
// platform's native enforcement, detected by OS). Linux is the only wired native
// backend today; macOS/Windows default to native and the preflight guides.
func TestDefaultRuntimeNameIsNative(t *testing.T) {
	orig := goos
	defer func() { goos = orig }()
	for _, os := range []string{"linux", "darwin", "windows"} {
		goos = func() string { return os }
		if got := defaultRuntimeName(); got != "native" {
			t.Errorf("default on %s = %q, want native", os, got)
		}
	}
}
