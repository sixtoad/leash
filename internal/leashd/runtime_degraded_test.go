package leashd

import (
	"strings"
	"testing"
)

// preFlight must allow startup when no cgroup path is available (degraded,
// proxy-only mode) instead of failing with "cgroup path required". This is the
// Docker Desktop Kubernetes case where /proc/self/cgroup reports "0::/" and
// leash-entry cannot emit a scopable cgroup path. A non-empty-but-invalid
// cgroup path is still rejected (covered by TestPreFlightInvalidCgroup).
// See issue #67.
func TestPreFlightAllowsMissingCgroup(t *testing.T) {
	cfg, cleanup := setupRuntimeEnv(t, false)
	defer cleanup()

	cfg.CgroupPath = "" // degraded: no scopable cgroup

	if err := preFlight(cfg); err != nil {
		t.Fatalf("missing cgroup should be allowed (degraded proxy-only mode), got: %v", err)
	}
}

// Issue #117: without a scopable cgroup the eBPF LSM cannot enforce, so the
// fail-closed default refuses to start; only --allow-proxy-only runs proxy-only.
func TestPreFlightMissingCgroupFailsClosedByDefault(t *testing.T) {
	cfg, cleanup := setupRuntimeEnv(t, false)
	defer cleanup()

	cfg.CgroupPath = ""
	cfg.RequireLSM = true

	err := preFlight(cfg)
	if err == nil {
		t.Fatal("missing cgroup must fail closed unless proxy-only is allowed")
	}
	if !strings.Contains(err.Error(), "--allow-proxy-only") {
		t.Fatalf("error should name the opt-out: %v", err)
	}
}
