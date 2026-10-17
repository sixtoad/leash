package leashd

import (
	"strings"
	"testing"
)

// Without a scopable cgroup (the Docker Desktop Kubernetes case, where
// /proc/self/cgroup reports "0::/" and leash-entry cannot emit a scopable
// cgroup path) the eBPF LSM cannot enforce, so leashd refuses to start in
// every mode: there is no degraded mode that runs with only the L7 proxy.
// See issues #67 and #117.
func TestPreFlightMissingCgroupAlwaysRefuses(t *testing.T) {
	for _, lsmOnly := range []bool{false, true} {
		cfg, cleanup := setupRuntimeEnv(t, false)
		cfg.CgroupPath = ""
		cfg.LSMOnly = lsmOnly

		err := preFlight(cfg)
		cleanup()
		if err == nil {
			t.Fatalf("lsmOnly=%t: missing cgroup must refuse to start", lsmOnly)
		}
		if !strings.Contains(err.Error(), "no cgroup path") || !strings.Contains(err.Error(), "refusing to run it unenforced") {
			t.Fatalf("lsmOnly=%t: unexpected error: %v", lsmOnly, err)
		}
		if strings.Contains(err.Error(), "allow-proxy-only") {
			t.Fatalf("lsmOnly=%t: error must not suggest a proxy-only opt-out: %v", lsmOnly, err)
		}
	}
}
