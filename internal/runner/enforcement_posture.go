package runner

import (
	"fmt"
	"strings"

	"github.com/strongdm/leash/internal/enforcement"
)

// validatePostureOverrides rejects a user-supplied `-e LEASH_REQUIRE_LSM=…`
// (with or without a value). The client injects LEASH_REQUIRE_LSM=1 into the
// leash container so an older leashd image stays fail-closed; a user copy
// could override it there. Fail-closed is the only posture, so there is
// nothing to set.
func validatePostureOverrides(envVars []string) error {
	for _, env := range envVars {
		key := strings.TrimSpace(env)
		if i := strings.IndexByte(key, '='); i >= 0 {
			key = key[:i]
		}
		if key == enforcement.EnvRequireLSM {
			return fmt.Errorf("-e %s is not supported: leash always fails closed when the eBPF LSM is unavailable, and sets it for the leash container itself", key)
		}
	}
	return nil
}

// checkReleasedEnforcement cross-checks the level leashd reports in the
// enforcement-ready marker, so a leashd that released the workload at any
// level other than "lsm" (an older image) cannot run it less enforced. A
// marker without a status (older leashd) passes: existence-gating is
// unchanged and there is nothing to compare.
func checkReleasedEnforcement(st enforcement.Status, ok bool) error {
	if !ok {
		return nil
	}
	if err := st.Check(); err != nil {
		return fmt.Errorf("leashd reports %w", err)
	}
	return nil
}
