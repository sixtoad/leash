package runner

import (
	"fmt"
	"strings"

	"github.com/strongdm/leash/internal/enforcement"
)

// postureEnvKeys are the env vars that select leashd's fail-closed vs
// proxy-only posture. The client resolves the posture once and injects exactly
// one of them into the leash container; a user-supplied copy would either be
// overridden silently or (both set) make leashd abort with a mutual-exclusion
// error, so they are rejected up front.
var postureEnvKeys = []string{enforcement.EnvRequireLSM, enforcement.EnvAllowProxyOnly}

// postureFlags are the leashd flags carrying the same posture. Forwarding one
// through LEASH_EXTRA_ARGS would let leashd's posture diverge from the
// client's (explicit flags beat env on the leashd side).
var postureFlags = []string{"require-lsm", "allow-proxy-only"}

// validatePostureOverrides rejects posture settings smuggled past the client's
// resolution: `-e LEASH_REQUIRE_LSM=…` / `-e LEASH_ALLOW_PROXY_ONLY=…` (with or
// without a value) and posture flags inside LEASH_EXTRA_ARGS.
func validatePostureOverrides(envVars []string, extraArgs string) error {
	for _, env := range envVars {
		key := strings.TrimSpace(env)
		if i := strings.IndexByte(key, '='); i >= 0 {
			key = key[:i]
		}
		for _, k := range postureEnvKeys {
			if key == k {
				return fmt.Errorf("-e %s is not supported: set the enforcement posture with --allow-proxy-only (or %s=1 in leash's own environment); fail-closed is the default", k, enforcement.EnvAllowProxyOnly)
			}
		}
	}
	for _, field := range strings.Fields(extraArgs) {
		name := strings.TrimLeft(field, "-")
		if i := strings.IndexByte(name, '='); i >= 0 {
			name = name[:i]
		}
		if !strings.HasPrefix(field, "-") {
			continue
		}
		for _, f := range postureFlags {
			if name == f {
				return fmt.Errorf("LEASH_EXTRA_ARGS must not contain --%s: pass --allow-proxy-only to leash itself so the client and leashd agree on the enforcement posture", f)
			}
		}
	}
	return nil
}

// checkReleasedEnforcement cross-checks the level leashd reports in the
// enforcement-ready marker against the posture the client resolved, so a
// leashd whose posture diverged cannot release the workload less enforced than
// the client requires. A marker without a status (older leashd) passes:
// existence-gating is unchanged and there is nothing to compare.
func checkReleasedEnforcement(st enforcement.Status, ok, requireLSM bool) error {
	if !ok {
		return nil
	}
	if err := st.Check(requireLSM); err != nil {
		return fmt.Errorf("leashd reports %w", err)
	}
	return nil
}
