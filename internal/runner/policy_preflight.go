package runner

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	cedarutil "github.com/strongdm/leash/internal/cedar"
	"github.com/strongdm/leash/internal/entrypoint"
	"github.com/strongdm/leash/internal/lsm"
)

// validateSourcePolicy checks the configured policy file (--policy or
// LEASH_POLICY_FILE) up front, before the launcher's preflight or any
// provisioning. A missing or unreadable file is fatal when it was requested
// explicitly; with no configured policy there is nothing to check yet.
func (r *runner) validateSourcePolicy() error {
	src := strings.TrimSpace(r.cfg.policyPath)
	if src == "" {
		return nil
	}
	data, err := os.ReadFile(src)
	if err != nil {
		if !r.cfg.policyOverride {
			return nil // syncPolicyFile warns; leashd falls back to its default
		}
		return policyLoadError(src, fmt.Errorf("read policy: %w", err))
	}
	return validatePolicyText(src, string(data))
}

// validateStagedPolicy compiles the policy leashd will load (cfgDir/leash.cedar)
// before anything is provisioned, so a policy that does not parse, compile or
// fit the kernel's limits aborts the run with its reason, for every runtime and
// regardless of --allow-proxy-only: a bad policy is not an LSM-availability
// problem, and no posture permits running the workload without one. When no
// policy is staged (none configured), leashd writes its default; nothing to check.
func (r *runner) validateStagedPolicy() error {
	staged := filepath.Join(r.cfg.cfgDir, "leash.cedar")
	data, err := os.ReadFile(staged)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && !r.cfg.policyOverride {
			return nil
		}
		return policyLoadError(r.policyDisplayPath(staged), fmt.Errorf("read policy: %w", err))
	}
	display := r.policyDisplayPath(staged)
	return validatePolicyText(display, string(data))
}

// policyDisplayPath names the operator's policy file in errors rather than the
// staged copy leashd reads.
func (r *runner) policyDisplayPath(staged string) string {
	if p := strings.TrimSpace(r.cfg.policyPath); p != "" {
		return p
	}
	return staged
}

// validatePolicyText compiles Cedar the same way leashd does at startup and
// checks the result against the kernel's policy limits.
func validatePolicyText(name, text string) error {
	comp, err := cedarutil.CompileString(name, text)
	if err != nil {
		var detail *cedarutil.ErrorDetail
		if errors.As(err, &detail) {
			return policyLoadError(name, errors.New(cedarutil.FormatForCLI(detail)))
		}
		return policyLoadError(name, err)
	}
	if err := lsm.ValidateKernelPolicyLimits(comp.Policies); err != nil {
		return policyLoadError(name, err)
	}
	return nil
}

func policyLoadError(name string, cause error) error {
	return fmt.Errorf("policy %s failed to load; refusing to start the workload without it:\n%w", name, cause)
}

// clearStaleEnforcementMarker removes a previous run's enforcement-ready marker
// from the share dir before leashd starts. A reused share dir (LEASH_SHARE_DIR)
// could otherwise satisfy the readiness wait for a leashd that exited before
// clearing it (e.g. on a policy that failed to load). Failing to remove it is
// fatal: the marker is the release gate.
func clearStaleEnforcementMarker(shareDir string) error {
	if strings.TrimSpace(shareDir) == "" {
		return nil
	}
	marker := filepath.Join(shareDir, entrypoint.EnforcementReadyFileName)
	if err := os.Remove(marker); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove stale enforcement-ready marker %s: %w", marker, err)
	}
	return nil
}
