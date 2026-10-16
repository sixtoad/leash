package runner

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/strongdm/leash/internal/configstore"
)

// Bounds for target-container resource limits (#116). The floors match what
// docker enforces itself (memory >= 6 MiB) or are the smallest meaningful value;
// the ceilings only reject obvious garbage.
const (
	minMemoryBytes = 6 * 1024 * 1024
	maxCPUs        = 4096
	maxPidsLimit   = 1 << 22
)

// resourceLimits are validated target-container limits. The string fields are
// the normalized engine syntax passed to `run`; the numeric fields are what the
// engine must report back on inspect. A zero value means "not set".
type resourceLimits struct {
	cpus      string // --cpus, e.g. "1.5"
	memory    string // --memory, e.g. "2g"
	pidsLimit string // --pids-limit, e.g. "256"

	nanoCPUs    int64
	memoryBytes int64
	pids        int64
}

func (l resourceLimits) any() bool {
	return l.cpus != "" || l.memory != "" || l.pidsLimit != ""
}

var (
	cpusPattern   = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?$`)
	memoryPattern = regexp.MustCompile(`^([0-9]+)([bkmg]?)$`)
	pidsPattern   = regexp.MustCompile(`^[0-9]+$`)
)

func parseCPUs(raw string) (string, int64, error) {
	v := strings.TrimSpace(raw)
	if !cpusPattern.MatchString(v) {
		return "", 0, fmt.Errorf("invalid cpus %q: want a positive decimal number of CPUs, e.g. 1 or 1.5", raw)
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil || f <= 0 || f > maxCPUs {
		return "", 0, fmt.Errorf("invalid cpus %q: must be > 0 and <= %d", raw, maxCPUs)
	}
	nano := int64(math.Round(f * 1e9))
	if nano <= 0 {
		return "", 0, fmt.Errorf("invalid cpus %q: too small", raw)
	}
	return v, nano, nil
}

func parseMemory(raw string) (string, int64, error) {
	v := strings.ToLower(strings.TrimSpace(raw))
	m := memoryPattern.FindStringSubmatch(v)
	if m == nil {
		return "", 0, fmt.Errorf("invalid memory %q: want <number>[b|k|m|g], e.g. 512m or 2g", raw)
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return "", 0, fmt.Errorf("invalid memory %q: %v", raw, err)
	}
	mult := int64(1)
	switch m[2] {
	case "k":
		mult = 1 << 10
	case "m":
		mult = 1 << 20
	case "g":
		mult = 1 << 30
	}
	if n > math.MaxInt64/mult {
		return "", 0, fmt.Errorf("invalid memory %q: too large", raw)
	}
	bytes := n * mult
	if bytes < minMemoryBytes {
		return "", 0, fmt.Errorf("invalid memory %q: minimum is 6m", raw)
	}
	return v, bytes, nil
}

func parsePidsLimit(raw string) (string, int64, error) {
	v := strings.TrimSpace(raw)
	if !pidsPattern.MatchString(v) {
		return "", 0, fmt.Errorf("invalid pids limit %q: want a positive integer", raw)
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 1 || n > maxPidsLimit {
		return "", 0, fmt.Errorf("invalid pids limit %q: must be between 1 and %d", raw, maxPidsLimit)
	}
	return strconv.FormatInt(n, 10), n, nil
}

// resolveResourceLimits layers each limit flag > env > config file
// ([leash.resources], .leash.toml over the global config) and validates the
// winner. A garbage value at the winning layer is an error, never ignored.
func resolveResourceLimits(opts options, file configstore.ResourceLimits) (resourceLimits, error) {
	pick := func(flag, envKey, fromFile string) (string, string) {
		if v := strings.TrimSpace(flag); v != "" {
			return v, "flag"
		}
		if v := strings.TrimSpace(os.Getenv(envKey)); v != "" {
			return v, envKey
		}
		if v := strings.TrimSpace(fromFile); v != "" {
			return v, "config"
		}
		return "", ""
	}
	var out resourceLimits
	var errs []error
	if v, src := pick(opts.cpus, "LEASH_CPUS", file.CPUs); v != "" {
		norm, nano, err := parseCPUs(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", src, err))
		}
		out.cpus, out.nanoCPUs = norm, nano
	}
	if v, src := pick(opts.memory, "LEASH_MEMORY", file.Memory); v != "" {
		norm, b, err := parseMemory(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", src, err))
		}
		out.memory, out.memoryBytes = norm, b
	}
	if v, src := pick(opts.pidsLimit, "LEASH_PIDS_LIMIT", file.PidsLimit); v != "" {
		norm, n, err := parsePidsLimit(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", src, err))
		}
		out.pidsLimit, out.pids = norm, n
	}
	if err := errors.Join(errs...); err != nil {
		return resourceLimits{}, fmt.Errorf("resource limits: %w", err)
	}
	return out, nil
}

// dockerArgs are the target `run` flags for the limits. --memory-swap is pinned
// to --memory so the memory limit is a hard cap rather than memory+swap.
func (l resourceLimits) dockerArgs() []string {
	var args []string
	if l.cpus != "" {
		args = append(args, "--cpus", l.cpus)
	}
	if l.memory != "" {
		args = append(args, "--memory", l.memory, "--memory-swap", l.memory)
	}
	if l.pidsLimit != "" {
		args = append(args, "--pids-limit", l.pidsLimit)
	}
	return args
}

// report is the stable key=value form printed once the engine confirmed the
// limits. Fields are always in this order; unset limits are omitted.
func (l resourceLimits) report() string {
	var b strings.Builder
	b.WriteString("event=runner.resource-limits status=applied")
	if l.cpus != "" {
		fmt.Fprintf(&b, " cpus=%s nano_cpus=%d", l.cpus, l.nanoCPUs)
	}
	if l.memory != "" {
		fmt.Fprintf(&b, " memory=%s memory_bytes=%d", l.memory, l.memoryBytes)
	}
	if l.pidsLimit != "" {
		fmt.Fprintf(&b, " pids_limit=%d", l.pids)
	}
	return b.String()
}

// verifyTargetResourceLimits reads the target's HostConfig back from the engine
// and fails closed when a requested limit was not applied (e.g. an engine or
// cgroup setup that accepts the flag but drops it). On success it reports the
// applied limits on the diagnostics stream (stderr under --machine-output).
func (r *runner) verifyTargetResourceLimits(ctx context.Context) error {
	l := r.cfg.resources
	if !l.any() {
		return nil
	}
	out, err := r.rt().Output(ctx, "inspect", "-f", "{{.HostConfig.NanoCpus}} {{.HostConfig.Memory}} {{.HostConfig.PidsLimit}}", r.cfg.targetContainer)
	if err != nil {
		return fmt.Errorf("verify resource limits on %s: %w", r.cfg.targetContainer, err)
	}
	fields := strings.Fields(out)
	if len(fields) != 3 {
		return fmt.Errorf("verify resource limits on %s: unexpected inspect output %q", r.cfg.targetContainer, strings.TrimSpace(out))
	}
	got := make([]int64, 3)
	for i, f := range fields {
		if f == "<nil>" {
			continue // unset (e.g. podman PidsLimit when not requested)
		}
		n, err := strconv.ParseInt(f, 10, 64)
		if err != nil {
			return fmt.Errorf("verify resource limits on %s: unexpected inspect output %q", r.cfg.targetContainer, strings.TrimSpace(out))
		}
		got[i] = n
	}
	var mismatches []string
	if l.cpus != "" && got[0] != l.nanoCPUs {
		mismatches = append(mismatches, fmt.Sprintf("cpus: requested %s (NanoCpus %d), engine reports %d", l.cpus, l.nanoCPUs, got[0]))
	}
	if l.memory != "" && got[1] != l.memoryBytes {
		mismatches = append(mismatches, fmt.Sprintf("memory: requested %s (%d bytes), engine reports %d", l.memory, l.memoryBytes, got[1]))
	}
	if l.pidsLimit != "" && got[2] != l.pids {
		mismatches = append(mismatches, fmt.Sprintf("pids-limit: requested %d, engine reports %d", l.pids, got[2]))
	}
	if len(mismatches) > 0 {
		return fmt.Errorf("target container %s: requested resource limits were not applied by %s (%s)", r.cfg.targetContainer, r.rt().Name(), strings.Join(mismatches, "; "))
	}
	r.diagnosticf("%s\n", l.report())
	return nil
}
