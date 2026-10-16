package leashd

import (
	"fmt"
	"path/filepath"
	"strings"
)

// cgroup2Root is where the unified (v2) cgroup hierarchy is mounted. leashd
// already assumes this mount point elsewhere (the runner bind-mounts it into
// the leash container, the native launcher builds paths under it, and the LSM
// derives cgroup levels from it), and nft itself resolves `socket cgroupv2`
// paths relative to this same directory, so it is the root we strip.
const cgroup2Root = "/sys/fs/cgroup"

// cgroup2RulePath converts an absolute cgroup directory (e.g.
// /sys/fs/cgroup/system.slice/foo.service) into the form the kernel-side
// cgroup matchers expect: a path relative to the cgroup2 root
// ("system.slice/foo.service") plus its depth below that root (2), which is
// the `level` nft's `socket cgroupv2` match must be given.
//
// It returns an error when the path cannot be expressed safely as a
// per-cgroup rule: empty input, a relative input, a path outside root, the
// root cgroup itself (which would match every process), or a component that
// cannot be embedded in an nft quoted string. Callers fall back to the
// namespace-wide control-plane block in that case.
func cgroup2RulePath(root, cgroupPath string) (string, int, error) {
	p := strings.TrimSpace(cgroupPath)
	if p == "" {
		return "", 0, fmt.Errorf("empty cgroup path")
	}
	if !filepath.IsAbs(p) {
		return "", 0, fmt.Errorf("cgroup path %q is not absolute", cgroupPath)
	}
	root = filepath.Clean(root)
	rel, err := filepath.Rel(root, filepath.Clean(p))
	if err != nil {
		return "", 0, fmt.Errorf("cgroup path %q is not under %s: %w", cgroupPath, root, err)
	}
	rel = filepath.ToSlash(rel)
	if rel == ".." || strings.HasPrefix(rel, "../") {
		return "", 0, fmt.Errorf("cgroup path %q is not under %s", cgroupPath, root)
	}
	if rel == "." {
		return "", 0, fmt.Errorf("cgroup path %q is the cgroup2 root; refusing a rule that matches every process", cgroupPath)
	}
	for _, r := range rel {
		// nft quoted strings have no escape syntax, so a double quote cannot be
		// represented; backslashes and control characters are rejected too
		// rather than relying on version-specific scanner behaviour.
		if r == '"' || r == '\\' || r < 0x20 || r == 0x7f {
			return "", 0, fmt.Errorf("cgroup path %q contains a character that cannot be used in an nft rule", cgroupPath)
		}
	}
	return rel, len(strings.Split(rel, "/")), nil
}

// nftablesScriptArgs builds the /bin/sh argv for apply-nftables.sh:
// -s <MITM_PORT> <LEASH_PORT> <TARGET_CGROUP> <TARGET_CGROUP_LEVEL>.
func nftablesScriptArgs(port, leashPort, cgroupPath string, cgroupLevel int) []string {
	level := ""
	if cgroupPath != "" {
		level = fmt.Sprint(cgroupLevel)
	}
	return []string{"-s", port, leashPort, cgroupPath, level}
}
