//go:build darwin

package darwind

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/strongdm/leash/internal/policy"
)

// The darwin daemon enforces whatever Cedar policy it loads, so the policy file
// is as sensitive as the enforcement itself (#12). It used to default to
// /tmp/tmp.leash.policy: any local user could create that file, or a symlink
// in its place, before leash first ran and hand the daemon their own policy.
//
// The default is now policy.cedar in the per-user leash state directory
// (~/Library/Application Support/leash, created 0700), and every policy path,
// default or not, must pass checkPolicyPathSafe before it is created or read.

// policyFilename is the default policy file name inside the state directory.
const policyFilename = "policy.cedar"

// policyPathTrustedFloor stops the ancestor walk of checkPolicyPathSafe at
// this directory (inclusive). Always empty in leash; tests set it to their
// temporary root, which on a developer machine may sit below a directory
// other users can write to.
var policyPathTrustedFloor string

// defaultDarwinPolicyPath is the policy file the daemon uses when neither
// --policy nor LEASH_POLICY names one.
func defaultDarwinPolicyPath() (string, error) {
	dir, err := execStateDir()
	if err != nil {
		return "", fmt.Errorf("prepare leash state directory: %w", err)
	}
	return filepath.Join(dir, policyFilename), nil
}

// checkPolicyPathSafe refuses a policy path another local user could have
// planted or could still replace:
//
//   - the file itself, if it exists, must be a regular file (not a symlink),
//     owned by the daemon's user or root, and not writable by group or others;
//   - every directory from the root down to the file's directory (after
//     resolving symlinks in the directory part) must be owned by the daemon's
//     user or root, and must not be writable by group or others unless it is
//     sticky. A sticky directory (/private/tmp) is acceptable only because the
//     entry below it must itself pass these checks: the sticky bit stops other
//     users from renaming or deleting an entry they do not own.
//
// The same-user workload is not stopped by any of this (it runs as the
// daemon's user); that is the Endpoint Security extension's job.
func checkPolicyPathSafe(path string) error {
	cleaned := filepath.Clean(strings.TrimSpace(path))
	if cleaned == "" || cleaned == "." {
		return fmt.Errorf("policy file path required")
	}
	if !filepath.IsAbs(cleaned) {
		abs, err := filepath.Abs(cleaned)
		if err != nil {
			return fmt.Errorf("resolve policy path %q: %w", path, err)
		}
		cleaned = abs
	}
	uid := uint32(os.Geteuid())
	trusted := func(st *syscall.Stat_t) bool { return st.Uid == uid || st.Uid == 0 }

	dir, err := filepath.EvalSymlinks(filepath.Dir(cleaned))
	if err != nil {
		return fmt.Errorf("unsafe policy path %q: resolve its directory: %w", path, err)
	}
	// Walk from the root down to the file's directory.
	var chain []string
	for d := dir; ; d = filepath.Dir(d) {
		chain = append([]string{d}, chain...)
		if d == filepath.Dir(d) || (policyPathTrustedFloor != "" && d == policyPathTrustedFloor) {
			break
		}
	}
	for _, d := range chain {
		info, err := os.Lstat(d)
		if err != nil {
			return fmt.Errorf("unsafe policy path %q: %w", path, err)
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("unsafe policy path %q: cannot read the owner of %q", path, d)
		}
		if !info.IsDir() {
			return fmt.Errorf("unsafe policy path %q: %q is not a directory", path, d)
		}
		if !trusted(st) {
			return fmt.Errorf("unsafe policy path %q: directory %q is owned by uid %d, not by you or root", path, d, st.Uid)
		}
		if info.Mode().Perm()&0o022 != 0 && info.Mode()&os.ModeSticky == 0 {
			return fmt.Errorf("unsafe policy path %q: directory %q is writable by other users (mode %04o)", path, d, info.Mode().Perm())
		}
	}

	file := filepath.Join(dir, filepath.Base(cleaned))
	info, err := os.Lstat(file)
	if errors.Is(err, fs.ErrNotExist) {
		return nil // created by ensurePolicyFile, inside the directory just checked
	}
	if err != nil {
		return fmt.Errorf("unsafe policy path %q: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("unsafe policy path %q: it is a symlink; point leash at the real file", path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("unsafe policy path %q: not a regular file", path)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("unsafe policy path %q: cannot read its owner", path)
	}
	if !trusted(st) {
		return fmt.Errorf("unsafe policy path %q: owned by uid %d, not by you or root", path, st.Uid)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("unsafe policy path %q: writable by other users (mode %04o); chmod go-w it", path, info.Mode().Perm())
	}
	return nil
}

// ensurePolicyFile checks the path and, if the file does not exist, writes the
// default policy with O_EXCL|O_NOFOLLOW (mode 0600), so a file or symlink
// planted between the check and the create makes it fail instead of being
// followed or reused.
func ensurePolicyFile(path string) error {
	if err := checkPolicyPathSafe(path); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return checkPolicyPathSafe(path) // it exists: re-check what is there now
	}
	if err != nil {
		return fmt.Errorf("create policy file %q: %w", path, err)
	}
	content := strings.TrimSpace(policy.DefaultCedar()) + "\n"
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		return fmt.Errorf("write default policy to %q: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("write default policy to %q: %w", path, err)
	}
	return nil
}
