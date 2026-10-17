//go:build unix

package enforcerd

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// CgroupRoot is the cgroup v2 mount.
const CgroupRoot = "/sys/fs/cgroup"

// ValidateTargetCgroup decides whether uid may have enforcement attached to
// the cgroup directory path, and returns the cgroup's id (its inode number,
// which is what the BPF programs compare against).
//
// The cgroup must be inside uid's delegated systemd subtree,
// <root>/user.slice/user-<uid>.slice/user@<uid>.service/..., strictly below
// the service itself (never the service, the slice or anything above), with
// every path component a real directory (no symlinks), the delegated service
// directory owned by uid and the target owned by uid or by one of uid's
// subordinate uids (resolve maps a uid to its owning account: crun creates the
// container's cgroup as container root, which is a subordinate uid in a
// keep-id user namespace), the target a live cgroup v2
// directory (cgroup.controllers present) with processes in it. Rootless
// podman's containers live there (libpod-<id>.scope/container); nothing of
// another user, or of the system, does.
func ValidateTargetCgroup(root string, uid int, path string, resolve func(uid int) (int, error)) (uint64, error) {
	if uid <= 0 {
		return 0, errors.New("root does not need the enforcer daemon: run leash as root to load the eBPF LSM directly")
	}
	if path == "" || !filepath.IsAbs(path) {
		return 0, fmt.Errorf("cgroup %q is not an absolute path", path)
	}
	if filepath.Clean(path) != path || strings.Contains(path, "/../") || strings.HasSuffix(path, "/..") {
		return 0, fmt.Errorf("cgroup %q is not a clean path", path)
	}
	root = filepath.Clean(root)
	delegated := filepath.Join(root, "user.slice", fmt.Sprintf("user-%d.slice", uid), fmt.Sprintf("user@%d.service", uid))
	rel, err := filepath.Rel(delegated, path)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return 0, fmt.Errorf("cgroup %s is not inside your delegated cgroup subtree %s/ (uid %d): the daemon only enforces on cgroups its caller owns", path, delegated, uid)
	}
	// Walk from the root so no component can be a symlink to elsewhere.
	cur := root
	if err := checkDir(cur, -1, nil); err != nil {
		return 0, err
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, root+"/"), "/") {
		cur = filepath.Join(cur, part)
		switch cur {
		case delegated:
			if err := checkDir(cur, uid, nil); err != nil {
				return 0, err
			}
		case path:
			if err := checkDir(cur, uid, resolve); err != nil {
				return 0, err
			}
		default:
			if err := checkDir(cur, -1, nil); err != nil {
				return 0, err
			}
		}
	}
	if _, err := os.Lstat(filepath.Join(path, "cgroup.controllers")); err != nil {
		return 0, fmt.Errorf("cgroup %s is not a cgroup v2 directory: %v", path, err)
	}
	populated, err := CgroupPopulated(path)
	if err != nil {
		return 0, err
	}
	if !populated {
		return 0, fmt.Errorf("cgroup %s has no processes", path)
	}
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return 0, err
	}
	return uint64(st.Ino), nil
}

// checkDir checks that path is a real directory and, when owner >= 0, that
// it is owned by owner (or, with resolve, by a uid that resolves to owner).
func checkDir(path string, owner int, resolve func(uid int) (int, error)) error {
	var st syscall.Stat_t
	if err := syscall.Lstat(path, &st); err != nil {
		return fmt.Errorf("cgroup path %s: %w", path, err)
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return fmt.Errorf("cgroup path %s is not a directory", path)
	}
	if owner < 0 || int(st.Uid) == owner {
		return nil
	}
	if resolve != nil {
		if o, err := resolve(int(st.Uid)); err == nil && o == owner {
			return nil
		}
	}
	return fmt.Errorf("cgroup %s is owned by uid %d, not by the caller (uid %d) or one of its subordinate uids", path, st.Uid, owner)
}

// CgroupPopulated reads cgroup.events: whether the cgroup or a descendant has
// processes.
func CgroupPopulated(path string) (bool, error) {
	data, err := os.ReadFile(filepath.Join(path, "cgroup.events"))
	if err != nil {
		return false, err
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		key, val, ok := strings.Cut(strings.TrimSpace(sc.Text()), " ")
		if ok && key == "populated" {
			return val == "1", nil
		}
	}
	return false, fmt.Errorf("%s/cgroup.events has no populated field", path)
}

// KillCgroup stops every process in the cgroup at path and its descendants:
// cgroup.kill (Linux 5.14+), else SIGKILL to each pid in every cgroup.procs,
// repeated so a process forked meanwhile is caught too. It is the fail-closed
// backstop when kernel enforcement can no longer be trusted (#193).
func KillCgroup(path string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("no cgroup to stop")
	}
	killErr := writeExisting(filepath.Join(path, "cgroup.kill"), "1")
	if killErr == nil {
		return nil
	}
	for pass := 0; pass < 10; pass++ {
		alive := 0
		walkErr := filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
			if err != nil || !d.IsDir() {
				return err
			}
			data, err := os.ReadFile(filepath.Join(p, "cgroup.procs"))
			if err != nil {
				return err
			}
			for _, f := range strings.Fields(string(data)) {
				pid, err := strconv.Atoi(f)
				if err != nil || pid <= 0 {
					continue // 0: a process outside this pid namespace
				}
				alive++
				_ = syscall.Kill(pid, syscall.SIGKILL)
			}
			return nil
		})
		if walkErr != nil {
			return fmt.Errorf("stop cgroup %s: cgroup.kill: %v; walking cgroup.procs: %w", path, killErr, walkErr)
		}
		if alive == 0 {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("stop cgroup %s: cgroup.kill: %v; processes still present after SIGKILL", path, killErr)
}

// writeExisting writes data to an existing file (a cgroup interface file is
// never created).
func writeExisting(path, data string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	_, werr := f.WriteString(data)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return werr
}

// CgroupID returns a cgroup directory's id (its inode number).
func CgroupID(path string) (uint64, error) {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return 0, err
	}
	return uint64(st.Ino), nil
}

// procCgroupPath returns the cgroup v2 path (relative to the cgroup root, with
// a leading slash) in a /proc/<pid>/cgroup document.
func procCgroupPath(data []byte) (string, error) {
	for _, line := range strings.Split(string(data), "\n") {
		if p, ok := strings.CutPrefix(strings.TrimSpace(line), "0::"); ok {
			return strings.TrimSpace(p), nil
		}
	}
	return "", errors.New("no cgroup v2 entry")
}

// within reports whether cgroup path p (absolute under root) is dir or below.
func within(p, dir string) bool {
	return p == dir || strings.HasPrefix(p, strings.TrimSuffix(dir, "/")+"/")
}

// SubIDOwner resolves a uid to the account that owns it: the uid itself, or,
// when it falls in a range of /etc/subuid, that range's owner. Rootless
// podman maps container root to the caller's uid by default, but to a
// subordinate uid in containers with their own user namespace (keep-id); only
// the owner (via newuidmap) or root can run processes as those. A uid that is
// itself an account (isAccount) is never remapped, so a subuid range that
// overlaps a real account (a misconfiguration) cannot make that account act
// as the range's owner.
func SubIDOwner(subuid []byte, uid int, isAccount func(uid int) bool, lookup func(name string) (int, error)) (int, error) {
	if isAccount != nil && isAccount(uid) {
		return uid, nil
	}
	sc := bufio.NewScanner(bytes.NewReader(subuid))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) != 3 {
			continue
		}
		start, err1 := strconv.ParseUint(parts[1], 10, 32)
		count, err2 := strconv.ParseUint(parts[2], 10, 32)
		if err1 != nil || err2 != nil || count == 0 {
			continue
		}
		if uint64(uid) >= start && uint64(uid) < start+count {
			if owner, err := strconv.Atoi(parts[0]); err == nil {
				return owner, nil
			}
			owner, err := lookup(parts[0])
			if err != nil {
				return 0, fmt.Errorf("uid %d is a subordinate uid of %q, which does not resolve: %w", uid, parts[0], err)
			}
			return owner, nil
		}
	}
	return uid, nil
}
