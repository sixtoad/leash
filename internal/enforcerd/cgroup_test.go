//go:build unix

package enforcerd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// cgroupTree builds <root>/user.slice/user-<uid>.slice/user@<uid>.service/
// user.slice/libpod-x.scope/container as a fake cgroup v2 tree owned by the
// test user, and returns the root and the container cgroup.
func cgroupTree(t *testing.T, uid int, populated bool) (string, string) {
	t.Helper()
	root := t.TempDir()
	target := filepath.Join(root, "user.slice", fmt.Sprintf("user-%d.slice", uid), fmt.Sprintf("user@%d.service", uid), "user.slice", "libpod-x.scope", "container")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	p := "0"
	if populated {
		p = "1"
	}
	for _, f := range []struct{ name, data string }{{"cgroup.controllers", "cpu memory pids\n"}, {"cgroup.events", "populated " + p + "\nfrozen 0\n"}} {
		if err := os.WriteFile(filepath.Join(target, f.name), []byte(f.data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root, target
}

func TestValidateTargetCgroupAcceptsOwnContainerCgroup(t *testing.T) {
	uid := os.Getuid()
	if uid == 0 {
		t.Skip("needs a non-root test user")
	}
	root, target := cgroupTree(t, uid, true)
	id, err := ValidateTargetCgroup(root, uid, target, nil)
	if err != nil {
		t.Fatalf("own container cgroup refused: %v", err)
	}
	want, _ := CgroupID(target)
	if id == 0 || id != want {
		t.Fatalf("cgroup id = %d, want the inode %d", id, want)
	}
}

func TestValidateTargetCgroupRefusals(t *testing.T) {
	uid := os.Getuid()
	if uid == 0 {
		t.Skip("needs a non-root test user")
	}
	root, target := cgroupTree(t, uid, true)
	delegated := filepath.Join(root, "user.slice", fmt.Sprintf("user-%d.slice", uid), fmt.Sprintf("user@%d.service", uid))
	other := uid + 1
	otherRoot, otherTarget := cgroupTree(t, other, true) // dirs named for another uid, owned by us

	link := filepath.Join(delegated, "user.slice", "evil.scope")
	if err := os.Symlink(filepath.Join(root, "user.slice"), link); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(delegated, "user.slice", "empty.scope")
	if err := os.MkdirAll(empty, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(empty, "cgroup.controllers"), nil, 0o644)
	_ = os.WriteFile(filepath.Join(empty, "cgroup.events"), []byte("populated 0\n"), 0o644)
	notCgroup := filepath.Join(delegated, "user.slice", "plain")
	_ = os.MkdirAll(notCgroup, 0o755)

	cases := []struct {
		name   string
		root   string
		uid    int
		path   string
		reason string
	}{
		{"root caller", root, 0, target, "root does not need"},
		{"relative path", root, uid, "user.slice/x", "not an absolute path"},
		{"unclean path", root, uid, target + "/../container", "not a clean path"},
		{"the delegated service itself", root, uid, delegated, "not inside your delegated cgroup subtree"},
		{"above the delegated subtree", root, uid, filepath.Dir(delegated), "not inside your delegated cgroup subtree"},
		{"another user's subtree", otherRoot, uid, otherTarget, "not inside your delegated cgroup subtree"},
		{"system cgroup", root, uid, filepath.Join(root, "system.slice"), "not inside your delegated cgroup subtree"},
		{"owned by someone else", otherRoot, other, otherTarget, "owned by uid"},
		{"symlinked component", root, uid, filepath.Join(link, "user-x.slice"), "not a directory"},
		{"not a cgroup", root, uid, notCgroup, "not a cgroup v2 directory"},
		{"no processes", root, uid, empty, "has no processes"},
		{"missing", root, uid, filepath.Join(delegated, "user.slice", "gone.scope"), "no such file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ValidateTargetCgroup(tc.root, tc.uid, tc.path, nil)
			if err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("ValidateTargetCgroup(%s) = %v, want an error containing %q", tc.path, err, tc.reason)
			}
		})
	}
}

// The target may be owned by a subordinate uid of the caller (crun creates a
// keep-id container's cgroup as container root); nothing else.
func TestCheckDirSubordinateOwner(t *testing.T) {
	dir := t.TempDir()
	me := os.Getuid()
	caller := me + 100000 // pretend the test user is a subordinate uid of "caller"
	toCaller := func(u int) (int, error) {
		if u == me {
			return caller, nil
		}
		return u, nil
	}
	if err := checkDir(dir, caller, toCaller); err != nil {
		t.Fatalf("subordinate-owned target refused: %v", err)
	}
	if err := checkDir(dir, caller, nil); err == nil {
		t.Fatal("without resolve a foreign owner must be refused")
	}
	toSomeoneElse := func(int) (int, error) { return caller + 1, nil }
	if err := checkDir(dir, caller, toSomeoneElse); err == nil {
		t.Fatal("a uid that resolves to another account must be refused")
	}
	failing := func(int) (int, error) { return 0, errors.New("boom") }
	if err := checkDir(dir, caller, failing); err == nil {
		t.Fatal("an unresolvable owner must be refused")
	}
}

func TestSubIDOwner(t *testing.T) {
	subuid := []byte("# comment\nagent:165536:65536\n1002:231072:65536\nbroken\nghost:300000:10\n")
	lookup := func(name string) (int, error) {
		if name == "agent" {
			return 1001, nil
		}
		return 0, errors.New("no such user")
	}
	accounts := map[int]bool{1001: true, 1002: true, 200000: true}
	isAccount := func(u int) bool { return accounts[u] }
	cases := []struct {
		uid, want int
		err       bool
	}{
		{1001, 1001, false},   // an account maps to itself
		{165536, 1001, false}, // first subordinate uid
		{231071, 1001, false}, // last subordinate uid of agent
		{231072, 1002, false}, // numeric owner
		{296608, 296608, false},
		{300005, 0, true},       // owner does not resolve
		{200000, 200000, false}, // an account inside a range stays itself (misconfiguration guard)
	}
	accounts[200000] = true
	for _, tc := range cases {
		got, err := SubIDOwner(subuid, tc.uid, isAccount, lookup)
		if (err != nil) != tc.err || (!tc.err && got != tc.want) {
			t.Errorf("SubIDOwner(%d) = %d, %v; want %d (err=%v)", tc.uid, got, err, tc.want, tc.err)
		}
	}
}

func TestProcCgroupPathAndWithin(t *testing.T) {
	p, err := procCgroupPath([]byte("1:name=systemd:/x\n0::/user.slice/a.scope\n"))
	if err != nil || p != "/user.slice/a.scope" {
		t.Fatalf("procCgroupPath = %q, %v", p, err)
	}
	if _, err := procCgroupPath([]byte("1:cpu:/x\n")); err == nil {
		t.Fatal("cgroup v1 only must be an error")
	}
	for _, tc := range []struct {
		p, dir string
		want   bool
	}{
		{"/a/b", "/a/b", true}, {"/a/b/c", "/a/b", true}, {"/a/bc", "/a/b", false}, {"/a", "/a/b", false}, {"/a/b/c", "/a/b/", true},
	} {
		if got := within(tc.p, tc.dir); got != tc.want {
			t.Errorf("within(%q, %q) = %v", tc.p, tc.dir, got)
		}
	}
}
