//go:build darwin

package darwind

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// trustTestRoot makes checkPolicyPathSafe stop its ancestor walk at the
// test's temporary root: a developer's TMPDIR may live below a directory other
// users can write to, which the check rightly refuses.
func trustTestRoot(t *testing.T, dir string) {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	orig := policyPathTrustedFloor
	policyPathTrustedFloor = resolved
	t.Cleanup(func() { policyPathTrustedFloor = orig })
}

func privateTestDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	trustTestRoot(t, dir)
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestEnsurePolicyFileCreatesPrivateDefault(t *testing.T) {
	path := filepath.Join(privateTestDir(t), "policy.cedar")
	if err := ensurePolicyFile(path); err != nil {
		t.Fatalf("ensurePolicyFile: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("default policy mode = %04o, want 0600", perm)
	}
	data, err := os.ReadFile(path)
	if err != nil || len(strings.TrimSpace(string(data))) == 0 {
		t.Fatalf("default policy not written: %v %q", err, data)
	}
	// An existing safe file is kept as is.
	if err := os.WriteFile(path, []byte("// mine\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ensurePolicyFile(path); err != nil {
		t.Fatalf("existing file: %v", err)
	}
	if data, _ := os.ReadFile(path); string(data) != "// mine\n" {
		t.Fatalf("existing policy overwritten: %q", data)
	}
}

func TestCheckPolicyPathSafeRefusesUnsafePaths(t *testing.T) {
	dir := privateTestDir(t)

	target := filepath.Join(dir, "real.cedar")
	if err := os.WriteFile(target, []byte("// p\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.cedar")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := checkPolicyPathSafe(link); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlinked policy accepted: %v", err)
	}
	if err := ensurePolicyFile(link); err == nil {
		t.Fatal("ensurePolicyFile followed a symlink")
	}

	loose := filepath.Join(dir, "loose.cedar")
	if err := os.WriteFile(loose, []byte("// p\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := checkPolicyPathSafe(loose); err == nil || !strings.Contains(err.Error(), "writable by other users") {
		t.Fatalf("world-writable policy accepted: %v", err)
	}

	open := filepath.Join(dir, "open")
	if err := os.Mkdir(open, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := checkPolicyPathSafe(filepath.Join(open, "policy.cedar")); err == nil || !strings.Contains(err.Error(), "writable by other users") {
		t.Fatalf("policy in a world-writable directory accepted: %v", err)
	}
	if err := ensurePolicyFile(filepath.Join(open, "policy.cedar")); err == nil {
		t.Fatal("default policy created in a world-writable directory")
	}
	if _, err := os.Stat(filepath.Join(open, "policy.cedar")); !os.IsNotExist(err) {
		t.Fatalf("refused path was created anyway: %v", err)
	}

	// A sticky world-writable directory (like /private/tmp) is acceptable when
	// the entry in it is ours and not writable by others: the sticky bit keeps
	// other users from replacing it.
	sticky := filepath.Join(dir, "sticky")
	if err := os.Mkdir(sticky, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sticky, 0o777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	mine := filepath.Join(sticky, "policy.cedar")
	if err := os.WriteFile(mine, []byte("// p\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := checkPolicyPathSafe(mine); err != nil {
		t.Fatalf("own file in a sticky directory refused: %v", err)
	}

	if err := checkPolicyPathSafe(""); err == nil {
		t.Fatal("empty path accepted")
	}
}

func TestDefaultDarwinPolicyPathIsInPrivateStateDir(t *testing.T) {
	state := filepath.Join(privateTestDir(t), "state")
	t.Setenv("LEASH_DARWIN_STATE_DIR", state)
	got, err := defaultDarwinPolicyPath()
	if err != nil {
		t.Fatal(err)
	}
	if got != filepath.Join(state, policyFilename) {
		t.Fatalf("default policy path = %q", got)
	}
	info, err := os.Stat(state)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Fatalf("state dir mode = %04o, want 0700", perm)
	}
	if strings.HasPrefix(got, "/tmp/") || strings.HasPrefix(got, "/private/tmp/") {
		t.Fatalf("default policy path is in /tmp: %q", got)
	}
}

func TestSecureStateDirRepairsLooseOwnDirectory(t *testing.T) {
	dir := filepath.Join(privateTestDir(t), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := secureStateDir(dir); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(dir)
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Fatalf("state dir mode = %04o after repair, want 0700", perm)
	}
}

func TestWithEnvReplacesExistingKey(t *testing.T) {
	got := withEnv([]string{"A=1", "LEASH_POLICY=/tmp/tmp.leash.policy", "B=2"}, "LEASH_POLICY", "/safe/p.cedar")
	n := 0
	for _, kv := range got {
		if strings.HasPrefix(kv, "LEASH_POLICY=") {
			n++
			if kv != "LEASH_POLICY=/safe/p.cedar" {
				t.Fatalf("LEASH_POLICY = %q", kv)
			}
		}
	}
	if n != 1 {
		t.Fatalf("LEASH_POLICY entries = %d, want 1: %v", n, got)
	}
}
