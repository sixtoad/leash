package lsm_test

import (
	"testing"

	"github.com/strongdm/leash/internal/lsm"
)

// TestKernelWriteForbidSealsAServiceSocketDirectory pins what a caller that
// injects a service socket relies on (sixto/walk#281): a FileOpenReadWrite
// forbid on the socket's directory, plus an exact forbid on each ancestor,
// compiles to a mutation table that denies every way a box process could
// replace the socket — unlink or rename it, bind a new socket or create any
// other entry beside it, rename or remove the directory, or rename an
// ancestor away and rebuild the path — while the rest of a writable /tmp
// stays writable. Connecting to the socket is not a mutation and is not
// decided here.
func TestKernelWriteForbidSealsAServiceSocketDirectory(t *testing.T) {
	t.Parallel()
	const policy = `@leash_semantics("cedar")
permit (principal, action in [Action::"FileOpen", Action::"FileOpenReadOnly"], resource in Dir::"/");
permit (principal, action == Action::"FileOpenReadWrite", resource in Dir::"/tmp/");
permit (principal, action == Action::"FileOpenReadWrite", resource in Dir::"/home/u/tmp/");
forbid (principal, action == Action::"FileOpenReadWrite", resource)
when { resource in [ Dir::"/tmp/walk-svc-r1/", Dir::"/home/u/tmp/walk-git-r1/" ] };
forbid (principal, action == Action::"FileOpenReadWrite", resource)
when { resource in [ File::"/tmp", File::"/home", File::"/home/u", File::"/home/u/tmp" ] };
`
	eng, ir, _, err := compileStrict(t, policy)
	if err != nil {
		t.Fatal(err)
	}
	k, err := lsm.NewKernelForTest(ir)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		path  string
		allow bool
	}{
		{"/tmp/walk-svc-r1/svc.sock", false},    // unlink / rename the socket, bind over it
		{"/tmp/walk-svc-r1/forged.sock", false}, // bind a second socket
		{"/tmp/walk-svc-r1/x/y", false},         // anything below
		{"/tmp/walk-svc-r1", false},             // rename / rmdir the directory itself
		{"/tmp", false},                         // rename the parent away
		{"/home/u/tmp/walk-git-r1/git.sock", false},
		{"/home/u/tmp/walk-git-r1", false},
		{"/home/u/tmp", false}, // a user-owned TMPDIR: renaming it would free the path
		{"/home/u", false},
		{"/home", false},
		{"/tmp/walk-svc-r1x", true}, // a sibling with the same prefix stays writable
		{"/tmp/other.sock", true},
		{"/home/u/tmp/scratch", true},
	} {
		if got := k.Mutation(c.path); got != c.allow {
			t.Errorf("kernel mutation %q = %v, want %v (rules %v)", c.path, got, c.allow, ruleStrings(ir.Open))
		}
		if got := eng.DecideMutation(c.path).Allow; got != c.allow {
			t.Errorf("cedar mutation %q = %v, want %v", c.path, got, c.allow)
		}
	}
	// The socket is still openable read-only (stat, path resolution).
	if !k.Open("/tmp/walk-svc-r1/svc.sock", lsm.OpOpenRO) {
		t.Errorf("read-only open of the socket path denied")
	}
}
