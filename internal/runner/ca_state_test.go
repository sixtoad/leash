package runner

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/strongdm/leash/internal/proxy"
)

// leashdCA runs leashd's real CA bootstrap against share/private dirs.
func leashdCA(t *testing.T, share, private string) error {
	t.Helper()
	t.Setenv("LEASH_DIR", share)
	t.Setenv("LEASH_PRIVATE_DIR", private)
	_, err := proxy.NewCertificateAuthority()
	return err
}

func mkPrivate(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

// A reused share dir keeps run 1's certificate while run 1's private dir (and
// key) is gone. Without reconciling, leashd refuses ("incomplete certificate
// authority state"); with it, run 2 gets a fresh pair (#165).
func TestCAShareDirReuseAcrossRuns(t *testing.T) {
	share := t.TempDir()
	priv1 := mkPrivate(t)
	if err := leashdCA(t, share, priv1); err != nil {
		t.Fatalf("run 1: %v", err)
	}
	cert1, _ := os.ReadFile(caCertPath(share))
	_ = os.RemoveAll(priv1) // run 1's per-run private dir goes away

	priv2 := mkPrivate(t)
	if err := leashdCA(t, share, priv2); err == nil || !strings.Contains(err.Error(), "incomplete certificate authority state") {
		t.Fatalf("precondition: leashd should refuse the orphaned cert, got %v", err)
	}
	removed, err := reconcileCAState(share, priv2)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 1 || removed[0] != caCertPath(share) {
		t.Fatalf("removed %v, want only the orphaned cert", removed)
	}
	if err := leashdCA(t, share, priv2); err != nil {
		t.Fatalf("run 2 after reconcile: %v", err)
	}
	cert2, _ := os.ReadFile(caCertPath(share))
	if bytes.Equal(cert1, cert2) {
		t.Fatal("run 2 must get a fresh CA, not run 1's certificate")
	}
	if info, err := os.Stat(caKeyPath(priv2)); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("key must stay 0600 in the private dir: %v %v", info, err)
	}
	if _, err := os.Stat(filepath.Join(share, "ca-key.pem")); !os.IsNotExist(err) {
		t.Fatal("the key must never land in the share dir")
	}
}

// A matching pair with the same lifetime is kept, so leashd restores it.
func TestCAMatchingPairKept(t *testing.T) {
	share, priv := t.TempDir(), mkPrivate(t)
	if err := leashdCA(t, share, priv); err != nil {
		t.Fatal(err)
	}
	cert1, _ := os.ReadFile(caCertPath(share))
	removed, err := reconcileCAState(share, priv)
	if err != nil || len(removed) != 0 {
		t.Fatalf("matching pair: removed=%v err=%v", removed, err)
	}
	if err := leashdCA(t, share, priv); err != nil {
		t.Fatal(err)
	}
	cert2, _ := os.ReadFile(caCertPath(share))
	if !bytes.Equal(cert1, cert2) {
		t.Fatal("a matching pair should be restored, not regenerated")
	}
}

// A mismatched pair, a key without its cert and a legacy key in the share dir
// are all removed.
func TestCAStaleStatesRemoved(t *testing.T) {
	shareA, privA := t.TempDir(), mkPrivate(t)
	shareB, privB := t.TempDir(), mkPrivate(t)
	if err := leashdCA(t, shareA, privA); err != nil {
		t.Fatal(err)
	}
	if err := leashdCA(t, shareB, privB); err != nil {
		t.Fatal(err)
	}
	// Mismatch: A's cert with B's key.
	removed, err := reconcileCAState(shareA, privB)
	if err != nil || len(removed) != 2 {
		t.Fatalf("mismatch: removed=%v err=%v", removed, err)
	}
	if err := leashdCA(t, shareA, privB); err != nil {
		t.Fatalf("after mismatch reconcile: %v", err)
	}

	// Key without cert.
	_ = os.Remove(caCertPath(shareA))
	removed, err = reconcileCAState(shareA, privB)
	if err != nil || len(removed) != 1 || removed[0] != caKeyPath(privB) {
		t.Fatalf("key-only: removed=%v err=%v", removed, err)
	}

	// Legacy key in the (workload-readable) share dir.
	legacy := filepath.Join(shareB, "ca-key.pem")
	if err := os.WriteFile(legacy, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := reconcileCAState(shareB, privB); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatal("legacy share-dir key must be removed")
	}
}

// At the end of a run the cert is removed from a reused share dir once the
// private dir (and key) is gone.
func TestRemoveOrphanedCACert(t *testing.T) {
	share, priv := t.TempDir(), mkPrivate(t)
	if err := leashdCA(t, share, priv); err != nil {
		t.Fatal(err)
	}
	removeOrphanedCACert(share, priv)
	if _, err := os.Stat(caCertPath(share)); err != nil {
		t.Fatal("cert removed while its key still exists")
	}
	_ = os.RemoveAll(priv)
	removeOrphanedCACert(share, priv)
	if _, err := os.Stat(caCertPath(share)); !os.IsNotExist(err) {
		t.Fatal("orphaned cert left in the reused share dir")
	}
}
