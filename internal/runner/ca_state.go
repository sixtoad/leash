package runner

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// caKeyPath is where leashd keeps the CA private key: the 0700 private dir,
// which the workload never sees.
func caKeyPath(privateDir string) string { return filepath.Join(privateDir, "ca-key.pem") }

// reconcileCAState gives the leash CA certificate (share dir, readable by the
// workload) and its private key (private dir, 0700) a single lifetime before
// leashd starts (#165).
//
// The two directories can have different lifetimes: a reused LEASH_SHARE_DIR
// keeps the previous run's ca-cert.pem while the matching key lived in that
// run's per-run private dir, which is gone. leashd then refuses with
// "incomplete certificate authority state" and the run never starts. So:
//
//   - cert and key both present and matching: keep them (leashd restores the CA);
//   - only one present, or they do not match, or either is unreadable: remove
//     both, and leashd generates a fresh pair (it writes each file atomically);
//   - a legacy key in the share dir is always removed: it would be readable by
//     the workload, and the CA it belongs to is being replaced anyway.
//
// The key is only ever read here (to compare it with the certificate); it is
// never copied, moved or re-permissioned. It returns the paths it removed; a
// failure to remove a stale file is fatal, since leashd would refuse anyway.
func reconcileCAState(shareDir, privateDir string) ([]string, error) {
	shareDir, privateDir = strings.TrimSpace(shareDir), strings.TrimSpace(privateDir)
	if shareDir == "" || privateDir == "" {
		return nil, nil
	}
	certPath, keyPath := caCertPath(shareDir), caKeyPath(privateDir)
	legacyKey := filepath.Join(shareDir, "ca-key.pem")

	var stale []string
	if exists(legacyKey) {
		stale = append(stale, legacyKey)
	}
	certOK, keyOK := exists(certPath), exists(keyPath)
	switch {
	case certOK && keyOK:
		if !caPairMatches(certPath, keyPath) {
			stale = append(stale, certPath, keyPath)
		}
	case certOK:
		stale = append(stale, certPath)
	case keyOK:
		stale = append(stale, keyPath)
	}
	var removed []string
	for _, p := range stale {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return removed, fmt.Errorf("remove stale CA file %s: %w", p, err)
		}
		removed = append(removed, p)
	}
	return removed, nil
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// caPairMatches reports whether the PEM certificate at certPath is for the
// PKCS#1 RSA key at keyPath (the formats leashd writes).
func caPairMatches(certPath, keyPath string) bool {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return false
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return false
	}
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return false
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return false
	}
	key, err := x509.ParsePKCS1PrivateKey(kb.Bytes)
	if err != nil {
		return false
	}
	return key.PublicKey.Equal(cert.PublicKey)
}

// removeOrphanedCACert removes the CA certificate from a share dir that
// outlives this run (LEASH_SHARE_DIR) when the run's private dir — and with it
// the key — is being removed, so the next run does not find a certificate
// without its key (#165).
func removeOrphanedCACert(shareDir, privateDir string) {
	if strings.TrimSpace(shareDir) == "" || strings.TrimSpace(privateDir) == "" {
		return
	}
	if !exists(caKeyPath(privateDir)) {
		_ = os.Remove(caCertPath(shareDir))
	}
}
