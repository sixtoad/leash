package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func makeCertPEM(t *testing.T, isCA bool) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "leash test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestValidateCACert(t *testing.T) {
	t.Parallel()
	valid := makeCertPEM(t, true)

	cases := []struct {
		name      string
		data      []byte
		wantErr   string
		retryable bool
	}{
		{name: "valid", data: valid},
		{name: "empty", data: nil, wantErr: "empty", retryable: true},
		// The exact #169 symptom: same size as the real cert, all NUL.
		{name: "all NUL", data: make([]byte, len(valid)), wantErr: "NUL bytes", retryable: true},
		{name: "truncated", data: valid[:len(valid)/2], wantErr: "", retryable: true},
		{name: "garbage", data: []byte("not a certificate\n"), wantErr: "no PEM block", retryable: true},
		{name: "wrong PEM type", data: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte{1, 2, 3}}), wantErr: "unexpected PEM block type", retryable: true},
		{name: "bad DER", data: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}}), wantErr: "parse certificate", retryable: true},
		{name: "leaf not CA", data: makeCertPEM(t, false), wantErr: "not a CA", retryable: false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cert, err := validateCACert(tc.data)
			if tc.name == "valid" {
				if err != nil || cert == nil {
					t.Fatalf("valid cert rejected: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
			if tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not mention %q", err, tc.wantErr)
			}
			if got := errors.Is(err, errCANotReady); got != tc.retryable {
				t.Fatalf("retryable = %v, want %v (err %v)", got, tc.retryable, err)
			}
		})
	}
}

func TestReadValidCACertRetriesUntilValid(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "ca-cert.pem")
	valid := makeCertPEM(t, true)
	if err := os.WriteFile(path, make([]byte, len(valid)), 0o644); err != nil {
		t.Fatal(err)
	}

	var sleeps []time.Duration
	sleep := func(d time.Duration) {
		sleeps = append(sleeps, d)
		switch len(sleeps) {
		case 1:
			_ = os.WriteFile(path, nil, 0o644) // empty
		case 2:
			_ = os.WriteFile(path, valid[:40], 0o644) // truncated
		case 3:
			_ = os.WriteFile(path, valid, 0o644)
		}
	}
	data, cert, err := readValidCACert(path, 8, 10*time.Millisecond, 25*time.Millisecond, sleep)
	if err != nil {
		t.Fatalf("readValidCACert: %v", err)
	}
	if !bytes.Equal(data, valid) || cert == nil {
		t.Fatalf("unexpected result")
	}
	want := []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 25 * time.Millisecond}
	if len(sleeps) != len(want) {
		t.Fatalf("sleeps = %v, want %v", sleeps, want)
	}
	for i := range want {
		if sleeps[i] != want[i] {
			t.Fatalf("sleeps = %v, want %v (bounded exponential backoff)", sleeps, want)
		}
	}
}

func TestReadValidCACertGivesUpOnPersistentNUL(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "ca-cert.pem")
	if err := os.WriteFile(path, make([]byte, 1277), 0o644); err != nil {
		t.Fatal(err)
	}
	calls := 0
	_, _, err := readValidCACert(path, 4, time.Millisecond, time.Millisecond, func(time.Duration) { calls++ })
	if err == nil {
		t.Fatal("expected failure for persistent all-NUL file")
	}
	if calls != 3 {
		t.Fatalf("slept %d times, want 3 for 4 attempts", calls)
	}
	if !strings.Contains(err.Error(), "after 4 attempts") || !strings.Contains(err.Error(), "NUL") {
		t.Fatalf("error should name attempts and NUL cause: %v", err)
	}
}

func TestReadValidCACertNonCAIsNotRetried(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "ca-cert.pem")
	if err := os.WriteFile(path, makeCertPEM(t, false), 0o644); err != nil {
		t.Fatal(err)
	}
	calls := 0
	_, _, err := readValidCACert(path, 5, time.Millisecond, time.Millisecond, func(time.Duration) { calls++ })
	if err == nil || calls != 0 {
		t.Fatalf("non-CA should fail immediately; err=%v sleeps=%d", err, calls)
	}
}

func TestInstallCAAnchorAtomic(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	dest := filepath.Join(dir, leashCAFileName)
	valid := makeCertPEM(t, true)

	// A stale (corrupt) anchor from a previous run must be replaced.
	if err := os.WriteFile(dest, make([]byte, len(valid)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := installCAAnchor(dest, valid); err != nil {
		t.Fatalf("installCAAnchor: %v", err)
	}
	got, err := os.ReadFile(dest)
	if err != nil || !bytes.Equal(got, valid) {
		t.Fatalf("installed content mismatch: %v", err)
	}
	info, err := os.Stat(dest)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("mode = %v, want 0644", info.Mode().Perm())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("temp file left behind: %v", entries)
	}
}

func TestInstallCAAnchorRejectsInvalidWithoutTouchingDest(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	dest := filepath.Join(dir, leashCAFileName)
	if err := installCAAnchor(dest, make([]byte, 64)); err == nil {
		t.Fatal("expected all-NUL input to be rejected")
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatalf("dest should not be created for invalid input: %v", err)
	}
}

func TestRunInstallCASubcommandReadsStdin(t *testing.T) {
	t.Parallel()
	dest := filepath.Join(t.TempDir(), leashCAFileName)
	valid := makeCertPEM(t, true)
	if err := runInstallCASubcommand(dest, bytes.NewReader(valid)); err != nil {
		t.Fatalf("runInstallCASubcommand: %v", err)
	}
	if err := verifyFileContent(dest, valid); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyTrustBundle(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	caPEM := makeCertPEM(t, true)
	cert, err := validateCACert(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	other := makeCertPEM(t, true)

	missing := filepath.Join(dir, "missing.crt")
	without := filepath.Join(dir, "without.crt")
	with := filepath.Join(dir, "with.crt")
	if err := os.WriteFile(without, other, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(with, append(append([]byte{}, other...), caPEM...), 0o644); err != nil {
		t.Fatal(err)
	}

	if checked, err := verifyTrustBundle([]string{missing, with}, cert); err != nil || len(checked) != 1 {
		t.Fatalf("bundle containing CA should pass: checked=%v err=%v", checked, err)
	}
	if _, err := verifyTrustBundle([]string{missing, without}, cert); err == nil {
		t.Fatal("bundle lacking CA must fail (silent update-ca-certificates skip, #169)")
	}
	if checked, err := verifyTrustBundle([]string{without, with}, cert); err != nil || len(checked) != 2 {
		t.Fatalf("any existing bundle containing CA should pass: checked=%v err=%v", checked, err)
	}
	if checked, err := verifyTrustBundle([]string{missing}, cert); err != nil || checked != nil {
		t.Fatalf("no bundles present should skip: checked=%v err=%v", checked, err)
	}
}
