package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"
)

// installCAFlag is the internal sub-command leash-entry re-execs itself with
// under sudo when it is not running as root. The validated PEM is streamed on
// stdin and written to the destination given as the next argument.
const installCAFlag = "--install-ca"

// leashCAFileName is the file name of the Leash CA inside the distro's trust
// anchor directory.
const leashCAFileName = "leash-ca.crt"

// Bundle files the distro trust-store tools regenerate. Debian/Ubuntu/Alpine
// (update-ca-certificates) write the first; RHEL/Fedora (update-ca-trust)
// write the others.
var defaultCABundlePaths = []string{
	"/etc/ssl/certs/ca-certificates.crt",
	"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
	"/etc/pki/tls/certs/ca-bundle.crt",
}

// errCANotReady marks a read of the shared CA that may succeed on retry
// (empty, all-NUL, truncated or otherwise unparseable content).
var errCANotReady = errors.New("CA certificate not ready")

// validateCACert checks that data is a PEM-encoded X.509 CA certificate and
// returns the parsed certificate. Failures wrap errCANotReady so callers can
// distinguish "retry" from hard errors.
func validateCACert(data []byte) (*x509.Certificate, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: file is empty", errCANotReady)
	}
	if len(bytes.Trim(data, "\x00")) == 0 {
		// Signature of a sparse-aware copy over a share that misreports
		// extents (Docker Desktop VMM / virtiofs, see #169).
		return nil, fmt.Errorf("%w: file is %d NUL bytes", errCANotReady, len(data))
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%w: no PEM block found (%d bytes)", errCANotReady, len(data))
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%w: unexpected PEM block type %q", errCANotReady, block.Type)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: parse certificate: %v", errCANotReady, err)
	}
	if !cert.BasicConstraintsValid || !cert.IsCA {
		return nil, fmt.Errorf("certificate %q is not a CA certificate", cert.Subject.String())
	}
	return cert, nil
}

// readValidCACert reads path with plain read() calls (never via cp, whose
// SEEK_DATA/SEEK_HOLE path yields NULs on virtiofs) and validates it, retrying
// with bounded exponential backoff while the content is not yet valid.
func readValidCACert(path string, attempts int, initialDelay, maxDelay time.Duration, sleep func(time.Duration)) ([]byte, *x509.Certificate, error) {
	if attempts < 1 {
		attempts = 1
	}
	delay := initialDelay
	var lastErr error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			sleep(delay)
			delay *= 2
			if delay > maxDelay {
				delay = maxDelay
			}
		}
		data, err := os.ReadFile(path)
		if err != nil {
			lastErr = fmt.Errorf("%w: read %s: %v", errCANotReady, path, err)
			continue
		}
		cert, err := validateCACert(data)
		if err == nil {
			return data, cert, nil
		}
		lastErr = err
		if !errors.Is(err, errCANotReady) {
			return nil, nil, err
		}
	}
	return nil, nil, fmt.Errorf("after %d attempts: %w", attempts, lastErr)
}

// writeFileAtomic writes data to path via a PID-suffixed temp file in the same
// directory, fsyncs it and renames it into place. It avoids O_EXCL (rejected by
// Docker Desktop file sharing, see #73) and sets perm explicitly so the umask
// does not apply.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmpName := fmt.Sprintf("%s.%d.tmp", path, os.Getpid())
	tmp, err := os.OpenFile(tmpName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	fail := func(stage string, err error) error {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("%s: %w", stage, err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fail("write", err)
	}
	if err := tmp.Chmod(perm); err != nil {
		return fail("chmod", err)
	}
	if err := tmp.Sync(); err != nil {
		return fail("sync", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("close: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// installCAAnchor validates data and writes it atomically to dest. It is the
// body of both the root path and the sudo re-exec sub-command.
func installCAAnchor(dest string, data []byte) error {
	if _, err := validateCACert(data); err != nil {
		return err
	}
	if err := writeFileAtomic(dest, data, 0o644); err != nil {
		return err
	}
	return verifyFileContent(dest, data)
}

// verifyFileContent re-reads path and checks it is byte-identical to want.
func verifyFileContent(path string, want []byte) error {
	got, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("re-read %s: %w", path, err)
	}
	if !bytes.Equal(got, want) {
		return fmt.Errorf("%s does not match the Leash CA (%d bytes installed, %d expected)", path, len(got), len(want))
	}
	return nil
}

// bundleContainsCert reports whether the PEM bundle at path contains cert.
func bundleContainsCert(path string, cert *x509.Certificate) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return false, nil
		}
		if block.Type == "CERTIFICATE" && bytes.Equal(block.Bytes, cert.Raw) {
			return true, nil
		}
	}
}

// verifyTrustBundle checks that at least one existing distro bundle contains
// cert and returns the bundles it read. If none of the candidate bundles exist
// it returns (nil, nil): the anchor file itself has already been verified.
func verifyTrustBundle(paths []string, cert *x509.Certificate) (checked []string, err error) {
	for _, p := range paths {
		found, err := bundleContainsCert(p, cert)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return checked, fmt.Errorf("read bundle %s: %w", p, err)
		}
		checked = append(checked, p)
		if found {
			return checked, nil
		}
	}
	if len(checked) == 0 {
		return nil, nil
	}
	return checked, fmt.Errorf("Leash CA is missing from the system trust bundle (checked %v)", checked)
}

// runInstallCASubcommand implements `leash-entry --install-ca <dest>`: the PEM
// arrives on stdin and is validated and written atomically.
func runInstallCASubcommand(dest string, stdin io.Reader) error {
	data, err := io.ReadAll(io.LimitReader(stdin, 1<<20))
	if err != nil {
		return fmt.Errorf("read CA from stdin: %w", err)
	}
	return installCAAnchor(dest, data)
}

// installCAViaSudo re-execs this binary under sudo to write the anchor, so the
// copy goes through Go read()/write() rather than `sudo cp`.
func installCAViaSudo(dest string, data []byte) error {
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate leash-entry executable: %w", err)
	}
	cmd := exec.Command("sudo", self, installCAFlag, dest)
	cmd.Stdin = bytes.NewReader(data)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("sudo %s %s %s: %w", self, installCAFlag, dest, err)
	}
	return verifyFileContent(dest, data)
}

// runTrustUpdate regenerates the system bundle. For update-ca-certificates it
// first tries --fresh so the hash symlinks are rebuilt even when a previous
// (possibly corrupt) leash-ca.crt existed, falling back to a plain run for
// implementations that do not accept the flag.
func runTrustUpdate(updateCommand string, asRoot bool) error {
	run := func(args ...string) error {
		var cmd *exec.Cmd
		if asRoot {
			cmd = exec.Command(args[0], args[1:]...)
		} else {
			cmd = exec.Command("sudo", args...)
		}
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}
	if updateCommand == "update-ca-certificates" {
		if err := run(updateCommand, "--fresh"); err == nil {
			return nil
		}
		os.Stderr.WriteString("leash-entry: update-ca-certificates --fresh failed; retrying without --fresh\n")
	}
	return run(updateCommand)
}
