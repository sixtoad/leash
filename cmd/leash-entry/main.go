package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/strongdm/leash/internal/entrypoint"
)

const (
	shareRoot      = "/leash"
	readyFilePath  = shareRoot + "/" + entrypoint.ReadyFileName
	cgroupPathFile = shareRoot + "/cgroup-path"
	selfCgroupPath = "/proc/self/cgroup"
	bootstrapPath  = shareRoot + "/" + entrypoint.BootstrapReadyFileName
	caCertPath     = shareRoot + "/ca-cert.pem"

	// Bounded retry while the shared CA is present but not yet valid
	// (~10s total with these values).
	caReadAttempts     = 8
	caReadInitialDelay = 250 * time.Millisecond
	caReadMaxDelay     = 2 * time.Second
)

func main() {
	if len(os.Args) == 3 && os.Args[1] == "--resolve-identity" {
		if err := printResolvedIdentity(os.Args[2]); err != nil {
			os.Stderr.WriteString("leash-error: resolve identity: " + err.Error() + "\n")
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 3 && os.Args[1] == installCAFlag {
		if err := runInstallCASubcommand(os.Args[2], os.Stdin); err != nil {
			os.Stderr.WriteString("leash-error: install CA certificate: " + err.Error() + "\n")
			os.Exit(1)
		}
		return
	}
	_ = os.Remove(bootstrapPath)

	for {
		if _, err := os.Stat(readyFilePath); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Check for /leash root directory
	if _, err := os.Stat(shareRoot); os.IsNotExist(err) {
		os.Stderr.WriteString("leash-error: /leash root directory does not exist\n")
		os.Exit(1)
	}

	if err := emitCgroupPath(); err != nil {
		os.Stderr.WriteString("leash-error: failed to record cgroup path: " + err.Error() + "\n")
		os.Exit(1)
	}

	// Check if running as root
	if os.Geteuid() != 0 {
		// Check if sudo is available
		if _, err := exec.LookPath("sudo"); err != nil {
			os.Stderr.WriteString(nonRootBootstrapError(os.Geteuid()) + "\n")
			os.Exit(1)
		}
	}

	// Check if update-ca-certificates/update-ca-trust is available
	var updateCommand string = "update-ca-certificates"
	var certBasePath string = "/usr/local/share/ca-certificates"
	if _, err := exec.LookPath("update-ca-certificates"); err != nil {
		if _, err := exec.LookPath("update-ca-trust"); err != nil {
			os.Stderr.WriteString("leash-error: update-ca-trust or update-ca-certificates not found\n")
			os.Exit(1)
		}
		updateCommand = "update-ca-trust"
		certBasePath = "/etc/pki/ca-trust/source/anchors"
	}

	os.Stderr.WriteString("leash-entry: waiting for leash certificate\n")

	// Poll for CA certificate
	caCertFile := caCertPath
	for {
		if _, err := os.Stat(caCertFile); err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	// Read and validate the CA in Go. Never copy it with cp: on Docker
	// Desktop's VMM/virtiofs share the file reports st_blocks == 0 and
	// SEEK_DATA == EOF, so coreutils' sparse-aware copy writes a same-sized
	// run of NUL bytes that update-ca-certificates silently skips (#169).
	os.Stderr.WriteString("leash-entry: installing CA certificate\n")
	caData, caCert, err := readValidCACert(caCertFile, caReadAttempts, caReadInitialDelay, caReadMaxDelay, time.Sleep)
	if err != nil {
		os.Stderr.WriteString("leash-error: " + caCertFile + " is not a valid PEM CA certificate: " + err.Error() + "\n")
		os.Exit(1)
	}
	anchorPath := filepath.Join(certBasePath, leashCAFileName)
	asRoot := os.Geteuid() == 0
	if asRoot {
		err = installCAAnchor(anchorPath, caData)
	} else {
		err = installCAViaSudo(anchorPath, caData)
	}
	if err != nil {
		os.Stderr.WriteString("leash-error: failed to install CA certificate to " + anchorPath + ": " + err.Error() + "\n")
		os.Exit(1)
	}

	os.Stderr.WriteString("leash-entry: updating CA certificates\n")
	if err := runTrustUpdate(updateCommand, asRoot); err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
		os.Stderr.WriteString("leash-error: failed to update CA certificates\n")
		os.Exit(1)
	}

	// Only signal bootstrap once the regenerated bundle really trusts the CA;
	// a silent skip here would leave every TLS client in the container broken.
	checked, err := verifyTrustBundle(defaultCABundlePaths, caCert)
	if err != nil {
		os.Stderr.WriteString("leash-error: " + err.Error() + "\n")
		os.Exit(1)
	}
	if len(checked) == 0 {
		os.Stderr.WriteString("leash-entry: WARNING: no known CA bundle found; verified only " + anchorPath + "\n")
	}

	if err := writeBootstrapMarker(); err != nil {
		os.Stderr.WriteString("leash-error: failed to signal bootstrap completion: " + err.Error() + "\n")
		os.Exit(1)
	}

	// Get command arguments (skip the program name)
	targetArgs := resolveTargetArgs(os.Args[1:])

	// If no arguments provided, exit
	if len(targetArgs) == 0 {
		runIdleLoop()
		return
	}

	os.Stderr.WriteString("leash-entry: command exec\n")

	// Resolve the executable path
	execPath, err := exec.LookPath(targetArgs[0])
	if err != nil {
		os.Stderr.WriteString("leash-error: failed to find executable: " + err.Error() + "\n")
		os.Exit(1)
	}
	targetArgs[0] = execPath

	// Use syscall.Exec to replace current process with the target command
	err = syscall.Exec(targetArgs[0], targetArgs, os.Environ())
	if err != nil {
		os.Stderr.WriteString("leash-error: failed to exec: " + err.Error() + "\n")
		os.Exit(1)
	}
}

// nonRootBootstrapError explains a bootstrap that is not running as container
// root (#121). Leash always starts the target with --user 0 so the CA can be
// installed into the image's trust store before the workload runs as the image
// user; reaching this means something overrode that.
func nonRootBootstrapError(euid int) string {
	return fmt.Sprintf("leash-error: leash-entry is running as uid %d, not as container root, and sudo is not available: "+
		"the bootstrap (installing the leash CA into the image trust store) needs container root. "+
		"Leash starts the target with --user 0; check for a runtime setting that overrides it "+
		"(for example a containers.conf [containers] user/userns entry, or a wrapper passing --user)", euid)
}

func printResolvedIdentity(raw string) error {
	userPart, groupPart, _ := strings.Cut(raw, ":")
	var account *user.User
	var err error
	if _, parseErr := strconv.ParseUint(userPart, 10, 32); parseErr == nil {
		account, err = user.LookupId(userPart)
	} else {
		account, err = user.Lookup(userPart)
	}
	if err != nil {
		return err
	}
	uid64, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil {
		return fmt.Errorf("invalid uid %q", account.Uid)
	}
	gidText := account.Gid
	if groupPart != "" {
		if _, parseErr := strconv.ParseUint(groupPart, 10, 32); parseErr == nil {
			gidText = groupPart
		} else {
			group, lookupErr := user.LookupGroup(groupPart)
			if lookupErr != nil {
				return lookupErr
			}
			gidText = group.Gid
		}
	}
	gid64, err := strconv.ParseUint(gidText, 10, 32)
	if err != nil {
		return fmt.Errorf("invalid gid %q", gidText)
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"uid": uint32(uid64), "gid": uint32(gid64), "home": account.HomeDir})
}

func resolveTargetArgs(fallback []string) []string {
	if raw := strings.TrimSpace(os.Getenv("LEASH_ENTRY_COMMAND_B64")); raw != "" {
		decoded, err := base64.StdEncoding.DecodeString(raw)
		if err == nil {
			var parts []string
			if json.Unmarshal(decoded, &parts) == nil && len(parts) > 0 {
				return parts
			}
		}
	}
	return fallback
}

func runIdleLoop() {
	// Stay idle inside this process so policy rules that deny shell binaries do
	// not terminate the container.
	os.Stderr.WriteString("leash-entry: entering idle wait\n")
	for {
		time.Sleep(24 * time.Hour)
	}
}

func writeBootstrapMarker() error {
	host, _ := os.Hostname()
	payload := map[string]any{
		"pid":       os.Getpid(),
		"hostname":  host,
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal bootstrap payload: %w", err)
	}
	data = append(data, '\n')

	return writeMarkerAtomic(bootstrapPath, data)
}

// writeMarkerAtomic writes data to path via a temp file + rename so a reader
// never observes a partial marker.
//
// It deliberately avoids os.CreateTemp: that opens the temp file with O_EXCL,
// which Docker Desktop's gRPC-FUSE / virtio-fs file sharing rejects with EACCES
// on macOS — so bootstrap fails even though the directory is writable (the
// non-O_EXCL os.WriteFile used for /leash/cgroup-path succeeds in the same dir).
// A PID-suffixed temp name with O_CREATE|O_TRUNC (no O_EXCL) is unique enough —
// there is one leash-entry per container — and the rename still publishes the
// marker atomically. See issue #73.
func writeMarkerAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil && !os.IsExist(err) {
		return fmt.Errorf("ensure bootstrap dir: %w", err)
	}
	if err := writeFileAtomic(path, data, 0o644); err != nil {
		return fmt.Errorf("write marker: %w", err)
	}
	return nil
}

func emitCgroupPath() error {
	data, err := os.ReadFile(selfCgroupPath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", selfCgroupPath, err)
	}

	lines := strings.Split(string(data), "\n")
	var resolved string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, ":")
		var raw string
		switch len(parts) {
		case 0:
			continue
		case 1:
			raw = parts[0]
		default:
			raw = parts[len(parts)-1]
		}
		raw = strings.TrimSpace(raw)
		if raw == "" || raw == "/" || raw == "." {
			continue
		}
		if !strings.HasPrefix(raw, "/") {
			raw = "/" + raw
		}
		var candidate string
		if strings.HasPrefix(raw, "/sys/") {
			candidate = filepath.Clean(raw)
		} else {
			candidate = filepath.Clean(filepath.Join("/sys/fs/cgroup", strings.TrimPrefix(raw, "/")))
		}
		if candidate != "" {
			resolved = candidate
			break
		}
	}

	if resolved == "" {
		// Some environments (notably Docker Desktop with Kubernetes) run the
		// container in a private cgroup namespace where /proc/self/cgroup reports
		// "0::/", leaving no scopable cgroup. Rather than aborting the container,
		// continue without writing cgroup-path: leashd degrades to proxy-only
		// enforcement (kernel LSM disabled, L7 proxy still active). See issue #67.
		os.Stderr.WriteString("leash-entry: WARNING: no scopable cgroup in /proc/self/cgroup (e.g. Docker Desktop Kubernetes); continuing without cgroup scoping — kernel LSM enforcement disabled, proxy enforcement remains active\n")
		return nil
	}

	if err := os.WriteFile(cgroupPathFile, []byte(resolved+"\n"), 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", cgroupPathFile, err)
	}

	return nil
}
