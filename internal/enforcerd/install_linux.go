//go:build linux

package enforcerd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/strongdm/leash/internal/enforcement"
)

func runDaemon(version, socket string) error { return Run(version, socket) }
func runWorkerMain() error                   { return RunWorkerMain() }

func requireRoot(cmd string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("must run as root: sudo leash daemon %s", cmd)
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return errors.New("systemd is not running on this host; the enforcer daemon is a systemd service")
	}
	return nil
}

func run(out io.Writer, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	var buf strings.Builder
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(buf.String()))
	}
	return nil
}

// writeFileAtomic writes data to path via a root-owned temp file and rename.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Chown(tmp, 0, 0); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// Install installs and starts the daemon. Idempotent: re-running it upgrades
// the binary and the units.
func Install(addUser string, out io.Writer) error {
	if err := requireRoot("install"); err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if self, err = filepath.EvalSymlinks(self); err != nil {
		return err
	}
	bin, err := os.ReadFile(self)
	if err != nil {
		return fmt.Errorf("read %s: %w", self, err)
	}
	if err := os.MkdirAll(InstallDir, 0o755); err != nil {
		return err
	}
	if err := os.Chown(InstallDir, 0, 0); err != nil {
		return err
	}
	if err := os.Chmod(InstallDir, 0o755); err != nil {
		return err
	}
	if err := writeFileAtomic(InstallBin, bin, 0o755); err != nil {
		return fmt.Errorf("install %s: %w", InstallBin, err)
	}
	fmt.Fprintf(out, "installed %s (root-owned copy of %s)\n", InstallBin, self)

	if _, err := user.LookupGroup(GroupName); err != nil {
		if err := run(out, "groupadd", "--system", GroupName); err != nil {
			return err
		}
		fmt.Fprintf(out, "created group %s\n", GroupName)
	}
	if _, err := user.Lookup(ServiceUser); err != nil {
		if err := run(out, "useradd", "--system", "--user-group", "--no-create-home", "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", "--comment", "leash enforcer daemon", ServiceUser); err != nil {
			return err
		}
		fmt.Fprintf(out, "created system user %s\n", ServiceUser)
	}
	sock, svc := UnitPaths()
	if err := writeFileAtomic(sock, []byte(SocketUnitText()), 0o644); err != nil {
		return err
	}
	if err := writeFileAtomic(svc, []byte(ServiceUnitText(InstallBin)), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(out, "wrote %s and %s\n", sock, svc)
	if err := run(out, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	// A running daemon keeps its sessions until it restarts; restarting it
	// detaches them, and their leashd clients fail closed. Only restart when
	// nothing is attached... systemd cannot tell, so leave a running daemon
	// alone and say so.
	if err := run(out, "systemctl", "enable", "--now", SocketUnit); err != nil {
		return err
	}
	if exec.Command("systemctl", "is-active", "--quiet", ServiceUnit).Run() == nil {
		fmt.Fprintf(out, "the daemon is running the previous binary; `sudo systemctl restart %s` switches to the new one (attached sessions are detached and their runs stop)\n", ServiceUnit)
	}
	fmt.Fprintf(out, "enabled %s (listening on %s, group %s, mode 0660)\n", SocketUnit, DefaultSocketPath, GroupName)

	if addUser != "" && addUser != "root" {
		if _, err := user.Lookup(addUser); err != nil {
			return fmt.Errorf("user %q: %v", addUser, err)
		}
		if err := run(out, "usermod", "-aG", GroupName, addUser); err != nil {
			return err
		}
		fmt.Fprintf(out, "added %s to group %s: log out and back in (or run `newgrp %s`) for it to take effect\n", addUser, GroupName, GroupName)
	} else {
		fmt.Fprintf(out, "add the users who run rootless leash to the group: sudo usermod -aG %s <user>\n", GroupName)
	}
	if state, reason := enforcement.ClassifyLSMList(os.ReadFile(enforcement.ActiveLSMPath)); state != enforcement.LSMListActive {
		fmt.Fprintf(out, "WARNING: %s\nRootless runs will be refused until the kernel runs BPF LSM programs (see `leash doctor`).\n", reason)
	}
	fmt.Fprintln(out, "check it with: leash daemon status")
	return nil
}

// Uninstall stops and removes the daemon. Attached sessions are detached
// (their leashd clients see the session end and stop their runs).
func Uninstall(purge bool, out io.Writer) error {
	if err := requireRoot("uninstall"); err != nil {
		return err
	}
	_ = run(out, "systemctl", "disable", "--now", SocketUnit)
	_ = run(out, "systemctl", "stop", ServiceUnit)
	sock, svc := UnitPaths()
	for _, p := range []string{sock, svc} {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	_ = run(out, "systemctl", "daemon-reload")
	_ = run(out, "systemctl", "reset-failed", ServiceUnit, SocketUnit)
	fmt.Fprintf(out, "stopped and removed %s and %s\n", SocketUnit, ServiceUnit)
	if err := os.RemoveAll(InstallDir); err != nil {
		return err
	}
	fmt.Fprintf(out, "removed %s\n", InstallDir)
	_ = os.Remove(DefaultSocketPath)
	_ = os.Remove(filepath.Dir(DefaultSocketPath))
	if _, err := user.Lookup(ServiceUser); err == nil {
		if err := run(out, "userdel", ServiceUser); err != nil {
			return err
		}
		fmt.Fprintf(out, "removed system user %s\n", ServiceUser)
	}
	if _, err := user.LookupGroup(GroupName); err == nil {
		if err := run(out, "groupdel", GroupName); err != nil {
			return err
		}
		fmt.Fprintf(out, "removed group %s\n", GroupName)
	}
	logDir := filepath.Join("/var/log", AuditLogDirName)
	if purge {
		if err := os.RemoveAll(logDir); err != nil {
			return err
		}
		fmt.Fprintf(out, "removed %s\n", logDir)
	} else if _, err := os.Stat(logDir); err == nil {
		fmt.Fprintf(out, "kept the audit log in %s (--purge deletes it)\n", logDir)
	}
	return nil
}
