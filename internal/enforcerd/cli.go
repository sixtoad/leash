package enforcerd

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

const daemonUsage = `Usage: leash daemon <command>

The leash enforcer daemon gives rootless containers (rootless podman and Docker) the same
eBPF LSM enforcement leash applies as root. It is a small socket-activated
system service holding only CAP_BPF and CAP_PERFMON; members of the "leash"
group can ask it to enforce their own sessions' policies on their own
containers' cgroups. See docs/ROOTLESS.md.

Commands:
  install [--user <name>]   (root) Install and start the daemon; add <name>
                            (default: $SUDO_USER) to the leash group.
  uninstall [--purge]       (root) Stop and remove the daemon, its units, user
                            and group. --purge also deletes the audit log.
  status [--json]           Check the daemon from this user's point of view.
                            Exit 0 when a rootless run can use it.
`

// Main runs `leash daemon ...` and returns the exit code.
func Main(args []string, version string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(stdout, daemonUsage)
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	switch args[0] {
	case "install":
		fs := flag.NewFlagSet("leash daemon install", flag.ContinueOnError)
		fs.SetOutput(stderr)
		user := fs.String("user", strings.TrimSpace(os.Getenv("SUDO_USER")), "user to add to the leash group")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		if err := Install(*user, stdout); err != nil {
			fmt.Fprintf(stderr, "leash daemon install: %v\n", err)
			return 1
		}
		return 0
	case "uninstall":
		fs := flag.NewFlagSet("leash daemon uninstall", flag.ContinueOnError)
		fs.SetOutput(stderr)
		purge := fs.Bool("purge", false, "also delete the audit log")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		if err := Uninstall(*purge, stdout); err != nil {
			fmt.Fprintf(stderr, "leash daemon uninstall: %v\n", err)
			return 1
		}
		return 0
	case "status":
		fs := flag.NewFlagSet("leash daemon status", flag.ContinueOnError)
		fs.SetOutput(stderr)
		asJSON := fs.Bool("json", false, "print a JSON document")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		rep := Check(context.Background(), SocketPath())
		if *asJSON {
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(rep)
		} else {
			fmt.Fprint(stdout, rep.Human())
		}
		if !rep.Usable {
			return 1
		}
		return 0
	case "run":
		fs := flag.NewFlagSet("leash daemon run", flag.ContinueOnError)
		fs.SetOutput(stderr)
		socket := fs.String("socket", "", "listen on this path instead of the systemd-activated socket")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		if err := runDaemon(version, *socket); err != nil {
			fmt.Fprintf(stderr, "leash daemon run: %v\n", err)
			return 1
		}
		return 0
	case "worker":
		if err := runWorkerMain(); err != nil {
			fmt.Fprintf(stderr, "leash daemon worker: %v\n", err)
			return 1
		}
		return 0
	default:
		fmt.Fprintf(stderr, "leash daemon: unknown command %q\n\n%s", args[0], daemonUsage)
		return 2
	}
}

// Report is `leash daemon status`.
type Report struct {
	Socket    string  `json:"socket"`
	Reachable bool    `json:"reachable"`
	Error     string  `json:"error,omitempty"`
	Status    *Status `json:"daemon,omitempty"`
	// Usable: reachable, answered, and the kernel runs BPF LSM programs.
	Usable bool   `json:"usable"`
	Remedy string `json:"remedy,omitempty"`
}

// Check connects to the daemon and asks for its status.
func Check(ctx context.Context, socket string) Report {
	rep := Report{Socket: socket}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	c, err := Dial(ctx, socket, nil)
	if err != nil {
		rep.Error = err.Error()
		rep.Remedy = RemedyFor(err)
		return rep
	}
	defer c.Close()
	rep.Reachable = true
	st, err := c.Status()
	if err != nil {
		rep.Error = err.Error()
		rep.Remedy = "the daemon refused this caller; see its reason above and `journalctl -u leash-enforcerd`"
		return rep
	}
	rep.Status = st
	if st.BPFLSM != "active" {
		rep.Error = "the kernel does not run BPF LSM programs: " + st.BPFLSMReason
		rep.Remedy = "add bpf to the kernel's lsm= boot parameter and reboot (see `leash doctor`)"
		return rep
	}
	rep.Usable = true
	return rep
}

// RemedyFor turns a dial error into the next step.
func RemedyFor(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "no such file or directory"), strings.Contains(msg, "connection refused"):
		return "install the daemon once with `sudo leash daemon install`"
	case strings.Contains(msg, "permission denied"):
		return "your user is not in the leash group in this session: `sudo usermod -aG leash $USER`, then log out and back in (or run `newgrp leash`)"
	default:
		return "check `systemctl status leash-enforcerd.socket leash-enforcerd.service`"
	}
}

// Human renders the report.
func (r Report) Human() string {
	var b strings.Builder
	fmt.Fprintf(&b, "socket:    %s\n", r.Socket)
	if r.Status != nil {
		fmt.Fprintf(&b, "daemon:    leash %s (protocol %d)\n", r.Status.Version, r.Status.Protocol)
		fmt.Fprintf(&b, "caller:    uid %d, %d attached session(s)\n", r.Status.UID, r.Status.Sessions)
		fmt.Fprintf(&b, "bpf LSM:   %s\n", r.Status.BPFLSM)
	}
	if r.Usable {
		b.WriteString("status:    ready: rootless runs get eBPF LSM enforcement (enforcement=lsm)\n")
		return b.String()
	}
	fmt.Fprintf(&b, "status:    NOT usable: %s\n", r.Error)
	if r.Remedy != "" {
		fmt.Fprintf(&b, "fix:       %s\n", r.Remedy)
	}
	return b.String()
}
