package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"syscall"

	"github.com/strongdm/leash/internal/darwind"
	"github.com/strongdm/leash/internal/hardening"
	"github.com/strongdm/leash/internal/leashd"
	"github.com/strongdm/leash/internal/runner"
	"github.com/strongdm/leash/internal/telemetry/statsig"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

func main() {
	statsig.Configure(version)

	args := os.Args
	if len(args) > 1 {
		switch args[1] {
		case "--version":
			printVersion()
			return
		case "--daemon": // "Secret" flag to run leashd.
			daemonArgs := append([]string{args[0]}, args[2:]...)
			if err := leashd.Main(daemonArgs); err != nil {
				log.Fatal(err)
			}
			return
		case "--darwin": // macOS path.
			if err := darwind.Main(args[2:]); err != nil {
				if errors.Is(err, flag.ErrHelp) {
					return
				}
				log.Fatal(err)
			}
			return
		case "--harden-exec": // internal: seccomp-harden this process, then exec the workload.
			if err := hardenExec(args[2:]); err != nil {
				log.Fatal(err)
			}
			return
		default: // Docker-Leash CLI frontend.
			runner.SetVersion(version)
			if err := runner.Main(args); err != nil {
				var exitErr *runner.ExitCodeError
				if errors.As(err, &exitErr) {
					os.Exit(exitErr.ExitCode())
				}
				log.Fatal(err)
			}
		}
	}
}

// hardenExec applies the seccomp/no-new-privs/cap-drop hardening to the current
// process, then execs the remaining command. Inserted into the native workload
// launch (after leash's own namespace setup) so the filter is inherited by the
// agent and every subprocess — closing the userns→bind-mount path-LSM bypass.
// Usage: leash --harden-exec -- <cmd> [args...]
func hardenExec(rest []string) error {
	if len(rest) > 0 && rest[0] == "--" {
		rest = rest[1:]
	}
	if len(rest) == 0 {
		return errors.New("--harden-exec: no command given")
	}
	if err := hardening.Apply(); err != nil {
		return fmt.Errorf("--harden-exec: %w", err)
	}
	path := rest[0]
	if resolved, err := exec.LookPath(path); err == nil {
		path = resolved
	}
	return syscall.Exec(path, rest, os.Environ())
}

func printVersion() {
	shortHash := commit
	if len(shortHash) > 7 {
		shortHash = shortHash[:7]
	}
	fmt.Printf("version: %s\n", version)
	fmt.Printf("git hash: %s\n", shortHash)
	fmt.Printf("build date: %s\n", buildDate)
}
