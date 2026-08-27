package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"runtime"
	"syscall"

	"github.com/strongdm/leash/internal/darwind"
	"github.com/strongdm/leash/internal/doctor"
	"github.com/strongdm/leash/internal/hardening"
	"github.com/strongdm/leash/internal/leashd"
	"github.com/strongdm/leash/internal/resolvercontract"
	"github.com/strongdm/leash/internal/runner"
	"github.com/strongdm/leash/internal/telemetry/statsig"
	versionpkg "github.com/strongdm/leash/internal/version" // aliased: `version` is the ldflag var below
)

var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

func main() {
	statsig.Configure(version)

	args := os.Args
	if handled, code := runResolverSubcommand(args, os.Stdout, os.Stderr); handled {
		os.Exit(code)
	}
	if len(args) > 1 {
		switch args[1] {
		case "--version":
			printVersion()
			return
		case "version": // `version [--json]`: machine-readable build + contract info.
			if err := versionpkg.Run(args[2:], buildInfo(), os.Stdout); err != nil {
				if errors.Is(err, flag.ErrHelp) { // usage already printed: a clean exit, not a failure.
					return
				}
				log.Fatal(err)
			}
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
		case "doctor": // node readiness self-check; exit 0 enforces, 3 runs proxy-only, 1 cannot run at all.
			os.Exit(doctor.Main(args[2:], os.Stdout, os.Stderr))
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

func runResolverSubcommand(args []string, stdout, stderr io.Writer) (bool, int) {
	if len(args) <= 1 || args[1] != "resolvers" {
		return false, 0
	}
	return true, resolvercontract.Main(args[2:], stdout, stderr, runtime.GOOS, runner.NativeEgressResolvers)
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

// buildInfo bundles the link-time values for internal/version, which does the
// formatting so it can be unit-tested without these globals.
func buildInfo() versionpkg.Build {
	return versionpkg.Build{Version: version, Commit: commit, BuildDate: buildDate}
}

func printVersion() {
	fmt.Print(versionpkg.Describe(buildInfo()).Human())
}
