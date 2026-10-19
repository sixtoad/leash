package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"

	"github.com/strongdm/leash/internal/darwind"
	"github.com/strongdm/leash/internal/doctor"
	"github.com/strongdm/leash/internal/enforcerd"
	"github.com/strongdm/leash/internal/hardening"
	"github.com/strongdm/leash/internal/idmap"
	"github.com/strongdm/leash/internal/leashd"
	"github.com/strongdm/leash/internal/policycli"
	"github.com/strongdm/leash/internal/resolvercontract"
	"github.com/strongdm/leash/internal/runner"
	"github.com/strongdm/leash/internal/telemetry/statsig"
	versionpkg "github.com/strongdm/leash/internal/version" // aliased: `version` is the ldflag var below
)

var (
	version         = "dev"
	commit          = "unknown"
	buildDate       = "unknown"
	managerImage    = "ghcr.io/sixtoad/leash-manager:dev"
	managerRevision = ""
	managerContract = "1"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--idmap-userns-holder" {
		idmap.HoldUserNamespace()
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "--idmap-mount-helper" {
		specs, err := idmap.Decode(os.Getenv(idmap.Env))
		if err == nil {
			err = idmap.ApplyCurrent(specs)
		}
		if err != nil {
			log.Fatal(err)
		}
		return
	}
	if err := runner.SetManagerRelease(managerImage, managerRevision, managerContract); err != nil {
		log.Fatal(err)
	}
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
				// Full (possibly multi-line) error for the log, then a one-line
				// FATAL tag the native and container launchers extract as the
				// refusal reason.
				log.Print(err)
				fmt.Fprintln(os.Stderr, leashd.FatalLine(err))
				os.Exit(1)
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
		case "policy": // `policy migrate [--write] <file>` (legacy file -> strict Cedar, #142), `policy lint <file>`.
			os.Exit(policycli.Main(args[2:], os.Stdout, os.Stderr))
		case "daemon": // `daemon install|uninstall|status|run`: the rootless enforcer daemon.
			os.Exit(enforcerd.Main(args[2:], version, os.Stdout, os.Stderr))
		case "manager": // `manager inspect --json`: the manager image a container run would use, read from its OCI labels.
			os.Exit(runner.ManagerMain(args[2:], os.Stdout, os.Stderr))
		case "doctor": // node readiness self-check; exit 0 enforces, 3 runtime usable but a layer is off (leash run refuses), 1 cannot run at all.
			os.Exit(doctor.Main(args[2:], os.Stdout, os.Stderr))
		case "--native-holder": // internal: the native box holder, bound to the owning leash's lifetime (#158).
			os.Exit(runner.NativeHolderMain(args[2:]))
		case "--native-reap-box": // internal: reap one native box whose owning leash died (#158).
			os.Exit(runner.NativeReapBoxMain(args[2:]))
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

// hardenExec applies the seccomp/no-new-privs/capability hardening to the
// current process, then runs the remaining command. Inserted into the native
// workload launch (after leash's own namespace setup) so it is inherited by
// the agent and every subprocess — closing the userns→bind-mount path-LSM
// bypass. With --user it also drops root to that user: the bounding set can
// only be emptied while still privileged, so the drop happens here instead of
// in runuser (#203).
// Usage: leash --harden-exec [--user <name>] -- <cmd> [args...]
func hardenExec(rest []string) error {
	var drop *hardening.Identity
	if len(rest) >= 2 && rest[0] == "--user" {
		id, err := hardening.LookupIdentity(rest[1])
		if err != nil {
			return fmt.Errorf("--harden-exec: %w", err)
		}
		drop = id
		rest = rest[2:]
	}
	if len(rest) > 0 && rest[0] == "--" {
		rest = rest[1:]
	}
	if len(rest) == 0 {
		return errors.New("--harden-exec: no command given")
	}
	env := os.Environ()
	if drop != nil {
		env = hardening.UserEnv(env, drop)
	}
	if err := hardening.Apply(drop); err != nil {
		return fmt.Errorf("--harden-exec: %w", err)
	}
	code, err := hardening.Run(rest, env)
	if err != nil {
		return fmt.Errorf("--harden-exec: %w", err)
	}
	os.Exit(code)
	return nil
}

// buildInfo bundles the link-time values for internal/version, which does the
// formatting so it can be unit-tested without these globals.
func buildInfo() versionpkg.Build {
	return versionpkg.Build{Version: version, Commit: commit, BuildDate: buildDate}
}

func printVersion() {
	fmt.Print(versionpkg.Describe(buildInfo()).Human())
}
