package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/strongdm/leash/internal/darwind"
	"github.com/strongdm/leash/internal/hardening"
	"github.com/strongdm/leash/internal/leashd"
	"github.com/strongdm/leash/internal/runner"
	"github.com/strongdm/leash/internal/secretbroker"
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
		case "--secret-broker": // internal: run the keyring secret broker (spawned as the invoking user).
			if err := runSecretBroker(args[2:]); err != nil {
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

// runSecretBroker runs the keyring secret broker: a shadow D-Bus Secret Service
// that serves only the --secret services, live-proxying the invoking user's real
// keyring. It is spawned by the native launcher AS the invoking user (root can't
// reach the user's session bus), listens on --secret-bus, and blocks until the
// launcher signals it. Usage: leash --secret-broker --secret-bus <path> --secret <svc>...
func runSecretBroker(args []string) error {
	var sockPath string
	var services []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--secret-bus":
			if i+1 < len(args) {
				sockPath = args[i+1]
				i++
			}
		case "--secret":
			if i+1 < len(args) {
				services = append(services, args[i+1])
				i++
			}
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	b, err := secretbroker.Start(ctx, secretbroker.NewAllowlist(services), sockPath)
	if err != nil {
		return err
	}
	defer b.Close()
	fmt.Printf("secret broker: serving %d secret(s) at %s\n", len(services), b.SocketPath())
	<-ctx.Done()
	return nil
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
