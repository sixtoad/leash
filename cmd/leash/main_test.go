package main

import (
	"bytes"
	"encoding/json"
	"runtime"
	"strings"
	"testing"

	"github.com/strongdm/leash/internal/resolvercontract"
)

func TestResolverSubcommandDispatch(t *testing.T) {
	t.Parallel()
	for _, backend := range []string{"native", "docker", "podman"} {
		t.Run(backend, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			handled, code := runResolverSubcommand(
				[]string{"leash", "resolvers", "--runtime", backend, "--json"},
				&stdout, &stderr,
			)
			// Native resolver reporting describes Linux network namespaces;
			// other hosts must reject it without emitting a success document.
			if backend == "native" && runtime.GOOS != "linux" {
				if !handled || code != resolvercontract.ExitContract || stdout.Len() != 0 || !strings.Contains(stderr.String(), "unsupported") {
					t.Fatalf("handled=%t code=%d stdout=%q stderr=%q", handled, code, stdout.String(), stderr.String())
				}
				return
			}
			if !handled || code != resolvercontract.ExitSuccess || stderr.Len() != 0 {
				t.Fatalf("handled=%t code=%d stderr=%q", handled, code, stderr.String())
			}
			var document resolvercontract.Document
			if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
				t.Fatalf("stdout is not resolver JSON: %v (%q)", err, stdout.String())
			}
			wantStrategy := resolvercontract.StrategyRuntimeManaged
			if backend == "native" {
				wantStrategy = resolvercontract.StrategyLeashManaged
			}
			if document.Runtime != backend || document.Strategy != wantStrategy {
				t.Fatalf("document = %+v, want runtime %q strategy %q", document, backend, wantStrategy)
			}
		})
	}
}

func TestResolverSubcommandDoesNotClaimOtherCommands(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{{"leash"}, {"leash", "version", "--json"}, {"leash", "doctor"}} {
		handled, code := runResolverSubcommand(args, &bytes.Buffer{}, &bytes.Buffer{})
		if handled || code != 0 {
			t.Fatalf("runResolverSubcommand(%v) = %t, %d", args, handled, code)
		}
	}
}
