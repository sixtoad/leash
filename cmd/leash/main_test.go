package main

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/strongdm/leash/internal/resolvercontract"
)

func TestResolverSubcommandDispatch(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	handled, code := runResolverSubcommand(
		[]string{"leash", "resolvers", "--runtime", "native", "--json"},
		&stdout, &stderr,
	)
	if !handled || code != resolvercontract.ExitSuccess {
		t.Fatalf("handled=%t code=%d stderr=%q", handled, code, stderr.String())
	}
	var document resolvercontract.Document
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
		t.Fatalf("stdout is not resolver JSON: %v (%q)", err, stdout.String())
	}
	if document.Runtime != "native" || document.Strategy != resolvercontract.StrategyLeashManaged {
		t.Fatalf("document = %+v", document)
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
