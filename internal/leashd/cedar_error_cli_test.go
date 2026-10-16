package leashd

import (
	"errors"
	"strings"
	"testing"

	cedarutil "github.com/strongdm/leash/internal/cedar"
)

func cliError(t *testing.T, text string) string {
	t.Helper()
	_, err := cedarutil.CompileString("leash.cedar", text)
	var detail *cedarutil.ErrorDetail
	if !errors.As(err, &detail) {
		t.Fatalf("want an ErrorDetail, got %v", err)
	}
	return formatCedarErrorForCLI(detail)
}

func TestFormatCedarErrorForCLINamesThePolicyThatDoesNotCompile(t *testing.T) {
	out := cliError(t, `@leash_semantics("cedar")
permit (principal, action in Action::"FileOpen", resource in Dir::"/");

@id("exec-tty")
permit (principal, action == Action::"ProcessExec", resource) when { context.tty == true };`)
	for _, want := range []string{
		"error: policy not enforceable by the kernel",
		"policy: exec-tty",
		"file: leash.cedar:4:1",
		"context is not available to the kernel",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Review the Cedar syntax") {
		t.Errorf("a compile error is not a syntax error:\n%s", out)
	}
}

func TestFormatCedarErrorForCLINamesALegacyPolicyByItsSourceLine(t *testing.T) {
	out := cliError(t, `permit (principal, action in [Action::"FileOpen", Secret::Action::"Read"], resource);`)
	if !strings.Contains(out, "error: invalid policy") || !strings.Contains(out, "mixes plugin actions") {
		t.Errorf("got:\n%s", out)
	}
}

func TestFormatCedarErrorForCLIKeepsSyntaxErrors(t *testing.T) {
	out := cliError(t, "permit (principal, action, resource")
	if !strings.HasPrefix(out, "error: invalid Cedar policy") || !strings.Contains(out, "^") {
		t.Errorf("got:\n%s", out)
	}
}

func TestFormatCedarErrorForCLIAlwaysPrintsTheMessage(t *testing.T) {
	out := formatCedarErrorForCLI(&cedarutil.ErrorDetail{Message: "something specific", File: "leash.cedar"})
	if !strings.Contains(out, "message: something specific") {
		t.Errorf("got:\n%s", out)
	}
}
