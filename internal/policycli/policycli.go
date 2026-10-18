// Package policycli implements `leash policy ...` subcommands.
package policycli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/strongdm/leash/internal/transpiler"
)

const usage = `usage: leash policy migrate [--write] <file.cedar>
       leash policy lint [--json] <file.cedar>

Policy files are strict Cedar by default (forbid overrides permit, default
deny). The legacy Leash dialect (most specific rule wins, MCP default-allow,
File:: as a path prefix) is read only from a file marked
@leash_semantics("legacy").

  migrate   rewrite a legacy Leash policy file to strict Cedar with the same
            decisions. The input is read as legacy unless it is marked
            @leash_semantics("cedar") (or was written by migrate). The output
            is plain Cedar with no marker. Prints the result to stdout, or
            replaces the file with --write.
  lint      report what would fail the load of a policy file, and warn when
            an unmarked file decides differently than it would under the
            legacy dialect (it was probably written for it: migrate it, or
            mark it @leash_semantics("legacy")). Exits 1 when an error is
            reported.
`

// Main runs `leash policy <args>` and returns the process exit code.
func Main(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(stderr, usage)
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	switch args[0] {
	case "migrate":
		if err := migrate(args[1:], stdout, stderr); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return 0
			}
			fmt.Fprintf(stderr, "leash policy migrate: %v\n", err)
			return 1
		}
		return 0
	case "lint":
		code, err := lint(args[1:], stdout, stderr)
		if err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return 0
			}
			fmt.Fprintf(stderr, "leash policy lint: %v\n", err)
			return 2
		}
		return code
	}
	fmt.Fprintf(stderr, "leash policy: unknown subcommand %q\n%s", args[0], usage)
	return 2
}

func migrate(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("leash policy migrate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	write := fs.Bool("write", false, "replace the file in place instead of printing to stdout")
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return errors.New("exactly one policy file is required")
	}
	path := fs.Arg(0)
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	out, report, already, err := transpiler.MigrateText(filepath.Base(path), string(data))
	if err != nil {
		return err
	}
	if already {
		fmt.Fprintf(stderr, "%s already uses strict Cedar semantics; nothing to do\n", path)
		if !*write {
			_, err = io.WriteString(stdout, string(data))
		}
		return err
	}
	if parsed, perr := transpiler.NewCedarParser().ParseFromString(string(data)); perr == nil {
		if m, _ := transpiler.SemanticsMarker(parsed.NativePolicySet); m == transpiler.MarkerNone {
			fmt.Fprintf(stderr, "note: %s has no @leash_semantics marker; migrate reads it with the legacy dialect (a file already written for strict Cedar needs no migration)\n", path)
		}
	}
	for _, line := range report.Summary() {
		fmt.Fprintln(stderr, line)
	}
	if !*write {
		_, err = io.WriteString(stdout, out)
		return err
	}
	return writeAtomic(path, out)
}

func lint(args []string, stdout, stderr io.Writer) (int, error) {
	fs := flag.NewFlagSet("leash policy lint", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "print the report as JSON")
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return 2, errors.New("exactly one policy file is required")
	}
	path := fs.Arg(0)
	data, err := os.ReadFile(path)
	if err != nil {
		return 2, err
	}
	report, err := transpiler.LintFromString(string(data))
	if err != nil {
		return 2, err
	}
	failed := false
	for _, is := range report.Issues {
		if is.Severity == transpiler.LintError {
			failed = true
		}
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			return 2, err
		}
	} else {
		for _, is := range report.Issues {
			where := path
			if is.PolicyID != "" {
				where += " (" + is.PolicyID + ")"
			}
			fmt.Fprintf(stdout, "%s: %s [%s]: %s\n", where, is.Severity, is.Code, is.Message)
			if is.Suggestion != "" {
				fmt.Fprintf(stdout, "  hint: %s\n", is.Suggestion)
			}
		}
		if len(report.Issues) == 0 {
			fmt.Fprintf(stderr, "%s: no issues\n", path)
		}
	}
	if failed {
		return 1, nil
	}
	return 0, nil
}

func writeAtomic(path, content string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".migrate-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(info.Mode().Perm()); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
