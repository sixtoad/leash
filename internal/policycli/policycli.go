// Package policycli implements `leash policy ...` subcommands.
package policycli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/strongdm/leash/internal/transpiler"
)

const usage = `usage: leash policy migrate [--write] <file.cedar>

  migrate   rewrite a legacy Leash policy file to strict Cedar semantics
            (forbid overrides permit, default deny) with the same decisions,
            and mark every policy @leash_semantics("cedar"). Prints the result
            to stdout, or replaces the file with --write.
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
		fmt.Fprintf(stderr, "%s already uses strict Cedar semantics (@leash_semantics(\"cedar\")); nothing to do\n", path)
		if !*write {
			_, err = io.WriteString(stdout, string(data))
		}
		return err
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
