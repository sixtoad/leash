package resolvercontract

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
)

const (
	ExitSuccess  = 0
	ExitContract = 1
	ExitUsage    = 2
	ExitInternal = 4
)

// NativeResolverSource returns the addresses the native launcher installs and
// admits. The CLI accepts it as a seam so malformed future state is testable.
type NativeResolverSource func() []string

// Main runs the resolver-contract subcommand without launching a workload.
func Main(args []string, stdout, stderr io.Writer, platform string, nativeSource NativeResolverSource) int {
	fs := flag.NewFlagSet("leash resolvers", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var runtimes repeatedString
	var jsonRequests repeatedBool
	fs.Var(&runtimes, "runtime", "effective runtime: native, docker, or podman (required)")
	fs.Var(&jsonRequests, "json", "emit the resolver contract as JSON (required)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: leash resolvers --runtime <native|docker|podman> --json")
		fmt.Fprintln(stderr, "\nReports who owns DNS resolver discovery for the selected runtime.")
		fmt.Fprintln(stderr, "\nflags:")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "leash resolvers: unexpected argument %q\n", fs.Arg(0))
		fs.Usage()
		return ExitUsage
	}
	runtime, err := runtimes.oneRequired("--runtime")
	if err != nil {
		fmt.Fprintf(stderr, "leash resolvers: %v\n", err)
		fs.Usage()
		return ExitUsage
	}
	asJSON, err := jsonRequests.oneRequired("--json")
	if err != nil || !asJSON {
		if err == nil {
			err = errors.New("--json is required and must be true")
		}
		fmt.Fprintf(stderr, "leash resolvers: %v\n", err)
		fs.Usage()
		return ExitUsage
	}

	var nativeResolvers []string
	if runtime == "native" {
		if platform != "linux" {
			fmt.Fprintf(stderr, "leash resolvers: native resolver contract is unsupported on %q; this contract describes the Linux network-namespace runtime\n", platform)
			return ExitContract
		}
		if nativeSource == nil {
			fmt.Fprintln(stderr, "leash resolvers: native resolver source is unavailable")
			return ExitContract
		}
		nativeResolvers = nativeSource()
	}
	document, err := Build(runtime, nativeResolvers)
	if err != nil {
		fmt.Fprintf(stderr, "leash resolvers: %v\n", err)
		return ExitContract
	}
	encoded, err := document.JSON()
	if err != nil {
		fmt.Fprintf(stderr, "leash resolvers: %v\n", err)
		return ExitInternal
	}
	if n, err := stdout.Write(encoded); err != nil {
		fmt.Fprintf(stderr, "leash resolvers: write resolver contract: %v\n", err)
		return ExitInternal
	} else if n != len(encoded) {
		fmt.Fprintf(stderr, "leash resolvers: write resolver contract: %v\n", io.ErrShortWrite)
		return ExitInternal
	}
	return ExitSuccess
}

type repeatedString []string

func (v *repeatedString) String() string { return "" }

func (v *repeatedString) Set(value string) error {
	*v = append(*v, value)
	return nil
}

func (v repeatedString) oneRequired(name string) (string, error) {
	if len(v) == 0 || v[0] == "" {
		return "", fmt.Errorf("%s is required", name)
	}
	for _, value := range v[1:] {
		if value != v[0] {
			return "", fmt.Errorf("conflicting %s values %q and %q", name, v[0], value)
		}
	}
	return v[0], nil
}

type repeatedBool []bool

func (v *repeatedBool) String() string { return "false" }

func (v *repeatedBool) IsBoolFlag() bool { return true }

func (v *repeatedBool) Set(value string) error {
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return err
	}
	*v = append(*v, parsed)
	return nil
}

func (v repeatedBool) oneRequired(name string) (bool, error) {
	if len(v) == 0 {
		return false, fmt.Errorf("%s is required", name)
	}
	for _, value := range v[1:] {
		if value != v[0] {
			return false, fmt.Errorf("conflicting %s values", name)
		}
	}
	return v[0], nil
}
