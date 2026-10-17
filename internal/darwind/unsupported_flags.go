package darwind

import (
	"fmt"
	"strings"
)

// unsupportedDarwinFlags are leash options that exist for the Linux runner and
// have no implementation in native macOS mode. Each is refused with a reason
// instead of being passed to leashcli (which rejects any unknown option with a
// bare "Unrecognized option") or, worse, being mistaken for the workload's own
// command line.
var unsupportedDarwinFlags = map[string]string{
	// The plugin path (#152) spawns a helper, binds its socket into the box
	// and serves it a private Cedar authorization socket (LEASH_AUTHZ_SOCKET).
	// Native macOS has no box to bind into and darwind serves no authz socket,
	// so a plugin would run with no authorization service behind it.
	"--inject-service": "--inject-service (and its authz= socket) is not supported in native macOS mode: darwind serves no plugin authorization socket. Run the workload with the Linux runtime (container or native Linux) to use plugins; see docs/MACOS.md",
}

// refuseUnsupportedDarwinFlags scans the leash options that precede the
// workload command (leashcli's own -v/-C, then "--" or the first non-option)
// and refuses any option native macOS cannot honour.
func refuseUnsupportedDarwinFlags(args []string) error {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" || !strings.HasPrefix(arg, "-") {
			return nil
		}
		name := arg
		if eq := strings.IndexByte(name, '='); eq >= 0 {
			name = name[:eq]
		}
		if reason, ok := unsupportedDarwinFlags[name]; ok {
			return fmt.Errorf("%s", reason)
		}
		if arg == "-C" || arg == "--directory" {
			i++ // its value is not an option
		}
	}
	return nil
}
