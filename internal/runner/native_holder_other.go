//go:build !linux

package runner

import (
	"fmt"
	"os"
)

// NativeHolderMain is Linux-only (the native runtime needs systemd + cgroup v2).
func NativeHolderMain(args []string) int {
	fmt.Fprintln(os.Stderr, "leash --native-holder is only supported on Linux")
	return 2
}
