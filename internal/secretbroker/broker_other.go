//go:build !linux

package secretbroker

import (
	"context"
	"errors"
)

// Serve is unsupported off Linux: the shadow uses the D-Bus Secret Service. The
// macOS Keychain backend is a later phase under the same allow-list (see
// sixtoad/leash#4).
func Serve(_ context.Context, _ string, _ *Allowlist) error {
	return errors.New("secretbroker: the D-Bus Secret Service shadow is only supported on Linux")
}
