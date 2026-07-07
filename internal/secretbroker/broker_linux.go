//go:build linux

package secretbroker

import (
	"context"
	"errors"
)

// Serve runs the shadow D-Bus Secret Service on busAddress (a private session bus
// leash starts for the box), live-proxying to the real session keyring and
// serving only the items allow permits — every other item is hidden from
// SearchItems and denied on GetSecret.
//
// TODO(sixtoad/leash#4): export the org.freedesktop.Secret.Service object
// hierarchy via godbus — OpenSession("plain"), a proxied Collection, SearchItems
// filtered through allow.AllowsAttributes, and Item.GetSecret forwarded to the
// real bus only for allowed items — then block until ctx is done. This needs
// iterative verification against a real client (agy) under sudo.
//
// Until that lands Serve fails CLOSED: a caller that enabled --secret must abort
// rather than run an agent without its broker (never fall back to the real bus).
func Serve(_ context.Context, busAddress string, allow *Allowlist) error {
	if allow == nil || !allow.Enabled() {
		return errors.New("secretbroker: no secrets allow-listed")
	}
	if busAddress == "" {
		return errors.New("secretbroker: empty bus address")
	}
	return errors.New("secretbroker: D-Bus Secret Service shadow not yet implemented — see sixtoad/leash#4")
}
