// Package secretbroker mediates an agent's access to the OS keyring. leash runs a
// shadow D-Bus Secret Service that live-proxies to the real keyring but serves
// only allow-listed secrets, hiding every other item — so a keyring-based agent
// (e.g. Antigravity's `agy`) can read its own token inside the box without the
// box gaining access to the rest of the keyring.
//
// This file holds the platform-independent allow policy (pure, unit-tested). The
// D-Bus Secret Service shadow itself is Linux-only (broker_linux.go). Roadmap and
// the Cedar-policy / Control-UI phases: sixtoad/leash#4.
package secretbroker

// serviceAttr is the D-Bus Secret Service attribute go-keyring stores its item
// identity under, and the cross-platform "service" key (macOS: kSecAttrService).
const serviceAttr = "service"

// Allowlist decides which keyring items may be served, keyed by the go-keyring
// "service" attribute. Phase 1 is a static set built from leash's --secret flags;
// Phase 2 replaces it with a Cedar SecretRead policy. Default-deny: an empty
// allow-list serves nothing.
type Allowlist struct {
	services map[string]struct{}
}

// NewAllowlist builds an Allowlist from service names (blank names are ignored).
func NewAllowlist(services []string) *Allowlist {
	set := make(map[string]struct{}, len(services))
	for _, s := range services {
		if s != "" {
			set[s] = struct{}{}
		}
	}
	return &Allowlist{services: set}
}

// AllowsService reports whether an item with this "service" attribute may be
// served.
func (a *Allowlist) AllowsService(service string) bool {
	if service == "" {
		return false
	}
	_, ok := a.services[service]
	return ok
}

// AllowsAttributes reports whether a keyring item with these D-Bus attributes may
// be served. An item without a recognised service attribute is denied.
func (a *Allowlist) AllowsAttributes(attrs map[string]string) bool {
	return a.AllowsService(attrs[serviceAttr])
}

// Enabled reports whether the broker should run at all (non-empty allow-list).
func (a *Allowlist) Enabled() bool { return len(a.services) > 0 }

// Broker is a running secret broker: a private D-Bus session bus whose shadow
// Secret Service live-proxies the real keyring but serves only allow-listed
// items. It is runtime-agnostic — the launcher injects SocketPath() into the
// sandbox (bind-mount + DBUS_SESSION_BUS_ADDRESS for native; -v + -e for a
// container; lxc later) and calls Close() on teardown. Start() (per-platform)
// constructs it; Linux only today (macOS Keychain backend is a later phase).
type Broker interface {
	// SocketPath is the private bus socket to expose to the sandbox as
	// DBUS_SESSION_BUS_ADDRESS=unix:path=<SocketPath>.
	SocketPath() string
	// Close stops the shadow bus and removes the socket.
	Close() error
}
