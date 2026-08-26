// Package resolvercontract exposes the DNS resolver ownership contract that
// orchestrators need before they compose a Leash network policy.
package resolvercontract

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
)

const (
	SchemaVersion = 1
	MaxResolvers  = 16

	StrategyLeashManaged   = "leash-managed"
	StrategyRuntimeManaged = "runtime-managed"
)

const (
	nativeDiscovery    = "use the complete resolver list reported by Leash"
	containerDiscovery = "inspect the target runtime's effective /etc/resolv.conf"
)

// Document is emitted by `leash resolvers --runtime ... --json`.
//
// Strategy is the union discriminator. A leash-managed document always has a
// complete, non-empty resolver list. A runtime-managed document intentionally
// has an empty list and tells the orchestrator where discovery remains owned.
type Document struct {
	SchemaVersion int      `json:"schemaVersion"`
	Runtime       string   `json:"runtime"`
	Strategy      string   `json:"strategy"`
	Resolvers     []string `json:"resolvers"`
	Discovery     string   `json:"discovery"`
}

// Build validates and constructs the contract for one explicit runtime.
func Build(runtime string, nativeResolvers []string) (Document, error) {
	switch runtime {
	case "native":
		resolvers, err := CanonicalResolvers(nativeResolvers)
		if err != nil {
			return Document{}, fmt.Errorf("native resolver contract: %w", err)
		}
		return Document{
			SchemaVersion: SchemaVersion,
			Runtime:       runtime,
			Strategy:      StrategyLeashManaged,
			Resolvers:     resolvers,
			Discovery:     nativeDiscovery,
		}, nil
	case "docker", "podman":
		if len(nativeResolvers) != 0 {
			return Document{}, errors.New("container resolver contract must not contain native resolver addresses")
		}
		return Document{
			SchemaVersion: SchemaVersion,
			Runtime:       runtime,
			Strategy:      StrategyRuntimeManaged,
			Resolvers:     []string{},
			Discovery:     containerDiscovery,
		}, nil
	default:
		return Document{}, fmt.Errorf("unsupported runtime %q (want native, docker, or podman)", runtime)
	}
}

// CanonicalResolvers validates, canonicalizes, deduplicates, and sorts resolver
// addresses. It is exported only for the native launcher to consume the same
// representation that this package reports on the wire.
func CanonicalResolvers(raw []string) ([]string, error) {
	if len(raw) == 0 {
		return nil, errors.New("no resolver addresses configured")
	}

	seen := make(map[string]struct{}, len(raw))
	for _, value := range raw {
		addr, err := netip.ParseAddr(value)
		if err != nil {
			return nil, fmt.Errorf("invalid resolver address %q: %w", value, err)
		}
		canonical := addr.WithZone("").Unmap().String()
		seen[canonical] = struct{}{}
	}
	if len(seen) > MaxResolvers {
		return nil, fmt.Errorf("resolver count %d exceeds limit %d", len(seen), MaxResolvers)
	}

	resolvers := make([]string, 0, len(seen))
	for address := range seen {
		resolvers = append(resolvers, address)
	}
	sort.Strings(resolvers)
	return resolvers, nil
}

// JSON renders a complete document before a caller writes any stdout bytes.
func (d Document) JSON() ([]byte, error) {
	out, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode resolver contract: %w", err)
	}
	return append(out, '\n'), nil
}
