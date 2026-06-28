package darwind

import (
	"os"
	"strings"
)

// This file is intentionally NOT build-tagged: the parsing logic is pure and
// unit-tested on any OS. The darwin-only glue (invoking systemextensionsctl and
// wiring the check into preFlight) lives in preflight_extensions_darwin.go.

// extensionState describes a system extension's activation state, as reported by
// `systemextensionsctl list`.
type extensionState int

const (
	extNotInstalled extensionState = iota
	extInstalledButDisabled
	extActive
)

func (s extensionState) String() string {
	switch s {
	case extActive:
		return "active"
	case extInstalledButDisabled:
		return "installed but disabled"
	default:
		return "not installed / not approved"
	}
}

// Extension identifiers mirror mac-leash/Shared/LeashIdentifiers.swift. The base
// bundle id can be overridden for non-default builds via LEASH_BUNDLE_IDENTIFIER
// (the Swift app honors the same env var).
func leashBundleID() string {
	if v := strings.TrimSpace(os.Getenv("LEASH_BUNDLE_IDENTIFIER")); v != "" {
		return v
	}
	return "com.strongdm.leash"
}

func endpointSecurityExtensionID() string { return leashBundleID() + ".LeashES" }
func networkFilterExtensionID() string    { return leashBundleID() + ".LeashNetworkFilter" }

// interpretExtensionEntry mirrors interpretExtensionEntry in
// mac-leash/Leash/SystemExtensionController+Internals.swift (the source of
// truth). `systemextensionsctl list` rows are tab-separated:
//
//	enabled  active  teamID  bundleID (version)  name  [state]
//	  *        *     W5H…    com.strongdm.leash.LeashES (1/1)  LeashES  [activated enabled]
//
// column 0 carries a "*" when enabled, column 1 when active, and the last column
// is a bracketed [state]. ok is false only for an empty line.
func interpretExtensionEntry(line string) (isActive, isInstalledButDisabled bool, state string, ok bool) {
	cols := strings.Split(line, "\t")
	if len(cols) == 0 {
		return false, false, "", false
	}
	star := func(i int) bool { return i < len(cols) && strings.Contains(cols[i], "*") }
	enabled := star(0)
	active := star(1)

	state = strings.Trim(strings.TrimSpace(cols[len(cols)-1]), "[]")
	norm := strings.ToLower(state)

	isActive = (enabled && active) || strings.Contains(norm, "activated enabled")
	switch {
	case enabled && !active:
		isInstalledButDisabled = true
	case strings.Contains(norm, "disabled"), strings.Contains(norm, "inactive"), strings.Contains(norm, "paused"):
		isInstalledButDisabled = true
	}
	return isActive, isInstalledButDisabled, state, true
}

// parseExtensionState scans `systemextensionsctl list` output for the row(s)
// matching id (case-insensitive) and returns the best state found.
func parseExtensionState(output, id string) extensionState {
	idLower := strings.ToLower(strings.TrimSpace(id))
	disabled := false
	for _, raw := range strings.Split(output, "\n") {
		if !strings.Contains(strings.ToLower(raw), idLower) {
			continue
		}
		active, isDisabled, _, ok := interpretExtensionEntry(raw)
		if !ok {
			continue
		}
		if active {
			return extActive
		}
		if isDisabled {
			disabled = true
		}
	}
	if disabled {
		return extInstalledButDisabled
	}
	return extNotInstalled
}
