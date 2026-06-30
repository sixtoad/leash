package darwind

import (
	"fmt"
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
	// extUnknown means the activation state could not be determined — e.g.
	// `systemextensionsctl list` failed or exited 69 (EX_NOPERM). It is never
	// produced by parsing; the darwin glue assigns it on a query failure so the
	// preflight treats "can't tell" as "not active" rather than guessing.
	extUnknown
)

func (s extensionState) String() string {
	switch s {
	case extActive:
		return "active"
	case extInstalledButDisabled:
		return "installed but disabled"
	case extUnknown:
		return "unknown (could not query systemextensionsctl)"
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
	state, _ := parseExtensionStateDetail(output, id)
	return state
}

// rowBundleID extracts the bundle identifier from a `systemextensionsctl list`
// data row. Rows are tab-separated and the bundleID column carries a trailing
// version, e.g. "com.strongdm.leash.LeashES (1.0/1)"; this returns just the id.
// It returns "" for header/non-data rows (fewer than 4 columns).
func rowBundleID(cols []string) string {
	if len(cols) < 4 {
		return ""
	}
	field := strings.TrimSpace(cols[3])
	if i := strings.Index(field, " ("); i >= 0 {
		field = field[:i]
	}
	return field
}

// parseExtensionStateDetail is parseExtensionState plus the raw bracketed
// [state] text of the matched row (e.g. "activated waiting for user"), for use
// in user-facing guidance. detail is "" when no row matches.
//
// Matching is on the bundle-id column EXACTLY (not a substring of the whole
// line): a substring match would let a sibling id that merely has this id as a
// prefix (e.g. "<id>Helper") satisfy the check, which for the enforcement gate
// would mean running unenforced. An unparseable/space-formatted row yields no
// match and therefore a hard stop (fail-safe) rather than a false "active".
func parseExtensionStateDetail(output, id string) (extensionState, string) {
	idTrim := strings.TrimSpace(id)
	result := extNotInstalled
	detail := ""
	for _, raw := range strings.Split(output, "\n") {
		if !strings.EqualFold(rowBundleID(strings.Split(raw, "\t")), idTrim) {
			continue
		}
		active, isDisabled, state, ok := interpretExtensionEntry(raw)
		if !ok {
			continue
		}
		if active {
			return extActive, state // active wins outright
		}
		// Pair detail with the chosen state: prefer a disabled row's text,
		// otherwise the first matched row's text.
		if isDisabled {
			result = extInstalledButDisabled
			detail = state
		} else if detail == "" {
			detail = state
		}
	}
	return result, detail
}

// decideDarwinEnforcement is the pure policy for the native macOS enforcement
// preflight. Native --darwin mode enforces ONLY via the ES + NE system
// extensions — there is no MITM-proxy fallback (see docs/MACOS.md), so a missing
// layer means zero enforcement. The policy is therefore a hard stop: it returns
// nil only when BOTH extensions are active, otherwise an error carrying
// activation guidance. There is intentionally no opt-out — running native mode
// without its only enforcement mechanism is incoherent (don't use --darwin if
// you don't want enforcement). Pure, so the policy is unit-testable on any OS.
func decideDarwinEnforcement(esID, neID string, es, ne extensionState, esDetail, neDetail string) error {
	if es == extActive && ne == extActive {
		return nil
	}
	return fmt.Errorf("native macOS enforcement is unavailable, so leash will not start (native --darwin mode has no proxy fallback — running unenforced is not supported).\n%s",
		darwinEnforcementAdvice(esID, neID, es, ne, esDetail, neDetail))
}

// darwinEnforcementAdvice renders the per-extension state (including the raw
// [state] detail when available) and the activation steps.
func darwinEnforcementAdvice(esID, neID string, es, ne extensionState, esDetail, neDetail string) string {
	return fmt.Sprintf(`  Endpoint Security extension (%s): %s%s
  Network Filter extension   (%s): %s%s
Activate them:
  1. open Leash.app and click Activate for both extensions
  2. approve in System Settings ▸ General ▸ Login Items & Extensions
  3. grant the Endpoint Security extension Full Disk Access
     (System Settings ▸ Privacy & Security ▸ Full Disk Access)
See docs/MACOS.md.`, esID, es, detailSuffix(esDetail), neID, ne, detailSuffix(neDetail))
}

// detailSuffix formats the raw [state] text as a trailing annotation, or "" when
// there is none (so "active" doesn't become "active []").
func detailSuffix(detail string) string {
	if strings.TrimSpace(detail) == "" {
		return ""
	}
	return " [" + detail + "]"
}
