package macsync

import (
	"strings"
	"time"

	"github.com/strongdm/leash/internal/macext"
	"github.com/strongdm/leash/internal/messages"
)

// This file holds the facts `leash doctor` needs about the live macOS
// enforcement stack — the ones no external command can observe.
//
// The motivating one is Full Disk Access: macOS will not let one process read
// that permission on another's behalf, so the only honest signal is the one
// LeashES already produces. es_new_client returns
// ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED without FDA, and LeashES turns that
// into an es.full_disk_access.missing event before exiting (see
// mac-leash/LeashES/main.swift); on success it sends es.full_disk_access.ready.
// Recording those here turns a log line into a readiness fact. The state
// vocabulary itself lives in internal/macext, shared with leash doctor.

// Event names LeashES sends around its es_new_client call. They are matched by
// exact name rather than by prefix: a new es.full_disk_access.* event should
// have to be interpreted deliberately, not silently absorbed into whichever
// branch its name happens to resemble.
const (
	eventFDAReady   = "es.full_disk_access.ready"
	eventFDAMissing = "es.full_disk_access.missing"
)

// noteReadinessEvent records the readiness-relevant telemetry carried by a
// mac.event. It is called from LogMacEvent, so every event the daemon logs is
// also considered here — there is no second path an extension could report on
// that doctor would miss.
func (m *Manager) noteReadinessEvent(event *messages.MacEventPayload) {
	if event == nil {
		return
	}
	var state macext.FDA
	switch strings.TrimSpace(event.Event) {
	case eventFDAReady:
		state = macext.FDAGranted
	case eventFDAMissing:
		state = macext.FDADenied
	default:
		return
	}
	ts := event.Time
	if ts.IsZero() {
		ts = time.Now()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	// Last writer wins by observation time rather than by arrival: macOS
	// relaunches LeashES after an FDA failure, so a stale "ready" from a
	// previous launch must not overwrite the "missing" that followed it, and a
	// reconnect replaying old telemetry must not overwrite a newer grant.
	if !m.fdaAt.IsZero() && ts.Before(m.fdaAt) {
		return
	}
	m.fda = state
	m.fdaAt = ts
}

// FullDiskAccessState reports LeashES's Full Disk Access grant as last observed,
// and when. A zero time means nothing has been reported.
//
// Two signals, in this order:
//
//  1. A CONNECTED leash.es client advertising CapabilityFullDiskAccess. This is
//     live evidence and it wins: LeashES only advertises it after es_new_client
//     has already succeeded, and the advertisement dies with the connection, so
//     it cannot outlive the process it describes.
//  2. Otherwise the last es.full_disk_access.{ready,missing} event recorded.
//     That covers LeashES's very first connection (it says hello before it calls
//     es_new_client, so the opening hello cannot carry the capability), the
//     denial case (a denied LeashES reports and then exits, so it is never a
//     live client), and extensions too old to advertise anything.
//
// The fallback can be stale — a denial that never reached the daemon leaves an
// old "granted" standing — but not harmfully: with no leash.es client connected,
// leash doctor already refuses to call macOS ready on the connectivity check
// alone.
func (m *Manager) FullDiskAccessState() (macext.FDA, time.Time) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, client := range m.clients {
		if client.Component == macext.ComponentEndpointSecurity && client.Capabilities[macext.CapabilityFullDiskAccess] {
			return macext.FDAGranted, client.LastSeen
		}
	}
	return m.fda, m.fdaAt
}

// Health is the observation-only snapshot served at /health/darwin, and the
// only way `leash doctor` can learn what the running daemon sees. No verdicts
// are formed here: the daemon reports, doctor grades.
func (m *Manager) Health() macext.DaemonHealth {
	state, at := m.FullDiskAccessState()
	health := macext.DaemonHealth{
		Components:     m.ConnectedComponents(),
		FullDiskAccess: state.String(),
	}
	if !at.IsZero() {
		health.FullDiskAccessAt = at.UTC().Format(time.RFC3339)
	}
	return health
}
