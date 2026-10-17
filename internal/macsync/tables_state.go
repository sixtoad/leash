package macsync

import (
	"log"
	"sort"
	"strings"
)

// SetTables records the tables the extensions must enforce from now on.
// Acknowledgements of an older version stop counting as soon as it changes.
func (m *Manager) SetTables(t *MacPolicyTables) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tables = t
}

// CurrentTables returns the tables the extensions must enforce (nil before
// the first policy compiled).
func (m *Manager) CurrentTables() *MacPolicyTables {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.tables
}

// RecordApplied notes that a client applied (errMsg == "") or refused the
// tables of version. A refusal clears what that client had applied.
func (m *Manager) RecordApplied(clientID, version, errMsg string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	component := ComponentUnknown
	if c := m.clients[clientID]; c != nil {
		component = c.Component
	}
	if strings.TrimSpace(errMsg) != "" {
		delete(m.applied, clientID)
		log.Printf("macsync: %s (%s) REFUSED policy tables %s: %s", component, clientID, version, errMsg)
		return
	}
	m.applied[clientID] = version
	current := ""
	if m.tables != nil {
		current = m.tables.Version
	}
	log.Printf("macsync: %s (%s) applied policy tables %s (current %s)", component, clientID, version, current)
}

// PolicyAppliedComponents returns the sorted, de-duplicated components of
// the connected clients that applied the current tables.
func (m *Manager) PolicyAppliedComponents() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.policyAppliedLocked()
}

func (m *Manager) policyAppliedLocked() []string {
	if m.tables == nil {
		return []string{}
	}
	seen := map[string]bool{}
	out := []string{}
	for id, version := range m.applied {
		c := m.clients[id]
		if c == nil || version != m.tables.Version || seen[c.Component] {
			continue
		}
		seen[c.Component] = true
		out = append(out, c.Component)
	}
	sort.Strings(out)
	return out
}

// HasApplied reports whether the client acknowledged applying version.
func (m *Manager) HasApplied(clientID, version string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return version != "" && m.applied[clientID] == version
}

// PolicyVersion is the version of the current tables ("" before the first).
func (m *Manager) PolicyVersion() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.tables == nil {
		return ""
	}
	return m.tables.Version
}

// AcceptsPIDSync reports whether a client may replace the tracked PID set.
// Only the Endpoint Security extension observes leash's process lineage; the
// network filter and the transparent proxy decide which flows to enforce from
// this set, so a set sent by anything else could switch enforcement off for
// the workload.
func (m *Manager) AcceptsPIDSync(clientID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c := m.clients[clientID]
	return c != nil && c.Component == ComponentEndpointSecurity
}

// TrackedPIDList returns the tracked PIDs, sorted.
func (m *Manager) TrackedPIDList() []int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]int, 0, len(m.trackedPIDs))
	for pid := range m.trackedPIDs {
		out = append(out, pid)
	}
	sort.Ints(out)
	return out
}
