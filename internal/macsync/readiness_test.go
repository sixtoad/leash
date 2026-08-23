package macsync

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/strongdm/leash/internal/macext"
	"github.com/strongdm/leash/internal/messages"
)

func fdaEvent(name string, at time.Time) *messages.MacEventPayload {
	return &messages.MacEventPayload{Time: at, Event: name, Source: ComponentEndpointSecurity}
}

// Nothing heard means nothing known. A daemon that has never seen LeashES
// report must not imply a grant — that is the false assurance `leash doctor`
// exists to prevent, and the whole reason this state is tri-valued.
func TestFullDiskAccessStartsUnknown(t *testing.T) {
	m := NewManager(nil)
	if state, at := m.FullDiskAccessState(); state != macext.FDAUnknown || !at.IsZero() {
		t.Fatalf("fresh manager = %v at %v, want unknown at zero time", state, at)
	}
	if got := m.Health().FullDiskAccess; got != "unknown" {
		t.Errorf("health full_disk_access = %q, want unknown", got)
	}
}

func TestFullDiskAccessRecordsBothReports(t *testing.T) {
	for _, c := range []struct {
		event string
		want  macext.FDA
	}{
		{eventFDAReady, macext.FDAGranted},
		{eventFDAMissing, macext.FDADenied},
	} {
		t.Run(c.event, func(t *testing.T) {
			m := NewManager(nil)
			// LogMacEvent errors without a logger; the readiness fact must be
			// recorded anyway, or running the daemon without a log file would
			// silently cost doctor its only FDA signal.
			_ = m.LogMacEvent(fdaEvent(c.event, time.Unix(1000, 0)))
			if state, _ := m.FullDiskAccessState(); state != c.want {
				t.Fatalf("state = %v, want %v", state, c.want)
			}
		})
	}
}

// macOS relaunches LeashES after an FDA failure, so events from an old launch
// can arrive out of order. Ordering by the observation time is what keeps a
// stale "ready" from overwriting the "missing" that followed it.
func TestFullDiskAccessOrdersByObservationTime(t *testing.T) {
	newer, older := time.Unix(2000, 0), time.Unix(1000, 0)

	m := NewManager(nil)
	_ = m.LogMacEvent(fdaEvent(eventFDAMissing, newer))
	_ = m.LogMacEvent(fdaEvent(eventFDAReady, older))
	if state, _ := m.FullDiskAccessState(); state != macext.FDADenied {
		t.Errorf("a stale ready overwrote a newer denial: %v", state)
	}

	m = NewManager(nil)
	_ = m.LogMacEvent(fdaEvent(eventFDAMissing, older))
	_ = m.LogMacEvent(fdaEvent(eventFDAReady, newer))
	if state, _ := m.FullDiskAccessState(); state != macext.FDAGranted {
		t.Errorf("a newer grant did not win: %v", state)
	}
}

// Only the two names are readiness signals. A new es.full_disk_access.* event
// should have to be interpreted deliberately rather than absorbed by prefix.
func TestUnrelatedEventsLeaveFullDiskAccessAlone(t *testing.T) {
	m := NewManager(nil)
	_ = m.LogMacEvent(fdaEvent(eventFDAReady, time.Unix(1000, 0)))
	_ = m.LogMacEvent(fdaEvent("es.full_disk_access.rechecked", time.Unix(2000, 0)))
	_ = m.LogMacEvent(fdaEvent("es.boot", time.Unix(3000, 0)))
	if state, _ := m.FullDiskAccessState(); state != macext.FDAGranted {
		t.Errorf("state = %v, want the grant to survive unrelated events", state)
	}
}

// Health is what `leash doctor` reads over /health/darwin, so it has to encode
// to the shape doctor decodes — including empty (never null) components.
func TestHealthEncodesWhatDoctorReads(t *testing.T) {
	m := NewManager(nil)
	m.RegisterClient("a", &messages.ClientHelloPayload{Platform: "darwin", Component: ComponentEndpointSecurity})
	m.RegisterClient("b", &messages.ClientHelloPayload{Platform: "darwin", Component: ComponentNetworkFilter})
	_ = m.LogMacEvent(fdaEvent(eventFDAReady, time.Unix(1700000000, 0)))

	body, err := json.Marshal(m.Health())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded macext.DaemonHealth
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("the health document must decode back: %v (%s)", err, body)
	}
	if macext.ParseFDA(decoded.FullDiskAccess) != macext.FDAGranted {
		t.Errorf("full_disk_access = %q", decoded.FullDiskAccess)
	}
	if len(decoded.Components) != 2 {
		t.Errorf("components = %v, want the two registered clients", decoded.Components)
	}
	if decoded.FullDiskAccessAt == "" {
		t.Error("the observation time should be reported, so a reader can tell a fresh report from an old one")
	}

	empty, err := json.Marshal(NewManager(nil).Health())
	if err != nil {
		t.Fatalf("marshal empty: %v", err)
	}
	if string(empty) == "" || !json.Valid(empty) {
		t.Fatalf("invalid document: %s", empty)
	}
	var none macext.DaemonHealth
	if err := json.Unmarshal(empty, &none); err != nil || none.Components == nil {
		t.Errorf("components must be [] rather than null: %s", empty)
	}
}

func esClient(caps ...string) *messages.ClientHelloPayload {
	return &messages.ClientHelloPayload{
		Platform: "darwin", Component: ComponentEndpointSecurity, Capabilities: caps,
	}
}

// The gap this closes, measured on the validation VM: LeashES emits its FDA
// event once per process launch, so a daemon started after the extension saw
// nothing across 139 reconnects and doctor could never confirm the grant. The
// hello is re-sent on every reconnect, so carrying the capability there makes
// the signal survive a daemon restart.
func TestConnectedESClientAdvertisingTheCapabilityEstablishesFDA(t *testing.T) {
	m := NewManager(nil)
	if state, _ := m.FullDiskAccessState(); state != macext.FDAUnknown {
		t.Fatalf("precondition: fresh manager = %v", state)
	}

	// A reconnect after a daemon restart: no event will ever arrive for this
	// process, only the hello.
	m.RegisterClient("es", esClient("pid-sync", macext.CapabilityFullDiskAccess))

	state, at := m.FullDiskAccessState()
	if state != macext.FDAGranted {
		t.Errorf("state = %v, want granted from the hello alone", state)
	}
	if at.IsZero() {
		t.Error("the grant should carry the time the client was seen")
	}
	if got := m.Health().FullDiskAccess; got != "granted" {
		t.Errorf("health = %q, want granted", got)
	}
}

// The advertisement must not outlive the process it describes: LeashES exits
// when denied, so a disconnect has to take the grant with it.
func TestFDAAdvertisementDiesWithTheClient(t *testing.T) {
	m := NewManager(nil)
	m.RegisterClient("es", esClient(macext.CapabilityFullDiskAccess))
	m.UnregisterClient("es")
	if state, _ := m.FullDiskAccessState(); state != macext.FDAUnknown {
		t.Errorf("state = %v, want unknown once the client is gone", state)
	}
}

// Only LeashES's own claim counts. Another component advertising the tag says
// nothing about the ES client, which is the only process the grant is about.
func TestOnlyTheESComponentCanAdvertiseFDA(t *testing.T) {
	m := NewManager(nil)
	m.RegisterClient("filter", &messages.ClientHelloPayload{
		Platform: "darwin", Component: ComponentNetworkFilter,
		Capabilities: []string{macext.CapabilityFullDiskAccess},
	})
	if state, _ := m.FullDiskAccessState(); state != macext.FDAUnknown {
		t.Errorf("state = %v, want unknown", state)
	}
}

// An extension too old to advertise leaves the event as the only signal, and it
// must still work — that is every deployed build before this change.
func TestOlderExtensionsStillFallBackToTheEvent(t *testing.T) {
	m := NewManager(nil)
	m.RegisterClient("es", esClient("pid-sync", "rule-sync"))
	if state, _ := m.FullDiskAccessState(); state != macext.FDAUnknown {
		t.Fatalf("a client that advertises nothing establishes nothing, got %v", state)
	}
	_ = m.LogMacEvent(fdaEvent(eventFDAReady, time.Unix(1000, 0)))
	if state, _ := m.FullDiskAccessState(); state != macext.FDAGranted {
		t.Errorf("the startup event must still be honoured, got %v", state)
	}
}

// Live evidence beats a recorded one: a stale denial from a previous launch
// must not mask a LeashES that is connected and advertising the grant now.
func TestLiveCapabilityBeatsAStaleDenial(t *testing.T) {
	m := NewManager(nil)
	_ = m.LogMacEvent(fdaEvent(eventFDAMissing, time.Unix(1000, 0)))
	m.RegisterClient("es", esClient(macext.CapabilityFullDiskAccess))
	if state, _ := m.FullDiskAccessState(); state != macext.FDAGranted {
		t.Errorf("state = %v, want granted: a connected ES client got past es_new_client", state)
	}
}
