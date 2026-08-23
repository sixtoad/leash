package doctor

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/strongdm/leash/internal/macext"
	"github.com/strongdm/leash/internal/macsync"
	"github.com/strongdm/leash/internal/messages"
	"github.com/strongdm/leash/internal/runner"
)

// The contract between the daemon and doctor spans two packages and a socket,
// which is exactly where a hand-mirrored document drifts. The stubbed probe
// tests above prove doctor's grading; this one proves the thing being graded is
// what the daemon actually emits — a real macsync.Manager, encoded by the real
// health document, fetched over a real HTTP connection by the real probe.
//
// Without it, renaming a JSON field on one side leaves both packages' own tests
// green while `leash doctor` silently reports every extension as disconnected
// and Full Disk Access as unknown on a perfectly healthy Mac.
func TestDarwinProbeReadsTheDaemonsRealHealthDocument(t *testing.T) {
	manager := macsync.NewManager(nil)
	for _, component := range []string{
		macext.ComponentEndpointSecurity,
		macext.ComponentNetworkFilter,
		macext.ComponentTransparentProxy,
	} {
		manager.RegisterClient(component, &messages.ClientHelloPayload{Platform: "darwin", Component: component})
	}
	_ = manager.LogMacEvent(&messages.MacEventPayload{
		Time:   time.Unix(1700000000, 0),
		Event:  "es.full_disk_access.ready",
		Source: macext.ComponentEndpointSecurity,
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/health/darwin", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if err := json.NewEncoder(w).Encode(manager.Health()); err != nil {
			t.Errorf("encode health: %v", err)
		}
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	// Only systemextensionsctl and the leashcli stat are stubbed: those are the
	// two facts that genuinely come from this machine and cannot be staged. The
	// daemon half goes over the wire.
	stubDarwinProbes(t,
		func() (string, error) { return activeExtensionList, nil },
		darwinHTTPGet,
		func(string) error { return nil },
	)

	addr := strings.TrimPrefix(server.URL, "http://")
	d := probeDarwinFacts(ProbeOptions{DarwinDaemonAddr: addr})

	if !d.DaemonUp {
		t.Fatalf("daemon should be up: %s", d.DaemonError)
	}
	if !d.ComponentsKnown {
		t.Fatalf("the health document should have been read: %s", d.HealthError)
	}
	if d.FullDiskAccess != macext.FDAGranted {
		t.Errorf("fda = %v, want granted — the daemon reported a grant", d.FullDiskAccess)
	}
	for _, want := range []string{
		macext.ComponentEndpointSecurity,
		macext.ComponentNetworkFilter,
		macext.ComponentTransparentProxy,
	} {
		if !connected(d, want) {
			t.Errorf("component %s should be seen as connected, got %v", want, d.Components)
		}
	}

	// The proxy extension is pending approval in the fixture, so the whole
	// thing grades as exactly one degradation and nothing else.
	r := Evaluate(Host{GOOS: "darwin", DefaultRuntime: "native", Darwin: d})
	if r.Darwin.Status != StatusDegraded {
		t.Fatalf("status = %v, want degraded\n%s", r.Darwin.Status, strings.Join(r.Darwin.Issues, "\n"))
	}
	if len(r.Darwin.Issues) != 1 || !strings.Contains(r.Darwin.Issues[0], "transparent-proxy extension") {
		t.Errorf("want only the pending proxy extension, got %#v", r.Darwin.Issues)
	}
}

// The macOS section must not borrow the Linux summary. "Layer 1 is off but the
// proxy still applies" describes neither layer that exists on macOS, and it
// reads as authoritative.
func TestDegradedMacDoesNotBorrowTheLinuxSummary(t *testing.T) {
	h := macHost()
	h.Darwin.FullDiskAccess = macext.FDAUnknown
	text := Evaluate(h).Text()

	if !strings.Contains(text, "macOS enforcement: DEGRADED (runs, not fully enforcing)") {
		t.Errorf("the macOS section needs its own gloss:\n%s", text)
	}
	if !strings.Contains(text, darwinDegradedConsequence) {
		t.Errorf("the result should name what macOS is missing:\n%s", text)
	}
	if strings.Contains(text, layer1Consequence) {
		t.Errorf("a Mac's verdict must not be explained with the eBPF LSM:\n%s", text)
	}
}

// ... and the reverse: a degraded Linux host keeps its own summary and gains no
// macOS sentence.
func TestDegradedLinuxKeepsItsSummary(t *testing.T) {
	h := readyHost()
	h.BPFLSM = runner.LSMInactive
	h.BPFLSMAdvice = "reboot with bpf in the lsm list"
	text := Evaluate(h).Text()

	if !strings.Contains(text, layer1Consequence) {
		t.Errorf("the Layer 1 sentence should still explain a Linux degradation:\n%s", text)
	}
	if strings.Contains(text, darwinDegradedConsequence) {
		t.Errorf("a Linux host must not be told about macOS layers:\n%s", text)
	}
}
