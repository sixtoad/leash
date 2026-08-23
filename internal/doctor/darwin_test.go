package doctor

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/strongdm/leash/internal/macext"
)

// Same rule as doctor_test.go: no t.Parallel(), and the macOS hosts are spelled
// out in full rather than mutated one field off a baseline. The macOS states
// that matter (activated-but-disconnected, FDA unknown, daemon down) are not
// one field away from a healthy Mac, and a one-axis table would keep passing
// while the interesting combinations went ungraded.

// macHost returns a fully healthy macOS host: every extension activated and
// connected, the daemon up, FDA reported granted, leashcli in place.
func macHost() Host {
	return Host{
		GOOS:           "darwin",
		EUID:           501,
		DefaultRuntime: "native",
		Darwin: DarwinHost{
			Checked:         true,
			ESExtension:     macext.StateActive,
			FilterExtension: macext.StateActive,
			ProxyExtension:  macext.StateActive,
			DaemonAddr:      DefaultDarwinDaemonAddr,
			DaemonUp:        true,
			ComponentsKnown: true,
			Components: []string{
				macext.ComponentEndpointSecurity,
				macext.ComponentNetworkFilter,
				macext.ComponentTransparentProxy,
			},
			FullDiskAccess:  macext.FDAGranted,
			LeashCLIPath:    DefaultLeashCLIPath,
			LeashCLIPresent: true,
		},
	}
}

func TestDarwinReadinessMatrix(t *testing.T) {
	cases := []struct {
		name string
		// mutate spells out exactly which macOS fact this case removes.
		mutate     func(*DarwinHost)
		want       Status
		wantIssue  string
		wantAbsent string
	}{
		{
			name: "everything activated, connected and granted",
			want: StatusReady,
		},
		{
			// The macOS Layer 1. There is no proxy-only fallback on darwin, so
			// this is unavailable rather than degraded.
			name:      "ES extension not activated",
			mutate:    func(d *DarwinHost) { d.ESExtension = macext.StateMissing },
			want:      StatusUnavailable,
			wantIssue: "file and exec policy is NOT enforced",
		},
		{
			// The failure mode that looks healthiest and enforces least.
			name: "ES activated but not connected to the daemon",
			mutate: func(d *DarwinHost) {
				d.Components = []string{macext.ComponentNetworkFilter, macext.ComponentTransparentProxy}
			},
			want:      StatusUnavailable,
			wantIssue: "activated but is NOT connected",
		},
		{
			name:      "Full Disk Access denied",
			mutate:    func(d *DarwinHost) { d.FullDiskAccess = macext.FDADenied },
			want:      StatusUnavailable,
			wantIssue: "DENIED Full Disk Access",
		},
		{
			name:      "leashcli missing",
			mutate:    func(d *DarwinHost) { d.LeashCLIPresent = false },
			want:      StatusUnavailable,
			wantIssue: "companion leashcli binary is missing",
		},
		{
			// Not a blocker: ES still gates files and exec.
			name: "content filter not activated",
			mutate: func(d *DarwinHost) {
				d.FilterExtension = macext.StateDisabled
				d.Components = []string{macext.ComponentEndpointSecurity, macext.ComponentTransparentProxy}
			},
			want:      StatusDegraded,
			wantIssue: "socket-level network policy is NOT enforced",
		},
		{
			name: "transparent proxy not activated",
			mutate: func(d *DarwinHost) {
				d.ProxyExtension = macext.StateMissing
				d.Components = []string{macext.ComponentEndpointSecurity, macext.ComponentNetworkFilter}
			},
			want:      StatusDegraded,
			wantIssue: "HTTPS is NOT inspected",
		},
		{
			name: "daemon too old to serve /health/darwin",
			mutate: func(d *DarwinHost) {
				d.ComponentsKnown = false
				d.Components = nil
				d.HealthError = "HTTP 404: this daemon predates the /health/darwin endpoint"
				d.FullDiskAccess = macext.FDAUnknown
			},
			want:      StatusDegraded,
			wantIssue: "Upgrade the running daemon",
		},
		{
			// An unverified FDA is not a pass: everything else can look right
			// and LeashES still delivers no events.
			name:      "Full Disk Access never reported",
			mutate:    func(d *DarwinHost) { d.FullDiskAccess = macext.FDAUnknown },
			want:      StatusDegraded,
			wantIssue: "has not heard whether the Endpoint Security extension holds Full Disk Access",
		},
		{
			// systemextensionsctl refused to answer, but every extension holds
			// a websocket to the daemon. The websocket is proof they are
			// running, so the unreadable table changes nothing: grading it as a
			// negative would report a healthy Mac as unable to enforce whenever
			// doctor runs without the rights to read that table.
			name: "extension state unreadable but everything is connected",
			mutate: func(d *DarwinHost) {
				d.ESExtension = macext.StateUnknown
				d.FilterExtension = macext.StateUnknown
				d.ProxyExtension = macext.StateUnknown
				d.ExtensionsDetail = "exit status 69"
			},
			want: StatusReady,
		},
		{
			// Neither signal available. Unverified is a degradation, never a
			// blocker — doctor established that something is wrong with
			// neither, only that it could not tell. And the remedy must not be
			// "click Activate": the extension may be activated already.
			name: "extension state unreadable and the daemon is down",
			mutate: func(d *DarwinHost) {
				d.ESExtension = macext.StateUnknown
				d.FilterExtension = macext.StateUnknown
				d.ProxyExtension = macext.StateUnknown
				d.ExtensionsDetail = "exit status 69"
				d.DaemonUp = false
				d.DaemonError = "connection refused"
				d.ComponentsKnown = false
				d.Components = nil
				d.FullDiskAccess = macext.FDAUnknown
			},
			want:       StatusDegraded,
			wantIssue:  "re-run doctor as an admin user",
			wantAbsent: darwinActivateAdvice,
		},
		{
			// An extension macOS definitely is not running, while the daemon is
			// down: still a blocker. A definite negative from a command that
			// answered is not softened by the missing second signal.
			name: "ES missing and the daemon is down",
			mutate: func(d *DarwinHost) {
				d.ESExtension = macext.StateMissing
				d.DaemonUp = false
				d.DaemonError = "connection refused"
				d.ComponentsKnown = false
				d.Components = nil
				d.FullDiskAccess = macext.FDAUnknown
			},
			want:      StatusUnavailable,
			wantIssue: darwinActivateAdvice,
		},
		{
			// Regression, found by running this against a real Mac: the
			// extensions in Leash.app 1.1.0/20251027.1 connect without a
			// component name, so the daemon lists them as "unknown". Absence
			// from an unattributable list is not evidence of disconnection, and
			// reporting it as one sent the operator to re-activate two
			// extensions that were connected and working.
			name: "a connected client that does not identify itself",
			mutate: func(d *DarwinHost) {
				d.Components = []string{macext.ComponentUnknown}
			},
			want:       StatusDegraded,
			wantIssue:  "has a connected client that does not identify itself",
			wantAbsent: "activated but is NOT connected",
		},
		{
			// A positively named component still counts, though: only the
			// negative conclusion needs every client identified. Here the proxy
			// IS named and IS absent, so its disconnection stays provable.
			name: "one unidentified client does not erase a named one",
			mutate: func(d *DarwinHost) {
				d.Components = []string{macext.ComponentEndpointSecurity, macext.ComponentUnknown}
			},
			want:       StatusDegraded,
			wantAbsent: "the Endpoint Security extension is activated but is NOT connected",
		},
		{
			// Activated, daemon down. The daemon issue already says the
			// extensions are blind; repeating it once per extension would bury
			// the one thing to fix under three copies.
			name: "daemon down does not accuse each extension separately",
			mutate: func(d *DarwinHost) {
				d.DaemonUp = false
				d.DaemonError = "connection refused"
				d.ComponentsKnown = false
				d.Components = nil
				d.FullDiskAccess = macext.FDAUnknown
			},
			want:       StatusDegraded,
			wantIssue:  "the extensions are blind",
			wantAbsent: "activated but is NOT connected",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := macHost()
			if c.mutate != nil {
				c.mutate(&h.Darwin)
			}
			got := Evaluate(h).Darwin
			if got.Status != c.want {
				t.Fatalf("darwin status = %v, want %v\nissues: %s", got.Status, c.want, strings.Join(got.Issues, "\n---\n"))
			}
			joined := strings.Join(got.Issues, "\n")
			if c.wantIssue != "" && !strings.Contains(joined, c.wantIssue) {
				t.Errorf("issues missing %q:\n%s", c.wantIssue, joined)
			}
			if c.wantAbsent != "" && strings.Contains(joined, c.wantAbsent) {
				t.Errorf("issues should not contain %q:\n%s", c.wantAbsent, joined)
			}
			if c.want == StatusReady && len(got.Issues) > 0 {
				t.Errorf("a ready macOS host should have no issues:\n%s", joined)
			}
		})
	}
}

// Every blocker has to be reported at once. An operator who fixes the missing
// leashcli only to be told about the missing extension is running the loop this
// command exists to collapse.
func TestDarwinReportsEveryBlockerAtOnce(t *testing.T) {
	h := macHost()
	h.Darwin.LeashCLIPresent = false
	h.Darwin.ESExtension = macext.StateMissing
	h.Darwin.FullDiskAccess = macext.FDADenied

	issues := strings.Join(Evaluate(h).Darwin.Issues, "\n")
	for _, want := range []string{"companion leashcli binary is missing", "Endpoint Security extension", "DENIED Full Disk Access"} {
		if !strings.Contains(issues, want) {
			t.Errorf("issues missing %q:\n%s", want, issues)
		}
	}
}

// A non-macOS host must read as "not a Mac", not as a broken macOS install —
// and must not drag the verdict down, since it grades a runtime that does not
// apply here.
func TestDarwinSectionOnNonMacHost(t *testing.T) {
	r := Evaluate(readyHost())
	if r.Darwin.Checked {
		t.Error("a Linux host must not report the macOS checks as run")
	}
	if r.Darwin.Status != StatusUnavailable {
		t.Errorf("darwin status = %v, want unavailable", r.Darwin.Status)
	}
	if len(r.Darwin.Issues) != 1 || !strings.Contains(r.Darwin.Issues[0], "this host is linux") {
		t.Errorf("want one 'not a Mac' issue, got %#v", r.Darwin.Issues)
	}
	if r.Verdict() != StatusReady {
		t.Errorf("verdict = %v: a Linux host that enforces must stay ready", r.Verdict())
	}
	for _, u := range r.Unchecked {
		if strings.HasPrefix(u.Name, "macos_") {
			t.Errorf("a Linux host should not declare macOS prerequisites unchecked: %s", u.Name)
		}
	}
}

// The whole point of the section: a Mac that enforces answers exit 0, even
// though `--runtime native` (the Linux backend) is unavailable there.
func TestReadyMacReachesTheVerdict(t *testing.T) {
	r := Evaluate(macHost())
	if r.Verdict() != StatusReady || r.ExitCode() != 0 {
		t.Fatalf("verdict/exit = %v/%d, want ready/0", r.Verdict(), r.ExitCode())
	}
	if r.Native.Status != StatusUnavailable {
		t.Errorf("native on darwin should still be unavailable, got %v", r.Native.Status)
	}
	// ... and the reader is told that a bare `leash run` will not get them
	// there, because it selects the native runtime and never falls back.
	text := r.Text()
	if !strings.Contains(text, "NOTE: `leash run` with no --runtime uses the native runtime") {
		t.Errorf("a ready Mac must still warn that the default runtime is not the one that works:\n%s", text)
	}
}

// A degraded Mac has to be non-zero, for the same reason a Layer-1-less Linux
// host is: a provisioner gating on `leash doctor && ...` must fail closed.
func TestDegradedMacExitsNonZero(t *testing.T) {
	h := macHost()
	h.Darwin.FullDiskAccess = macext.FDAUnknown
	if got := Evaluate(h).ExitCode(); got != 3 {
		t.Errorf("exit = %d, want 3", got)
	}
}

// The two ways connectivity goes unproven have nothing alike as remedies, so
// the unchecked entry has to say which one happened.
func TestConnectivityUncheckedNamesWhichGap(t *testing.T) {
	reasonFor := func(mutate func(*DarwinHost)) string {
		h := macHost()
		mutate(&h.Darwin)
		for _, u := range Evaluate(h).Unchecked {
			if u.Name == "macos_extension_connectivity" {
				return u.Reason
			}
		}
		return ""
	}

	down := reasonFor(func(d *DarwinHost) {
		d.DaemonUp = false
		d.ComponentsKnown = false
		d.Components = nil
	})
	if !strings.Contains(down, "could not be asked") {
		t.Errorf("a down daemon should say so: %q", down)
	}

	anonymous := reasonFor(func(d *DarwinHost) { d.Components = []string{macext.ComponentUnknown} })
	if !strings.Contains(anonymous, "did not identify itself") {
		t.Errorf("an unattributable client should say so: %q", anonymous)
	}

	if reasonFor(func(*DarwinHost) {}) != "" {
		t.Error("a fully identified client list leaves nothing unchecked here")
	}
}

func TestDarwinUncheckedNamesMissingEvidence(t *testing.T) {
	h := macHost()
	h.Darwin.DaemonUp = false
	h.Darwin.ComponentsKnown = false
	h.Darwin.Components = nil
	h.Darwin.FullDiskAccess = macext.FDAUnknown
	h.Darwin.ESExtension = macext.StateUnknown
	h.Darwin.ExtensionsDetail = "exit status 69"

	names := map[string]string{}
	for _, u := range Evaluate(h).Unchecked {
		names[u.Name] = u.Reason
	}
	for _, want := range []string{"macos_extension_activation", "macos_extension_connectivity", "macos_full_disk_access", "macos_ne_configuration"} {
		if names[want] == "" {
			t.Errorf("unchecked missing %q, got %v", want, names)
		}
	}

	// On a fully healthy Mac only the NE-configuration inference stays
	// unchecked; the other two were established.
	healthy := map[string]bool{}
	for _, u := range Evaluate(macHost()).Unchecked {
		healthy[u.Name] = true
	}
	if healthy["macos_full_disk_access"] || healthy["macos_extension_connectivity"] || healthy["macos_extension_activation"] {
		t.Errorf("established facts should not be declared unchecked: %v", healthy)
	}
	if !healthy["macos_ne_configuration"] {
		t.Error("the NE-configuration inference is always declared, since doctor never reads it directly")
	}
}

func TestDarwinJSONShape(t *testing.T) {
	out, err := json.Marshal(Evaluate(macHost()))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(out)
	for _, want := range []string{
		`"darwin":{`,
		`"checked":true`,
		`"es_extension":"active"`,
		`"filter_extension":"active"`,
		`"proxy_extension":"active"`,
		`"full_disk_access":"granted"`,
		`"daemon_up":true`,
		`"components":["leash.es","leash.netfilter","leash.proxy"]`,
		`"leash_cli":"` + DefaultLeashCLIPath + `"`,
		`"verdict":"ready"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("JSON missing %s:\n%s", want, got)
		}
	}

	// A zero Report must still emit a complete macOS section, never nulls.
	zero, err := json.Marshal(Report{})
	if err != nil {
		t.Fatalf("marshal zero: %v", err)
	}
	for _, want := range []string{`"es_extension":"unknown"`, `"full_disk_access":"unknown"`, `"components":[]`, `"checked":false`} {
		if !strings.Contains(string(zero), want) {
			t.Errorf("json.Marshal(Report{}) missing %s: %s", want, zero)
		}
	}
}

// A macOS document from a future leash must not decode into a confident wrong
// answer, exactly as for the Linux states.
func TestDarwinRejectsUnknownStates(t *testing.T) {
	for _, doc := range []string{
		`{"darwin":{"es_extension":"probably"}}`,
		`{"darwin":{"full_disk_access":"maybe"}}`,
		`{"darwin":{"status":"fine"}}`,
	} {
		var r Report
		if err := json.Unmarshal([]byte(doc), &r); err == nil {
			t.Errorf("decoding %s should fail rather than yield %#v", doc, r)
		}
	}
}

func TestDarwinTextRendersFactsOnlyWhenProbed(t *testing.T) {
	mac := Evaluate(macHost()).Text()
	for _, want := range []string{"macOS enforcement: READY", "ES extension:     active", "full disk access: granted", "daemon:           up (127.0.0.1:18080)", "connected:        leash.es, leash.netfilter, leash.proxy"} {
		if !strings.Contains(mac, want) {
			t.Errorf("macOS text missing %q:\n%s", want, mac)
		}
	}

	// On a Linux host the section is still there (same facts, same order as the
	// JSON) but carries no unknown-valued fact lines, which would read as macOS
	// enforcement being broken rather than absent.
	linux := Evaluate(readyHost()).Text()
	if !strings.Contains(linux, "macOS enforcement:") {
		t.Errorf("the macOS section must still head the Linux report:\n%s", linux)
	}
	if strings.Contains(linux, "ES extension:") || strings.Contains(linux, "full disk access:") {
		t.Errorf("a Linux report must not print unprobed macOS facts:\n%s", linux)
	}
}

// --- the probe -------------------------------------------------------------

// stubDarwinProbes replaces the three seams for one test and restores them.
func stubDarwinProbes(t *testing.T, list func() (string, error), get func(string) (int, []byte, error), stat func(string) error) {
	t.Helper()
	origList, origGet, origStat := systemExtensionsList, darwinHTTPGet, statFile
	t.Cleanup(func() { systemExtensionsList, darwinHTTPGet, statFile = origList, origGet, origStat })
	systemExtensionsList, darwinHTTPGet, statFile = list, get, stat
}

const activeExtensionList = `3 extension(s)
--- com.apple.system_extension.endpoint_security
enabled	active	teamID	bundleID (version)	name	[state]
*	*	W5HSYBBJGA	com.strongdm.leash.LeashES (1.0/1)	LeashES	[activated enabled]
--- com.apple.system_extension.network_extension
enabled	active	teamID	bundleID (version)	name	[state]
*	*	W5HSYBBJGA	com.strongdm.leash.LeashNetworkFilter (1.0/1)	LeashNetworkFilter	[activated enabled]
*		W5HSYBBJGA	com.strongdm.leash.LeashProxy (1.0/1)	LeashProxy	[activated waiting for user]
`

func TestProbeDarwinReadsEveryFact(t *testing.T) {
	health := macext.DaemonHealth{
		Components:     []string{macext.ComponentEndpointSecurity, macext.ComponentNetworkFilter},
		FullDiskAccess: "granted",
	}
	body, err := json.Marshal(health)
	if err != nil {
		t.Fatalf("marshal health: %v", err)
	}
	stubDarwinProbes(t,
		func() (string, error) { return activeExtensionList, nil },
		func(url string) (int, []byte, error) {
			switch {
			case strings.HasSuffix(url, "/healthz"):
				return http.StatusOK, []byte("ok"), nil
			case strings.HasSuffix(url, "/health/darwin"):
				return http.StatusOK, body, nil
			}
			return http.StatusNotFound, nil, nil
		},
		func(string) error { return nil },
	)

	d := probeDarwinFacts(ProbeOptions{})
	if !d.Checked {
		t.Fatal("probeDarwinFacts must mark the macOS checks as run")
	}
	if d.ESExtension != macext.StateActive || d.FilterExtension != macext.StateActive {
		t.Errorf("ES/filter = %v/%v, want active/active", d.ESExtension, d.FilterExtension)
	}
	// The proxy row is enabled but not active: approval is still pending.
	if d.ProxyExtension != macext.StateDisabled {
		t.Errorf("proxy = %v, want disabled", d.ProxyExtension)
	}
	if !d.DaemonUp || !d.ComponentsKnown {
		t.Errorf("daemon up=%v componentsKnown=%v, want both true (%s)", d.DaemonUp, d.ComponentsKnown, d.DaemonError+d.HealthError)
	}
	if d.FullDiskAccess != macext.FDAGranted {
		t.Errorf("fda = %v, want granted", d.FullDiskAccess)
	}
	if !d.LeashCLIPresent {
		t.Error("leashcli should be reported present")
	}

	// End to end: the proxy pending approval is exactly one degradation.
	r := Evaluate(Host{GOOS: "darwin", Darwin: d})
	if r.Darwin.Status != StatusDegraded {
		t.Errorf("status = %v, want degraded", r.Darwin.Status)
	}
}

// An old daemon must be distinguishable from a dead one: the remedies differ.
func TestProbeDarwinSeparatesOldDaemonFromDeadDaemon(t *testing.T) {
	stubDarwinProbes(t,
		func() (string, error) { return activeExtensionList, nil },
		func(url string) (int, []byte, error) {
			if strings.HasSuffix(url, "/healthz") {
				return http.StatusOK, []byte("ok"), nil
			}
			return http.StatusNotFound, nil, nil
		},
		func(string) error { return nil },
	)
	d := probeDarwinFacts(ProbeOptions{})
	if !d.DaemonUp {
		t.Fatal("the daemon answered /healthz, so it is up")
	}
	if d.ComponentsKnown || !strings.Contains(d.HealthError, "predates") {
		t.Errorf("want a 404-specific health error, got known=%v err=%q", d.ComponentsKnown, d.HealthError)
	}

	stubDarwinProbes(t,
		func() (string, error) { return activeExtensionList, nil },
		func(string) (int, []byte, error) { return 0, nil, errors.New("connection refused") },
		func(string) error { return nil },
	)
	if d := probeDarwinFacts(ProbeOptions{}); d.DaemonUp || !strings.Contains(d.DaemonError, "connection refused") {
		t.Errorf("want a down daemon carrying the dial error, got up=%v err=%q", d.DaemonUp, d.DaemonError)
	}
}

// systemextensionsctl exits EX_NOPERM without admin rights. That is "we could
// not ask", never "not installed" — the difference decides whether the operator
// is sent to approve an extension that is already approved.
func TestProbeDarwinUnreadableExtensionsAreUnknown(t *testing.T) {
	stubDarwinProbes(t,
		func() (string, error) {
			return "systemextensionsctl: administrator privileges required\n", errors.New("exit status 69")
		},
		func(string) (int, []byte, error) { return 0, nil, errors.New("connection refused") },
		func(string) error { return errors.New("no such file") },
	)
	d := probeDarwinFacts(ProbeOptions{})
	if d.ESExtension != macext.StateUnknown || d.ProxyExtension != macext.StateUnknown {
		t.Errorf("states = %v/%v, want unknown", d.ESExtension, d.ProxyExtension)
	}
	if !strings.Contains(d.ExtensionsDetail, "exit status 69") || !strings.Contains(d.ExtensionsDetail, "administrator privileges") {
		t.Errorf("detail should carry both the error and what the command said: %q", d.ExtensionsDetail)
	}
	if d.LeashCLIPresent {
		t.Error("a failing stat must not report leashcli as present")
	}
}

// A daemon that answers something other than a decodable health document must
// leave connectivity unknown rather than reporting an empty component list as
// fact.
func TestProbeDarwinRejectsUndecodableHealth(t *testing.T) {
	stubDarwinProbes(t,
		func() (string, error) { return activeExtensionList, nil },
		func(url string) (int, []byte, error) { return http.StatusOK, []byte("<html>not json</html>"), nil },
		func(string) error { return nil },
	)
	d := probeDarwinFacts(ProbeOptions{})
	if d.ComponentsKnown {
		t.Error("an undecodable body must not establish connectivity")
	}
	if !strings.Contains(d.HealthError, "decode") {
		t.Errorf("health error should name the decode failure: %q", d.HealthError)
	}
}

func TestDarwinDaemonAddrResolution(t *testing.T) {
	t.Setenv("LEASH_LISTEN", "")
	cases := []struct{ flag, env, want string }{
		{want: DefaultDarwinDaemonAddr},
		{flag: "127.0.0.1:9999", want: "127.0.0.1:9999"},
		// The daemon's own bind syntax allows the host to be omitted; doctor
		// has to dial it, and loopback is the only interface it may assume.
		{flag: ":18080", want: "127.0.0.1:18080"},
		{flag: "18080", want: "127.0.0.1:18080"},
		{flag: "0.0.0.0:8127", want: "127.0.0.1:8127"},
		{env: ":8127", want: "127.0.0.1:8127"},
		// The flag wins over the environment.
		{flag: "127.0.0.1:1", env: ":2", want: "127.0.0.1:1"},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("flag=%q env=%q", c.flag, c.env), func(t *testing.T) {
			t.Setenv("LEASH_LISTEN", c.env)
			if got := darwinDaemonAddr(ProbeOptions{DarwinDaemonAddr: c.flag}); got != c.want {
				t.Errorf("addr = %q, want %q", got, c.want)
			}
		})
	}
}

func TestLeashCLIPathOverride(t *testing.T) {
	if got := leashCLIPath(ProbeOptions{}); got != DefaultLeashCLIPath {
		t.Errorf("default = %q, want %q", got, DefaultLeashCLIPath)
	}
	if got := leashCLIPath(ProbeOptions{LeashCLIPath: "/tmp/leashcli"}); got != "/tmp/leashcli" {
		t.Errorf("override = %q", got)
	}
}

// An "activated but not connected" transparent proxy must not get the generic
// re-activate advice. Found on the validation VM: after a silent system-extension
// version bump, systemextensionsctl reported LeashProxy as [activated enabled]
// while its provider process did not exist at all, and re-activating the
// extension did not bring it back — the dropped NETransparentProxyManager
// configuration has to be re-enabled.
func TestDisconnectedProxyGetsItsOwnRemedy(t *testing.T) {
	h := macHost()
	h.Darwin.Components = []string{macext.ComponentEndpointSecurity, macext.ComponentNetworkFilter}

	r := Evaluate(h).Darwin
	if r.Status != StatusDegraded {
		t.Fatalf("status = %v, want degraded", r.Status)
	}
	issues := strings.Join(r.Issues, "\n")
	if !strings.Contains(issues, "Network ▸ Filters & Proxies") {
		t.Errorf("the proxy needs its configuration re-enabled, not a re-activation:\n%s", issues)
	}
	if !strings.Contains(issues, "127.0.0.1:18080") {
		t.Errorf("the remedy should name the daemon address:\n%s", issues)
	}

	// The other two keep the generic remedy, which is the right one for them.
	h = macHost()
	h.Darwin.Components = []string{macext.ComponentEndpointSecurity, macext.ComponentTransparentProxy}
	issues = strings.Join(Evaluate(h).Darwin.Issues, "\n")
	if !strings.Contains(issues, "remove and re-activate it from Leash.app") {
		t.Errorf("the content filter should get the re-activate remedy:\n%s", issues)
	}
	if strings.Contains(issues, "Filters & Proxies") {
		t.Errorf("the content filter should not get the proxy remedy:\n%s", issues)
	}
}
