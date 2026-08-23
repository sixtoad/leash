package doctor

import (
	"fmt"
	"strings"

	"github.com/strongdm/leash/internal/macext"
)

// This file is doctor's macOS half, and it is a separate runtime rather than a
// branch inside evaluateNative because macOS enforcement is a different thing
// wearing the same word. `--runtime native` on Linux means leashd plus eBPF LSM
// programs; the macOS path is `leash --darwin`, which enforces through three
// system extensions and a daemon they talk to. Grading it under "native" would
// have meant a section whose every field means something else depending on
// GOOS, and a "not linux" issue standing in for a machine that enforces fine.
//
// Like doctor.go, everything here is pure: the facts arrive in DarwinHost and
// probe_darwin.go is the only part that touches the machine.
//
// The shape of the macOS failure modes is what drives the grading. Two signals
// are needed per extension, and neither substitutes for the other:
//
//   - ACTIVATION (systemextensionsctl): the user approved it, so macOS will
//     let the code run. An extension that is not activated is not running.
//   - CONNECTION (the daemon's client registry): it is running AND holds a
//     websocket to the daemon, so it receives PID and rule broadcasts. An
//     activated extension that never connected enforces nothing (leash #62) —
//     it has no policy to enforce.
//
// Full Disk Access is the third, and it is the one with no external probe at
// all: macOS exposes no API for reading another process's TCC grant, and the
// tempting substitutes answer a different question (a TCC-gated path tells you
// about whoever ran doctor). The signal used here is LeashES's own — it calls
// es_new_client, gets ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED without FDA, and
// reports that to the daemon before exiting. Doctor reads it back out of the
// daemon. When the daemon has heard nothing (it was started after LeashES, so
// it missed the event), FDA is UNKNOWN and this report refuses to reach ready:
// an unverified FDA is exactly the case where ES appears healthy and delivers
// no AUTH_OPEN events at all.

// DarwinHost is the macOS half of Host: everything a readiness decision about
// `leash --darwin` is made from. Probe fills it on macOS; on every other
// platform it stays zero and Checked stays false.
type DarwinHost struct {
	// Checked records that doctor actually ran the macOS probes. It is the
	// difference between "macOS enforcement is broken" and "this is not a Mac",
	// which the zero values alone cannot express — every state below reads as
	// its cautious value when nothing was probed.
	Checked bool

	// ES/Filter/Proxy are the activation states of leash's three system
	// extensions, from `systemextensionsctl list`. Unknown means the command
	// could not be consulted (it exits EX_NOPERM without admin rights), which
	// is not the same as "not installed" and gets its own advice.
	ESExtension     macext.State
	FilterExtension macext.State
	ProxyExtension  macext.State

	// ExtensionsDetail is why the activation states are unknown — the error
	// from systemextensionsctl — or "" when it answered.
	ExtensionsDetail string

	// DaemonAddr is where doctor looked for the `leash --darwin` daemon
	// (127.0.0.1:18080), reported so a reader can tell a wrong-port miss from a
	// daemon that is genuinely down.
	DaemonAddr string

	// DaemonUp is whether that daemon answered. DaemonError carries the reason
	// it did not.
	DaemonUp    bool
	DaemonError string

	// Components are the leash components currently holding a websocket to the
	// daemon, from its /health/darwin endpoint. ComponentsKnown is false when
	// the daemon is down or too old to serve that endpoint — an empty list from
	// an unanswered endpoint must never read as "nothing is connected".
	Components      []string
	ComponentsKnown bool

	// HealthError is why /health/darwin did not answer, when the daemon itself
	// was reachable. That combination means an older daemon, and the remedy is
	// different from "start the daemon".
	HealthError string

	// FullDiskAccess is LeashES's TCC grant as the daemon last heard it. Only
	// meaningful when ComponentsKnown is true; unknown otherwise.
	FullDiskAccess macext.FDA

	// LeashCLIPath is where doctor looked for the companion leashcli binary the
	// `--darwin` runtime execs, and LeashCLIPresent whether it was there.
	LeashCLIPath    string
	LeashCLIPresent bool
}

// DarwinReport covers the `leash --darwin` runtime: the macOS section of the
// readiness document. The field names are contract, like the rest of Report.
type DarwinReport struct {
	// Checked mirrors DarwinHost.Checked into the document, so a consumer can
	// distinguish "graded and unavailable" from "never probed, because this is
	// not a Mac" without inspecting the issue text.
	Checked bool `json:"checked"`

	Status Status `json:"status"`

	ESExtension     macext.State `json:"es_extension"`
	FilterExtension macext.State `json:"filter_extension"`
	ProxyExtension  macext.State `json:"proxy_extension"`

	FullDiskAccess macext.FDA `json:"full_disk_access"`

	DaemonUp bool   `json:"daemon_up"`
	Daemon   string `json:"daemon"`

	// Components is what the daemon reported as connected, or an empty list
	// when it could not be asked. The Issues say which, so the empty list is
	// never left to be read as an answer.
	Components []string `json:"components"`

	LeashCLI string   `json:"leash_cli"`
	Issues   []string `json:"issues"`
}

// Ready mirrors NativeReport.Ready: only a runtime enforcing every layer counts.
func (d DarwinReport) Ready() bool { return d.Status == StatusReady }

// The macOS analogue of layer1Consequence: the sentence that says what the
// degraded state actually costs. Named once so the text and the JSON issues
// cannot describe the same state differently.
const (
	darwinESConsequence     = "file and exec policy is NOT enforced: the Endpoint Security extension is what gates them on macOS, and there is no fallback layer (unlike Linux, `leash --darwin` has no proxy-only mode)."
	darwinFilterConsequence = "socket-level network policy is NOT enforced: the content filter is what gates connections on macOS."
	darwinProxyConsequence  = "HTTPS is NOT inspected or rewritten: the transparent-proxy extension is what feeds flows to leash's MITM proxy, so URL/header policy and MCP rewriting do not apply."
	darwinDaemonConsequence = "the extensions are blind: they receive no tracked PIDs and no rules over the websocket, so whatever is activated is enforcing nothing."

	// The one-line summary for a degraded macOS verdict. It is deliberately not
	// the Linux sentence: macOS has no eBPF LSM and no proxy-only fallback, so
	// "Layer 1 is off, Layer 2 still applies" describes nothing that is true here.
	darwinDegradedConsequence = "macOS enforcement is partial: some of the file/exec, socket and HTTPS-inspection layers are not active, or could not be verified. The issues above say which."
)

const darwinActivateAdvice = "Open Leash.app and click Activate, then approve it in System Settings ▸ General ▸ Login Items & Extensions."

// Remedies for an extension that macOS says is activated but that is not
// talking to the daemon. %s is the daemon address.
const (
	darwinReactivateRemedy = "Restart it (remove and re-activate it from Leash.app) so it reconnects to %s."

	// The transparent proxy has its own, because "activated" and "running" come
	// apart for it in a way they do not for the other two: a system-extension
	// version bump drops the NETransparentProxyManager configuration, and
	// systemextensionsctl still reports [activated enabled] for an extension
	// whose provider process is gone. Re-activating the extension does not
	// restore it — the configuration has to be turned back on.
	darwinProxyReconnectRemedy = "Check System Settings ▸ Network ▸ Filters & Proxies and re-enable the leash proxy: a system-extension version bump drops its configuration, and systemextensionsctl still reports it as activated even though its provider is not running. Then re-open Leash.app so it reconnects to %s."
)

// reconnectRemedy fills the daemon address into the extension's remedy, falling
// back to the generic one so a new extension added without a remedy still gets
// an actionable next step rather than a bare statement of the fault.
func reconnectRemedy(e extension, d DarwinHost) string {
	remedy := e.reconnectRemedy
	if strings.TrimSpace(remedy) == "" {
		remedy = darwinReactivateRemedy
	}
	return fmt.Sprintf(remedy, quoteAddr(d.DaemonAddr))
}

// evaluateDarwin grades the `leash --darwin` runtime. It is the whole macOS
// decision, and it is pure.
func evaluateDarwin(h Host) DarwinReport {
	d := h.Darwin
	r := DarwinReport{
		Checked:         d.Checked,
		ESExtension:     d.ESExtension,
		FilterExtension: d.FilterExtension,
		ProxyExtension:  d.ProxyExtension,
		FullDiskAccess:  d.FullDiskAccess,
		DaemonUp:        d.DaemonUp,
		Daemon:          strings.TrimSpace(d.DaemonAddr),
		// Copied so the report never aliases the caller's Host, for the same
		// reason ContainerReport copies the engine name.
		Components: append([]string{}, d.Components...),
		LeashCLI:   strings.TrimSpace(d.LeashCLIPath),
		Issues:     []string{},
	}
	if !d.Checked {
		// Not a Mac, so nothing here was probed. One issue, matching how the
		// native section reports a non-Linux host: a wrong-platform runtime has
		// exactly one thing to say.
		r.Status = StatusUnavailable
		r.Issues = append(r.Issues, fmt.Sprintf("macOS enforcement (`leash --darwin`) needs macOS; this host is %s.", displayGOOS(h.GOOS)))
		return r
	}

	// Blockers first: each of these means macOS enforcement cannot work at all,
	// so the runtime is unavailable rather than degraded. They are collected
	// (not short-circuited) because they are independent — an operator with no
	// leashcli AND no activated extensions has two things to fix, and finding
	// out about the second only after fixing the first is the loop this command
	// exists to collapse.
	blockers := []string{}
	// Extension problems that are real but not certain — an activation state
	// that could not be read at all. They are collected here and reported with
	// the degradations, so the blockers list stays exactly the set of things
	// doctor KNOWS are broken.
	softExtensionIssues := []string{}

	if !d.LeashCLIPresent {
		blockers = append(blockers, fmt.Sprintf("the companion leashcli binary is missing at %s, so `leash --darwin` cannot launch a workload.\nInstall Leash.app, or pass --leash-cli-path pointing at a locally built leashcli.", quotePath(d.LeashCLIPath)))
	}

	// The ES extension is the macOS Layer 1. Its absence is not a degradation:
	// there is no second layer that still gates files and exec.
	if issue, blocking := extensionCheck(d, extension{
		state:           d.ESExtension,
		id:              macext.EndpointSecurityExtensionID(),
		component:       macext.ComponentEndpointSecurity,
		name:            "Endpoint Security",
		consequence:     darwinESConsequence,
		critical:        true,
		reconnectRemedy: darwinReactivateRemedy,
	}); issue != "" {
		if blocking {
			blockers = append(blockers, issue)
		} else {
			softExtensionIssues = append(softExtensionIssues, issue)
		}
	}

	// Full Disk Access gates every AUTH_OPEN event LeashES would ever see, so a
	// denial is the same blocker as a missing extension. It is reported
	// separately from the extension state on purpose: the extension is
	// activated and running in this case, and the remedy is a different
	// System Settings pane.
	if d.FullDiskAccess == macext.FDADenied {
		blockers = append(blockers, fmt.Sprintf("the Endpoint Security extension reported that it was DENIED Full Disk Access (es_new_client returned ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED), so it cannot observe file events and %s\nGrant it Full Disk Access in System Settings ▸ Privacy & Security ▸ Full Disk Access, then re-activate the extension.", darwinESConsequence))
	}

	r.Issues = append(r.Issues, blockers...)

	// Degradations: macOS still enforces something, but not everything. Each is
	// the macOS analogue of Linux's "Layer 1 is off but the proxy still runs".
	degraded := []string{}

	if !d.DaemonUp {
		degraded = append(degraded, fmt.Sprintf("the leash daemon is not reachable at %s (%s), so %s\nStart it with `leash --darwin`.", quoteAddr(d.DaemonAddr), daemonFailure(d), darwinDaemonConsequence))
	} else if !d.ComponentsKnown {
		degraded = append(degraded, fmt.Sprintf("the leash daemon at %s answered, but its /health/darwin endpoint did not (%s), so doctor could not see which extensions are connected or whether Full Disk Access was granted.\nUpgrade the running daemon to a build that serves /health/darwin.", quoteAddr(d.DaemonAddr), healthFailure(d)))
	} else if !disconnectionProvable(d) {
		// The daemon answered, and one of its clients would not say what it is.
		// Not a blocker — something IS connected — but it cannot reach ready
		// either: whether each extension is receiving rules is exactly the
		// question this leaves unanswered, and #62 is what an unnoticed "no"
		// costs.
		degraded = append(degraded, fmt.Sprintf("the leash daemon at %s has a connected client that does not identify itself, so doctor cannot tell which extensions are receiving rules — an extension that is activated but holding no policy would look the same from here.\nUpgrade Leash.app: extensions built before client.hello carried a component name (through 1.1.0/20251027.1) register as \"unknown\".", quoteAddr(d.DaemonAddr)))
	}

	degraded = append(degraded, softExtensionIssues...)
	degraded = append(degraded, secondaryExtensionIssues(d)...)

	// An unverified FDA is not a pass. Everything else can look right and
	// LeashES still delivers no events, which is precisely the shape of false
	// assurance the Linux half refuses for an unread capability set. It is only
	// raised once the daemon is actually answering — when it is not, the
	// daemon issue above already says why nothing is known.
	if d.ComponentsKnown && d.FullDiskAccess == macext.FDAUnknown {
		degraded = append(degraded, "the leash daemon has not heard whether the Endpoint Security extension holds Full Disk Access, and without it the extension observes no file events at all while still looking activated.\nA current LeashES advertises the grant in every client.hello, so this normally means the extension has not reconnected since the daemon started, or predates that advertisement — wait a few seconds and re-run, then upgrade Leash.app if it persists. (System Settings ▸ Privacy & Security ▸ Full Disk Access is the pane that grants it.)")
	}

	r.Issues = append(r.Issues, degraded...)

	switch {
	case len(blockers) > 0:
		r.Status = StatusUnavailable
	case len(degraded) > 0:
		r.Status = StatusDegraded
	default:
		r.Status = StatusReady
	}
	return r
}

// secondaryExtensionIssues grades the content filter and the transparent proxy.
// They are degradations rather than blockers because ES still gates files and
// exec without them.
func secondaryExtensionIssues(d DarwinHost) []string {
	out := []string{}
	for _, e := range []extension{
		{
			state: d.FilterExtension, id: macext.NetworkFilterExtensionID(),
			component: macext.ComponentNetworkFilter, name: "content filter",
			consequence: darwinFilterConsequence, critical: false,
			reconnectRemedy: darwinReactivateRemedy,
		},
		{
			state: d.ProxyExtension, id: macext.TransparentProxyExtensionID(),
			component: macext.ComponentTransparentProxy, name: "transparent-proxy",
			consequence: darwinProxyConsequence, critical: false,
			reconnectRemedy: darwinProxyReconnectRemedy,
		},
	} {
		if issue, _ := extensionCheck(d, e); issue != "" {
			out = append(out, issue)
		}
	}
	return out
}

// extension is one row of the macOS enforcement stack. critical marks the one
// whose absence means nothing is enforced at all (ES); the others degrade.
type extension struct {
	state       macext.State
	id          string
	component   string
	name        string
	consequence string
	critical    bool

	// reconnectRemedy is what to do when this extension is activated but not
	// connected. It is per-extension because the fixes genuinely differ, and
	// the transparent proxy's is not guessable: its NETransparentProxyManager
	// configuration is dropped by a system-extension version bump, leaving
	// systemextensionsctl reporting "[activated enabled]" for an extension
	// whose provider process is not even running. Observed on the validation
	// VM after a silent replacement — the generic "re-activate it in Leash.app"
	// does not bring it back.
	reconnectRemedy string
}

// extensionCheck collapses the two signals — activation and connection — into
// one verdict, and it is where their asymmetry lives.
//
// Neither signal is authoritative on its own, but they fail in opposite
// directions, so the combination says more than either:
//
//	activation | connected | verdict
//	-----------+-----------+---------------------------------------------
//	active     | yes       | running and holding rules — no issue
//	active     | no        | activated but enforcing nothing (blocking)
//	active     | unknown   | no issue here; the daemon issue already says why
//	unknown    | yes       | running — the websocket is proof, so the
//	           |           | unreadable table does not matter
//	unknown    | unknown   | unverified: an issue, but never blocking
//	missing    | —         | macOS is not running it (blocking)
//
// The two rows that matter are the unknown ones. Grading an unreadable
// systemextensionsctl as a definite negative would report a perfectly healthy
// Mac as unable to enforce whenever doctor is run without the rights to read
// that table — and a connected extension is running whatever the table says, so
// the stronger signal wins rather than the more pessimistic one. Equally,
// "unverified" must not reach ready: an unread state is reported as unknown and
// not-ready, exactly as an unread capability set is on Linux.
func extensionCheck(d DarwinHost, e extension) (issue string, blocking bool) {
	connectedNow := connectionKnown(d) && connected(d, e.component)
	switch {
	case connectedNow && e.state != macext.StateMissing && e.state != macext.StateDisabled:
		return "", false
	case e.state == macext.StateActive && !disconnectionProvable(d):
		// Activated, and doctor cannot prove it is NOT wired up — either the
		// daemon could not be asked, or a client in its list did not identify
		// itself. Either way the gap is named once, by the daemon issue or the
		// unchecked entry; repeating it per extension would bury the one thing
		// to fix under three copies.
		return "", false
	case e.state == macext.StateActive:
		return fmt.Sprintf("the %s extension is activated but is NOT connected to the leash daemon, so it holds no rules and %s\n%s", e.name, e.consequence, reconnectRemedy(e, d)), e.critical
	case e.state == macext.StateUnknown:
		// Neither signal available (the connected case was caught above).
		// Never blocking: doctor did not establish that anything is wrong, only
		// that it could not tell. darwinUnchecked names it too.
		return fmt.Sprintf("doctor could not read the activation state of the %s extension (%s), so whether %s is unverified.\n%s", e.name, e.id, strings.TrimSuffix(e.consequence, "."), unreadableStateRemedy(d)), false
	default:
		return fmt.Sprintf("the %s extension (%s) is %s, so %s\n%s", e.name, e.id, e.state.Describe(), e.consequence, darwinActivateAdvice), e.critical
	}
}

// unreadableStateRemedy names why systemextensionsctl did not answer, so the
// operator is not sent to approve an extension that is already approved.
func unreadableStateRemedy(d DarwinHost) string {
	reason := strings.TrimSpace(d.ExtensionsDetail)
	if reason == "" {
		reason = "it did not answer"
	}
	return fmt.Sprintf("systemextensionsctl said %s. It exits EX_NOPERM without admin rights, so re-run doctor as an admin user to get a real answer.", reason)
}

// connectionKnown reports whether the daemon answered with a component list at
// all. An empty list from a daemon that never answered is silence, not
// evidence.
func connectionKnown(d DarwinHost) bool { return d.DaemonUp && d.ComponentsKnown }

// connected is POSITIVE evidence: this component holds a websocket to the
// daemon. It is trustworthy on its own — a name in the list got there because a
// client claimed it.
func connected(d DarwinHost, component string) bool {
	for _, c := range d.Components {
		if strings.EqualFold(strings.TrimSpace(c), component) {
			return true
		}
	}
	return false
}

// disconnectionProvable gates the NEGATIVE conclusion — "this extension is
// activated and is NOT connected" — which needs strictly more than the positive
// one. Absence from the list only means "not connected" if every client in it
// could be identified.
//
// Extensions built before client.hello carried a `component` register as
// "unknown" (macsync's fallback), and that is not hypothetical: the extensions
// shipped in Leash.app 1.1.0/20251027.1 do exactly this, so a Mac with both
// extensions genuinely connected reported two "activated but NOT connected"
// faults and an `unavailable` verdict. Sending an operator to remove and
// re-activate a working extension is the same class of error as claiming
// enforcement that is not there, just pointed the other way.
//
// So an unidentified client suppresses the negative conclusion for everything,
// while a positively named component still counts: a new-build extension beside
// an old one is still provably connected.
func disconnectionProvable(d DarwinHost) bool {
	if !connectionKnown(d) {
		return false
	}
	for _, c := range d.Components {
		if strings.EqualFold(strings.TrimSpace(c), macext.ComponentUnknown) {
			return false
		}
	}
	return true
}

func daemonFailure(d DarwinHost) string {
	if reason := strings.TrimSpace(d.DaemonError); reason != "" {
		return reason
	}
	return "no reason given"
}

func healthFailure(d DarwinHost) string {
	if reason := strings.TrimSpace(d.HealthError); reason != "" {
		return reason
	}
	return "no reason given"
}

func quoteAddr(addr string) string {
	if addr = strings.TrimSpace(addr); addr != "" {
		return addr
	}
	return "(no address)"
}

func quotePath(path string) string {
	if path = strings.TrimSpace(path); path != "" {
		return fmt.Sprintf("%q", path)
	}
	return "(no path)"
}

// displayGOOS keeps the "not a Mac" sentence readable when GOOS is empty, which
// is what a hand-built Host has.
func displayGOOS(goos string) string {
	if goos = strings.TrimSpace(goos); goos != "" {
		return goos
	}
	return "an unknown platform"
}

// darwinUnchecked names what a macOS run could not establish. FDA is the one
// that matters: the report says "not ready" for it, and this says why the
// evidence is missing rather than leaving a reader to assume it was tested and
// failed.
func darwinUnchecked(h Host) []Unchecked {
	d := h.Darwin
	if !d.Checked {
		return nil
	}
	out := []Unchecked{}
	if d.ESExtension == macext.StateUnknown || d.FilterExtension == macext.StateUnknown || d.ProxyExtension == macext.StateUnknown {
		out = append(out, Unchecked{
			Name:   "macos_extension_activation",
			Reason: "systemextensionsctl could not be consulted, so at least one extension's activation state was not established (reported as unknown, never assumed active).",
		})
	}
	if !disconnectionProvable(d) {
		out = append(out, Unchecked{
			Name:   "macos_extension_connectivity",
			Reason: connectivityUncheckedReason(d),
		})
	}
	if d.FullDiskAccess == macext.FDAUnknown {
		out = append(out, Unchecked{
			Name:   "macos_full_disk_access",
			Reason: "Full Disk Access for the Endpoint Security extension was not established. macOS exposes no API to read another process's TCC grant, so the only signal is LeashES's own report — advertised in its client.hello and emitted as an event at startup — and neither was seen this run.",
		})
	}
	// NEFilterManager/NETransparentProxyManager configuration state is a
	// distinct fact from extension activation: a configuration can be installed
	// and switched off. Doctor infers "switched on and working" from the
	// extension holding a websocket, which is the stronger signal, but it is an
	// inference and the document says so.
	out = append(out, Unchecked{
		Name:   "macos_ne_configuration",
		Reason: "the NEFilterManager / NETransparentProxyManager configuration state (installed and enabled) is not read directly; doctor infers it from whether each extension is activated and connected to the daemon.",
	})
	return out
}

// connectivityUncheckedReason names which of the two gaps left connectivity
// unproven, because the remedies are nothing alike: one is "start the daemon",
// the other is "the extensions installed here are too old to say who they are".
func connectivityUncheckedReason(d DarwinHost) string {
	const consequence = " so an extension that is activated but not receiving rules would still read as activated here."
	if !connectionKnown(d) {
		return "the leash daemon could not be asked which extensions hold a websocket to it," + consequence
	}
	return "the leash daemon reported a connected client that did not identify itself (an extension built before client.hello carried a component name), so its websocket cannot be attributed to a particular extension —" + consequence
}

// writeDarwinSection renders the macOS half of Text(). The facts are printed
// only when they were probed: on a Linux host there is nothing behind them, and
// six lines of "unknown" would read as macOS enforcement being broken rather
// than absent.
func writeDarwinSection(b *strings.Builder, d DarwinReport) {
	fmt.Fprintf(b, "\nmacOS enforcement: %s\n", darwinStatusWord(d.Status))
	if d.Checked {
		// Wider than the Linux sections' 17 because "full disk access" is
		// longer than any label they carry; a section that aligns with itself
		// beats one that aligns with a section a reader is not comparing it to.
		const label = "  %-17s %s\n"
		fmt.Fprintf(b, label, "ES extension:", d.ESExtension)
		fmt.Fprintf(b, label, "content filter:", d.FilterExtension)
		fmt.Fprintf(b, label, "proxy extension:", d.ProxyExtension)
		fmt.Fprintf(b, label, "full disk access:", d.FullDiskAccess)
		fmt.Fprintf(b, label, "daemon:", daemonWord(d))
		fmt.Fprintf(b, label, "connected:", listOrNone(d.Components))
	}
	writeIssues(b, d.Issues)
}

func daemonWord(d DarwinReport) string {
	addr := quoteAddr(d.Daemon)
	if d.DaemonUp {
		return "up (" + addr + ")"
	}
	return "down (" + addr + ")"
}
