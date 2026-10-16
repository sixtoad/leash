package proxy

import (
	"fmt"
	"strings"
	"time"
)

// ALPN handling for the client-facing side of the HTTPS MITM.
//
// Request-level features (header rewrite, MCP sniffing and enforcement) must
// see every request, but an opaque h2 tunnel (tunnelH2) hides them (issue #57).
// The decision is made per connection from the SNI hostname: hosts with no
// request-level feature keep the h2 tunnel; for the others an h2 connection is
// served by the h2 MITM (h2mitm.go, LEASH_PROXY_H2=inspect, the default) or,
// with LEASH_PROXY_H2=downgrade, only http/1.1 is offered so the connection
// lands on the inspected HTTP/1.1 path.

// ALPN modes recorded on the event=http.alpn log line.
const (
	alpnModeTunnel    = "tunnel"    // h2 offered; an h2 connection is tunneled opaquely
	alpnModeInspect   = "inspect"   // h2 offered; an h2 connection is served by the h2 MITM
	alpnModeDowngrade = "downgrade" // only http/1.1 offered so requests are inspected
	alpnModeRefuse    = "refuse"    // h2-only client to a host whose enforcement cannot be skipped
)

// Reasons a host needs per-request inspection.
const (
	alpnReasonHeaderRewrite = "header_rewrite" // a rewrite rule targets the host
	alpnReasonMCPPolicy     = "mcp_policy"     // MCP tools/call rules are configured
	alpnReasonMCPObserve    = "mcp_observe"    // MCP observability is enabled (mode != off)
	alpnReasonClientH2Only  = "client_h2_only" // client did not offer http/1.1
)

// alpnDecision is the per-connection outcome of chooseALPN.
type alpnDecision struct {
	host      string
	offered   []string // client's ALPN list, as sent
	nextProto []string // what the proxy advertises back
	mode      string
	reasons   []string
}

// requestInspectionReasons lists the request-level features that apply to
// connections for host. An empty result means nothing would inspect or modify
// individual requests, so tunneling h2 opaquely loses nothing.
//
// MCP rules are not host-scoped at this layer (a rule may name no server, and
// the server is only known per request), so any configured MCP policy counts
// for every host. MCP observability likewise applies to every host: any JSON
// body may be a JSON-RPC call. LEASH_MCP_OBS=off turns that reason off.
func (p *MITMProxy) requestInspectionReasons(host string) []string {
	var reasons []string
	if p.headerRewriter.HasRulesForHost(host) {
		reasons = append(reasons, alpnReasonHeaderRewrite)
	}
	if p.policyChecker != nil && p.policyChecker.HasMCPPolicies() {
		reasons = append(reasons, alpnReasonMCPPolicy)
	}
	if p.mcpObserver != nil && p.mcpObserver.cfg.Mode != MCPModeOff {
		reasons = append(reasons, alpnReasonMCPObserve)
	}
	return reasons
}

// chooseALPN decides which ALPN protocols to advertise to a client connecting
// to host, given the client's offered list.
func (p *MITMProxy) chooseALPN(host string, offered []string) alpnDecision {
	d := alpnDecision{host: host, offered: offered}
	offersH2, offersH11 := false, false
	for _, proto := range offered {
		switch proto {
		case "h2":
			offersH2 = true
		case "http/1.1":
			offersH11 = true
		}
	}

	d.reasons = p.requestInspectionReasons(host)
	if !offersH2 || len(d.reasons) == 0 {
		// Nothing to decide (an h1-only client, or no ALPN at all), or nothing
		// to inspect: keep the historical list, h2 is tunneled.
		d.nextProto = []string{"h2", "http/1.1"}
		d.mode = alpnModeTunnel
		return d
	}

	if p.h2InspectEnabled() {
		// Serve h2 with full per-request inspection (h2mitm.go).
		d.nextProto = []string{"h2", "http/1.1"}
		d.mode = alpnModeInspect
		return d
	}

	// LEASH_PROXY_H2=downgrade: route inspected hosts to the HTTP/1.1 path.
	if offersH11 {
		d.nextProto = []string{"http/1.1"}
		d.mode = alpnModeDowngrade
		return d
	}

	// The client speaks only h2 (e.g. gRPC). Offering http/1.1 alone fails the
	// handshake (no_application_protocol). That is the right outcome when a
	// feature that changes what reaches the origin applies — tunneling would
	// silently skip a rewrite or an MCP deny — but for observability alone,
	// keep connectivity and tunnel as before.
	d.reasons = append(d.reasons, alpnReasonClientH2Only)
	if hasEnforcingReason(d.reasons) {
		d.nextProto = []string{"http/1.1"}
		d.mode = alpnModeRefuse
		return d
	}
	d.nextProto = []string{"h2", "http/1.1"}
	d.mode = alpnModeTunnel
	return d
}

func hasEnforcingReason(reasons []string) bool {
	for _, r := range reasons {
		if r == alpnReasonHeaderRewrite || r == alpnReasonMCPPolicy {
			return true
		}
	}
	return false
}

// offeredH2 reports whether the client offered h2, i.e. whether the decision
// could have changed anything and is worth logging.
func (d alpnDecision) offeredH2() bool {
	for _, proto := range d.offered {
		if proto == "h2" {
			return true
		}
	}
	return false
}

// logALPNDecision records the ALPN decision for connections where the client
// offered h2. negotiated is the protocol the handshake settled on ("" when the
// handshake failed or no ALPN was agreed).
func (p *MITMProxy) logALPNDecision(d alpnDecision, negotiated string, handshakeErr error) {
	if p.sharedLogger == nil || !d.offeredH2() {
		return
	}
	decision := "allowed"
	if d.mode == alpnModeRefuse {
		decision = "denied"
	}
	entry := fmt.Sprintf("time=%s event=http.alpn addr=\"%s\" alpn_offered=\"%s\" alpn_advertised=\"%s\" alpn_negotiated=\"%s\" alpn_mode=%s decision=%s",
		time.Now().Format(time.RFC3339), logSafe(d.host), logSafe(strings.Join(d.offered, ",")),
		strings.Join(d.nextProto, ","), logSafe(negotiated), d.mode, decision)
	if len(d.reasons) > 0 {
		entry += fmt.Sprintf(" reasons=\"%s\"", strings.Join(d.reasons, ","))
	}
	if handshakeErr != nil {
		entry += fmt.Sprintf(" error=\"%s\"", logSafe(handshakeErr.Error()))
	}
	_ = p.sharedLogger.Write(entry)
}

// logSafe makes client-supplied handshake values (SNI, ALPN names) safe to embed
// in a quoted logfmt field: quotes are swapped as elsewhere in the proxy logs and
// control or non-ASCII bytes are replaced so a value cannot forge fields or lines.
func logSafe(s string) string {
	s = escapeQuotes(s)
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e || r == '\\' {
			return '?'
		}
		return r
	}, s)
}
