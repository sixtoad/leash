import Foundation
import NetworkExtension
import os.log
import Darwin

extension FilterDataProvider {
// MARK: - Fail-Closed Policy Availability
//
// The filter used to treat "no rules loaded" exactly like "no rule matched" and
// allowed the flow. That made a provider which is running but disconnected from
// the daemon silently pass traffic an explicit `forbid` should have blocked
// (#62). A flow the filter would otherwise evaluate is now denied while the
// policy it needs is missing or stale.
//
// Scope is deliberately narrow: only flows that reach evaluateFlow — tracked
// PIDs, or every process when system-wide enforcement is on — are affected.
// Leash's own processes (the extensions' websocket to darwind, the proxy's
// relay to the local MITM listener) are never leashed, so they always
// reconnect and lift the condition. Processes the filter merely inferred keep
// loopback and link-local while policy is unavailable; a leashed process does
// not.

    /// The tables to decide with, or why there are none.
    ///
    /// `strictScope` is true for a leashed process: no tables means deny at
    /// once, because `leash --darwin exec` only starts a workload after this
    /// filter applied the daemon's current tables, so a missing table set is
    /// a real failure, not a startup race. Processes the filter only inferred
    /// (system-wide enforcement) get the old startup grace.
    ///
    /// A daemon gone for longer than `policyDisconnectGrace` also leaves the
    /// filter without usable tables: the policy may have changed since.
    func policyMatcher(strictScope: Bool, now: Date = Date()) -> (LeashPolicyMatcher?, String) {
        let connected = daemon.isConnected
        let disconnectedSince = daemon.disconnectedSince

        var matcher: LeashPolicyMatcher?
        var reason = ""
        var transition: (engaged: Bool, reason: String)?

        syncQueue.sync {
            matcher = policyTables
            if matcher == nil {
                if strictScope || now.timeIntervalSince(filterStartTime) > policyStartupGrace {
                    reason = tablesRefusal ?? "no network policy received from the leash daemon"
                } else {
                    reason = "starting"
                }
            } else if !connected, let since = disconnectedSince,
                      now.timeIntervalSince(since) > policyDisconnectGrace {
                matcher = nil
                reason = "leash daemon connection lost; network policy is stale"
            }

            let unavailable = matcher == nil && reason != "starting"
            if unavailable != failClosedEngaged {
                failClosedEngaged = unavailable
                transition = (unavailable, reason)
            }
        }

        if let transition {
            if transition.engaged {
                os_log("FAIL-CLOSED: %{public}@. Flows of leashed processes are denied until policy is restored.",
                       log: log, type: .fault, transition.reason)
            } else {
                os_log("Fail-closed lifted: network policy is authoritative again.",
                       log: log, type: .default)
            }
        }

        if matcher == nil && reason == "starting" {
            // Inferred processes during startup: no decision yet; the caller
            // applies its local-scope exemption and otherwise denies.
            return (nil, "network policy not received yet")
        }
        return (matcher, reason)
    }

    /// Destinations that stay allowed even when policy is unavailable.
    ///
    /// Loopback carries leash's own control plane — the extensions' websocket to
    /// darwind and the transparent proxy's relay to the local MITM listener — so
    /// denying it would make the degraded state unrecoverable. The unspecified
    /// and link-local ranges are local network plumbing (DHCP, mDNS, IPv6
    /// autoconfiguration); blocking those wedges connectivity without closing an
    /// egress path.
    func isFailClosedExempt(hostname: String) -> Bool {
        let normalized = normalizeHostname(hostname)
        if normalized == "localhost" || normalized.hasSuffix(".localhost") {
            return true
        }
        guard let ip = normalizedIPAddress(from: hostname) else {
            // A non-IP destination is a real remote host by name; not exempt.
            return false
        }
        return isLocalScopeAddress(ip)
    }

    func isLocalScopeAddress(_ value: String) -> Bool {
        var v4 = in_addr()
        if inet_pton(AF_INET, value, &v4) == 1 {
            return isLocalScopeIPv4(UInt32(bigEndian: v4.s_addr))
        }

        var v6 = in6_addr()
        guard inet_pton(AF_INET6, value, &v6) == 1 else { return false }

        return withUnsafeBytes(of: &v6) { raw -> Bool in
            guard raw.count == 16 else { return false }
            let bytes = Array(raw)

            // ::ffff:a.b.c.d — an IPv4 destination wearing an IPv6 address.
            let isIPv4Mapped = bytes[0..<10].allSatisfy { $0 == 0 } && bytes[10] == 0xff && bytes[11] == 0xff
            if isIPv4Mapped {
                let host = (UInt32(bytes[12]) << 24) | (UInt32(bytes[13]) << 16)
                    | (UInt32(bytes[14]) << 8) | UInt32(bytes[15])
                return isLocalScopeIPv4(host)
            }

            if bytes[0..<15].allSatisfy({ $0 == 0 }) {
                return bytes[15] == 0 || bytes[15] == 1 // :: and ::1
            }

            // fe80::/10 link-local
            return bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80
        }
    }

    private func isLocalScopeIPv4(_ host: UInt32) -> Bool {
        if host == 0 { return true } // 0.0.0.0
        let firstOctet = (host >> 24) & 0xff
        let secondOctet = (host >> 16) & 0xff
        if firstOctet == 127 { return true } // 127.0.0.0/8
        if firstOctet == 169 && secondOctet == 254 { return true } // 169.254.0.0/16
        return false
    }
}
