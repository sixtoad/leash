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
// With system-wide enforcement off and no tracked PIDs the filter has nothing
// in scope, so this changes nothing. Local-scope destinations stay exempt so
// the control plane (extension → daemon websocket, proxy → local MITM listener)
// can always reconnect and lift the condition.

    enum PolicyAvailability {
        case available
        case unavailable(reason: String)
    }

    /// Whether the filter currently holds a policy it can enforce.
    ///
    /// Two grace windows keep transients from cutting traffic: `policyStartupGrace`
    /// covers the gap between the provider starting and its first rule delivery,
    /// and `policyDisconnectGrace` covers websocket reconnect churn (the daemon
    /// re-pushes network rules on every hello, so a quick reconnect refreshes the
    /// policy on its own).
    func policyAvailability(now: Date = Date()) -> PolicyAvailability {
        let connected = daemon.isConnected
        let disconnectedSince = daemon.disconnectedSince

        var result: PolicyAvailability = .available
        var transition: (engaged: Bool, reason: String)?

        syncQueue.sync {
            if !rulesAreAuthoritative {
                if now.timeIntervalSince(filterStartTime) > policyStartupGrace {
                    result = .unavailable(reason: "no network policy received from the leash daemon")
                }
            } else if !connected, let since = disconnectedSince,
                      now.timeIntervalSince(since) > policyDisconnectGrace {
                result = .unavailable(reason: "leash daemon connection lost; network policy is stale")
            }

            switch result {
            case .available:
                if failClosedEngaged {
                    failClosedEngaged = false
                    transition = (false, "")
                }
            case .unavailable(let reason):
                if !failClosedEngaged {
                    failClosedEngaged = true
                    transition = (true, reason)
                }
            }
        }

        if let transition {
            if transition.engaged {
                os_log("FAIL-CLOSED: %{public}@. In-scope flows will be denied until policy is restored (local-scope destinations stay allowed).",
                       log: log, type: .fault, transition.reason)
            } else {
                os_log("Fail-closed lifted: network policy is authoritative again.",
                       log: log, type: .default)
            }
        }

        return result
    }

    /// Record that the current rule set came from the daemon, so the filter can
    /// tell "policy says allow" apart from "policy never arrived".
    func markRulesAuthoritative() {
        var engaged = false
        syncQueue.sync {
            rulesAreAuthoritative = true
            engaged = failClosedEngaged
        }
        if engaged {
            // Availability (and the lift log) is recomputed on the next flow;
            // note the delivery here so the daemon log shows the recovery point.
            os_log("Network policy delivered while fail-closed was engaged.",
                   log: log, type: .default)
        }
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
