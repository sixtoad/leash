import Foundation
import NetworkExtension
import Network
import os.log
import Darwin

extension FilterDataProvider {
// MARK: - Rule Evaluation

    enum FlowDecision {
        case allow
        case deny(reason: String)
    }

    func handleDNSOutbound(flow: NEFilterFlow, flowKey: ObjectIdentifier, readBytes: Data) -> NEFilterDataVerdict? {
        var hasState = false
        let inspectionResult = syncQueue.sync { () -> (DNSInspectionState, String, UInt16)? in
            guard var state = pendingDNSInspections[flowKey] else {
                return nil
            }
            hasState = true

            state.buffer.append(readBytes)
            if state.buffer.count > 2048 {
                state.buffer = state.buffer.suffix(2048)
            }

            if let parsed = parseDNSQuestion(from: state.buffer) {
                state.buffer.removeAll(keepingCapacity: true)
                pendingDNSInspections[flowKey] = state
                return (state, parsed.name, parsed.type)
            } else {
                pendingDNSInspections[flowKey] = state
                return nil
            }
        }

        if let (state, name, recordType) = inspectionResult {
            emitDNSQuery(state: state, query: name, recordType: recordType)
        }

        let hasPendingInspection = syncQueue.sync { pendingDNSInspections[flowKey] != nil }

        if inspectionResult == nil && !hasPendingInspection {
            return nil
        }

        if !hasState {
            return nil
        }

        return NEFilterDataVerdict(passBytes: readBytes.count, peekBytes: 512)
    }

    func parseDNSQuestion(from data: Data) -> (name: String, type: UInt16)? {
        guard data.count >= 12 else { return nil }
        let qdCount = (UInt16(data[4]) << 8) | UInt16(data[5])
        guard qdCount > 0 else { return nil }

        var offset = 12
        var labels: [String] = []

        while offset < data.count {
            let length = Int(data[offset])
            offset += 1
            if length == 0 {
                break
            }
            guard offset + length <= data.count else { return nil }
            let labelData = data[offset ..< offset + length]
            let label = String(bytes: labelData, encoding: .utf8) ??
                        String(bytes: labelData, encoding: .ascii) ??
                        ""
            labels.append(label)
            offset += length
        }

        guard !labels.isEmpty else { return nil }
        guard offset + 4 <= data.count else { return nil }

        let type = (UInt16(data[offset]) << 8) | UInt16(data[offset + 1])
        return (labels.joined(separator: "."), type)
    }

    func emitDNSQuery(state: DNSInspectionState, query: String, recordType: UInt16) {
        let recordTypeName = dnsRecordTypeName(recordType)

        os_log("DNS query %{public}@ type=%{public}@ via %{public}@",
               log: log, type: .info, query, recordTypeName, state.originalHostname)

        emitNetworkEvent(
            info: state.pidInfo,
            pid: state.pid,
            hostname: state.originalHostname,
            port: state.port,
            socketType: state.socketType,
            socketProtocol: state.socketProtocolName,
            decision: .allow,
            isDNSQuery: true,
            originalHostname: state.originalHostname,
            dnsQuery: query
        )

        os_log("DNS payload: %{public}@ query=%{public}@ type=%{public}@ pid=%{public}d leash=%{public}d",
               log: log, type: .debug,
               state.originalHostname,
               query,
               recordTypeName,
               state.pid,
               state.pidInfo.leashPID)
    }

    func dnsRecordTypeName(_ type: UInt16) -> String {
        switch type {
        case 1: return "A"
        case 2: return "NS"
        case 5: return "CNAME"
        case 6: return "SOA"
        case 12: return "PTR"
        case 15: return "MX"
        case 16: return "TXT"
        case 28: return "AAAA"
        case 33: return "SRV"
        default: return "TYPE\(type)"
        }
    }

    /// Decides a flow of a leashed process from the daemon's policy tables,
    /// as the Linux kernel decides connect/sendmsg: by destination address and
    /// port (hostname rules were resolved by the daemon when the policy
    /// loaded; names are the transparent proxy's job). DNS is an ordinary
    /// flow to the resolver, decided like any other.
    ///
    /// `exemptLocalScope` is only for flows of processes the filter merely
    /// inferred (system-wide enforcement): loopback and link-local stay open
    /// for them while policy is unavailable, so the machine's own plumbing
    /// keeps working. A leashed process gets no exemption.
    func evaluateFlow(
        hostname: String,
        port: String,
        direction: NETrafficDirection = .outbound,
        exemptLocalScope: Bool = false
    ) -> FlowDecision {
        if direction != .outbound {
            // Leash enforces egress. Inbound flows to a leashed process are
            // the machine's to decide.
            return .allow
        }
        let (matcher, unavailable) = policyMatcher(strictScope: !exemptLocalScope)
        guard let matcher else {
            if exemptLocalScope && isFailClosedExempt(hostname: hostname) {
                return .allow
            }
            return .deny(reason: "Policy unavailable: \(unavailable)")
        }
        guard let portNumber = UInt16(port) else {
            return .deny(reason: "unparseable destination port \(port)")
        }
        let allowed: Bool
        if normalizedIPAddress(from: hostname) != nil {
            allowed = matcher.allowsConnect(ip: hostname, port: portNumber)
        } else {
            // The flow names its destination but not its address. Allow it only
            // if the tables allow every address on this port: never looser
            // than deciding by the address the name resolves to.
            allowed = matcher.allowsConnectToAnyAddress(port: portNumber)
        }
        return allowed ? .allow : .deny(reason: "Blocked by policy (\(matcher.version))")
    }

    func normalizeDomain(_ domain: String) -> String {
        let trimmed = domain.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.trimmingCharacters(in: CharacterSet(charactersIn: ".")).lowercased()
    }

    func normalizeHostname(_ host: String) -> String {
        let trimmed = host.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.trimmingCharacters(in: CharacterSet(charactersIn: ".")).lowercased()
    }

    func normalizedIPAddress(from value: String) -> String? {
        var ipv4Addr = in_addr()
        if inet_pton(AF_INET, value, &ipv4Addr) == 1 {
            var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            let result = buffer.withUnsafeMutableBufferPointer { ptr in
                ptr.baseAddress.flatMap { inet_ntop(AF_INET, &ipv4Addr, $0, socklen_t(INET_ADDRSTRLEN)) }
            }
            if result != nil {
                return String(cString: buffer)
            }
        }

        var ipv6Addr = in6_addr()
        if inet_pton(AF_INET6, value, &ipv6Addr) == 1 {
            var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            let result = buffer.withUnsafeMutableBufferPointer { ptr in
                ptr.baseAddress.flatMap { inet_ntop(AF_INET6, &ipv6Addr, $0, socklen_t(INET6_ADDRSTRLEN)) }
            }
            if result != nil {
                return String(cString: buffer)
            }
        }

        return nil
    }

    func domainContainsIP(domain: String, ip: String) -> Bool {
        var contains = false
        let now = Date()
        var removedExpired = false

        syncQueue.sync {
            if let entry = domainResolutionCache[domain] {
                if entry.expiry > now {
                    if entry.ips.contains(ip) {
                        contains = true
                        domainResolutionCache[domain] = DomainResolution(ips: entry.ips, expiry: now.addingTimeInterval(domainResolutionTTL))
                    }
                } else {
                    domainResolutionCache.removeValue(forKey: domain)
                    removedExpired = true
                }
            }
        }

        if removedExpired {
            persistResolvedDomains()
        }

        return contains
    }

    func addResolvedIP(_ ip: String, to domain: String, pid: pid_t?, info: TrackedPIDInfo?) {
        var shouldPersist = false
        let expiry = Date().addingTimeInterval(domainResolutionTTL)

        syncQueue.sync {
            var currentIPs = domainResolutionCache[domain]?.ips ?? Set<String>()
            if !currentIPs.contains(ip) {
                currentIPs.insert(ip)
                shouldPersist = true
            }
            domainResolutionCache[domain] = DomainResolution(ips: currentIPs, expiry: expiry)
        }

        if shouldPersist {
            os_log("Learned IP %{public}@ for domain %{public}@", log: log, type: .info, ip, domain)
            persistResolvedDomains()
            emitDNSEvent(domain: domain, ip: ip, pid: pid, info: info)
        }
    }

    func persistResolvedDomains() {
        guard let url = resolvedDomainsStoreURL else { return }
        // Snapshot + write off the hot path. Dispatching the whole body (including the
        // syncQueue snapshot) to a separate queue keeps this deadlock-safe regardless of
        // whether the caller currently holds syncQueue.
        persistenceQueue.async { [weak self] in
            guard let self else { return }
            let now = Date()
            var snapshot: [String: DomainResolution] = [:]
            self.syncQueue.sync { snapshot = self.domainResolutionCache }

            let entries: [[String: Any]] = snapshot.compactMap { domain, res in
                guard res.expiry > now else { return nil }
                return [
                    "domain": domain,
                    "ips": Array(res.ips),
                    "expiry": res.expiry.timeIntervalSince1970
                ]
            }

            // Reuse the snapshot to evict expired entries from the in-memory cache;
            // otherwise this long-running extension only drops them on re-query,
            // leaking memory over time. Re-check under the lock so a mapping that was
            // refreshed since the snapshot isn't removed.
            let expiredKeys = snapshot.compactMap { domain, res in res.expiry <= now ? domain : nil }
            if !expiredKeys.isEmpty {
                self.syncQueue.async {
                    for key in expiredKeys where (self.domainResolutionCache[key]?.expiry ?? .distantFuture) <= now {
                        self.domainResolutionCache.removeValue(forKey: key)
                    }
                }
            }

            do {
                try FileManager.default.createDirectory(at: url.deletingLastPathComponent(),
                                                        withIntermediateDirectories: true)
                let data = try JSONSerialization.data(withJSONObject: ["domains": entries])
                try data.write(to: url, options: .atomic)
            } catch {
                os_log("Failed to persist resolved domains: %{public}@",
                       log: self.log, type: .error, String(describing: error))
            }
        }
    }

    func resolveDomainIPs(_ domain: String) -> Set<String> {
        let now = Date()
        var cached: DomainResolution?

        syncQueue.sync {
            if let entry = domainResolutionCache[domain], entry.expiry > now {
                cached = entry
            } else if let entry = domainResolutionCache[domain], entry.expiry <= now {
                domainResolutionCache.removeValue(forKey: domain)
            }
        }

        if let cached { return cached.ips }

        let resolved = performDomainResolution(domain)
        let expiry = Date().addingTimeInterval(domainResolutionTTL)

        var didUpdate = false
        syncQueue.sync {
            domainResolutionCache[domain] = DomainResolution(ips: resolved, expiry: expiry)
            didUpdate = !resolved.isEmpty
        }

        if didUpdate {
            os_log("Resolved domain %{public}@ to %{public}d IPs", log: log, type: .debug, domain, resolved.count)
            persistResolvedDomains()
        }

        return resolved
    }

    func emitNetworkEvent(info: TrackedPIDInfo,
                                  pid: pid_t,
                                  hostname: String,
                                  port: String,
                                  socketType: String,
                                  socketProtocol: String,
                                  decision: FlowDecision,
                                  isDNSQuery: Bool = false,
                                  originalHostname: String? = nil,
                                  dnsQuery: String? = nil) {
        var details: [String: String] = [
            "exe": info.executablePath,
            "process_path": info.executablePath,
            "pid": String(pid),
            "cgroup": String(info.leashPID),
            "leash_pid": String(info.leashPID),
            "port": port,
            "protocol": socketProtocol,
            "family": socketType
        ]

        let observedHost = originalHostname ?? hostname
        let observedHostIP = normalizedIPAddress(from: observedHost)
        var resolvedIP: String? = observedHostIP
        var resolvedDomain: String?

        if let cwd = info.cwd {
            details["cwd"] = cwd
        }
        if let tty = info.ttyPath {
            details["tty_path"] = tty
        }

        if isDNSQuery {
            details["resolver"] = observedHost
            if let dnsQuery, !dnsQuery.isEmpty {
                details["dns_query"] = dnsQuery
                let normalizedQuery = normalizeDomain(dnsQuery)
                if !normalizedQuery.isEmpty {
                    resolvedDomain = normalizedQuery
                }
            }
        }

        let decisionValue: String
        let severity: String
        switch decision {
        case .allow:
            severity = "info"
            decisionValue = "allow"
        case .deny(let reason):
            severity = "warning"
            decisionValue = "deny"
            details["reason"] = reason
        }
        details["decision"] = decisionValue

        if let ip = resolvedIP {
            details["addr_ip"] = ip
            if let cached = domainForResolvedIP(ip) {
                let normalized = normalizeDomain(cached)
                if !normalized.isEmpty {
                    resolvedDomain = normalized
                }
            }
        }

        if normalizedIPAddress(from: hostname) == nil {
            let normalizedDomain = normalizeDomain(hostname)
            if !normalizedDomain.isEmpty {
                resolvedDomain = normalizedDomain
            }
            if resolvedIP == nil {
                let resolved = resolveDomainIPs(normalizedDomain)
                if let ip = resolved.first {
                    resolvedIP = ip
                    details["addr_ip"] = ip
                }
            }
        }

        if let domain = resolvedDomain, !domain.isEmpty {
            details["domain"] = domain
        } else if normalizedIPAddress(from: observedHost) == nil {
            let normalizedObserved = normalizeDomain(observedHost)
            if !normalizedObserved.isEmpty {
                details["domain"] = normalizedObserved
            }
        }

        if details["domain"] == nil {
            details["domain"] = observedHost
        }

        if let ip = resolvedIP, !ip.isEmpty, observedHostIP != nil {
            details["addr"] = ip
        } else if let domain = resolvedDomain, !domain.isEmpty {
            details["addr"] = domain
        } else {
            details["addr"] = observedHost
        }

        if isDNSQuery, let dnsQuery, !dnsQuery.isEmpty {
            details["hostname"] = dnsQuery
            details["hostname_kind"] = "domain"
        } else if let observedHostIP, !observedHostIP.isEmpty {
            details["hostname"] = observedHost
            details["hostname_kind"] = "ip"
            if let domain = resolvedDomain, !domain.isEmpty {
                details["hostname_resolved"] = domain
            } else if let fallbackDomain = details["domain"], !fallbackDomain.isEmpty,
                      normalizedIPAddress(from: fallbackDomain) == nil {
                details["hostname_resolved"] = fallbackDomain
            }
        } else if let domain = resolvedDomain, !domain.isEmpty {
            details["hostname"] = domain
            details["hostname_kind"] = "domain"
        } else if let fallbackDomain = details["domain"], !fallbackDomain.isEmpty,
                  normalizedIPAddress(from: fallbackDomain) == nil {
            details["hostname"] = fallbackDomain
            details["hostname_kind"] = "domain"
        } else {
            details["hostname"] = observedHost
            details["hostname_kind"] = normalizedIPAddress(from: observedHost) == nil ? "domain" : "ip"
        }

        var displayHost: String
        if observedHostIP != nil {
            if let domain = resolvedDomain, !domain.isEmpty {
                displayHost = "\(observedHost) [\(domain)]"
            } else if let dnsQuery, !dnsQuery.isEmpty {
                displayHost = "\(observedHost) [\(dnsQuery)]"
            } else {
                displayHost = observedHost
            }
        } else {
            displayHost = details["addr"] ?? observedHost
        }

        if isDNSQuery, let dnsQuery, !dnsQuery.isEmpty {
            displayHost = "\(dnsQuery) > \(observedHost)"
        }

        let eventName: String
        let logIcon: String

        eventName = "net.send"
        logIcon = ""
        if isDNSQuery {
            details["query_type"] = "dns"
        }

        os_log("%{public}@ NET[leash=%{public}d] %{public}@:%{public}d → %{public}@:%{public}@ (%{public}@ %{public}@) cwd=%{public}@ → %{public}@",
               log: log, type: .default,
               logIcon,
               info.leashPID,
               info.executablePath, pid,
               displayHost, port,
               socketType, socketProtocol,
               info.cwd ?? "none",
               decisionValue.uppercased())

        DaemonSync.shared.sendEvent(
            name: eventName,
            details: details,
            severity: severity,
            source: "leash.netfilter"
        )

    }

    func domainForResolvedIP(_ ip: String) -> String? {
        var match: String?
        let now = Date()

        syncQueue.sync {
            for (domain, entry) in domainResolutionCache {
                if entry.expiry <= now {
                    continue
                }
                if entry.ips.contains(ip) {
                    match = domain
                    break
                }
            }
        }

        return match
    }

    func emitDNSEvent(domain: String, ip: String, pid: pid_t?, info: TrackedPIDInfo?) {
        var details: [String: String] = [
            "hostname": domain,
            "addr": ip,
            "decision": "allow"
        ]

        if let info {
            details["process_path"] = info.executablePath
            details["leash_pid"] = String(info.leashPID)
            if let cwd = info.cwd {
                details["cwd"] = cwd
            }
            if let tty = info.ttyPath {
                details["tty_path"] = tty
            }
        }
        if let pid {
            details["pid"] = String(pid)
        }

        os_log("DNS resolve host=%{public}@ ip=%{public}@ (pid=%{public}@ leash=%{public}@)",
               log: log, type: .info,
               domain,
               ip,
               pid.map(String.init) ?? "n/a",
               info.map { String($0.leashPID) } ?? "n/a")

        DaemonSync.shared.sendEvent(
            name: "dns.resolve",
            details: details,
            severity: "info",
            source: "leash.netfilter"
        )
    }


    func performDomainResolution(_ domain: String) -> Set<String> {
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_STREAM

        var resultPointer: UnsafeMutablePointer<addrinfo>? = nil
        let status = getaddrinfo(domain, nil, &hints, &resultPointer)

        guard status == 0 else {
            if status != EAI_NONAME {
                os_log("getaddrinfo failed for %{public}@ with error %{public}d", log: log, type: .default, domain, status)
            }
            return []
        }

        defer {
            if let pointer = resultPointer {
                freeaddrinfo(pointer)
            }
        }

        var ips: Set<String> = []
        var current = resultPointer

        while let info = current?.pointee {
            switch info.ai_family {
            case AF_INET:
                if let addrPtr = info.ai_addr {
                    var addr = addrPtr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
                    var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                    let result = buffer.withUnsafeMutableBufferPointer { ptr in
                        ptr.baseAddress.flatMap { inet_ntop(AF_INET, &addr.sin_addr, $0, socklen_t(INET_ADDRSTRLEN)) }
                    }
                    if result != nil {
                        ips.insert(String(cString: buffer))
                    }
                }

            case AF_INET6:
                if let addrPtr = info.ai_addr {
                    var addr = addrPtr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee }
                    var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                    let result = buffer.withUnsafeMutableBufferPointer { ptr in
                        ptr.baseAddress.flatMap { inet_ntop(AF_INET6, &addr.sin6_addr, $0, socklen_t(INET6_ADDRSTRLEN)) }
                    }
                    if result != nil {
                        ips.insert(String(cString: buffer))
                    }
                }

            default:
                break
            }

            current = info.ai_next
        }

        return ips
    }

    func describeSocketProtocol(_ number: Int32) -> String {
        switch number {
        case IPPROTO_TCP:
            return "TCP"
        case IPPROTO_UDP:
            return "UDP"
        default:
            return "proto:\(number)"
        }
    }

    
}
