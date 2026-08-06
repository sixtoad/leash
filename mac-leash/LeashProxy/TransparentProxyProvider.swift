import Foundation
import NetworkExtension
import Network
import os.log

/// Routes tracked-workload TCP flows through the local darwind MITM proxy.
///
/// macOS has no `SO_ORIGINAL_DST`, so for each intercepted flow we open a connection
/// to `127.0.0.1:<proxyPort>` and write a PROXY protocol v1 header carrying the
/// original destination. The Go proxy reads that header in place of `SO_ORIGINAL_DST`
/// (see `internal/proxy/proxy.go` `readProxyProtocolV1Dest`) and then MITMs the flow.
///
/// SCAFFOLD: the flow-relay and tracked-PID gating below are structured but must be
/// validated end-to-end in the SIP/AMFI-relaxed VM. See docs/MACOS-P1-PROXY.md.
final class TransparentProxyProvider: NETransparentProxyProvider {
    private let log = OSLog(subsystem: LeashIdentifiers.bundle, category: "transparent-proxy")

    private let proxyHost = "127.0.0.1"
    private let proxyPort: Network.NWEndpoint.Port = 18000
    // Serial: the Network framework expects a connection's callbacks to be serialized.
    private let relayQueue = DispatchQueue(label: LeashIdentifiers.namespaced("proxy.relay"))

    private let daemon = DaemonSync.shared
    private let stateQueue = DispatchQueue(label: LeashIdentifiers.namespaced("proxy.state"))
    // leash-tracked PIDs (the launched command + its lineage), synced from the ES
    // extension via the daemon. Only flows from these are routed through the proxy.
    private var trackedPIDs: Set<pid_t> = []
    // Verbose per-flow debug diagnostics gate, delivered from the daemon via the
    // "mac.debug" message (controlled by LEASH_MAC_DEBUG). Off in normal operation;
    // when on, the proxy emits proxy.start/proxy.pids/proxy.flow to the daemon log.
    // Accessed only on stateQueue.
    private var debugEnabled = false

    // MARK: - Lifecycle

    override func startProxy(options: [String: Any]? = nil, completionHandler: @escaping (Error?) -> Void) {
        // Track the same PID set the content filter uses, delivered over the daemon.
        daemon.subscribe(to: "mac.pid.sync") { [weak self] payload in
            self?.handlePIDUpdate(payload)
        }

        // Debug-logging flag from the daemon (LEASH_MAC_DEBUG). Toggling it is a
        // daemon restart — no extension re-activation.
        daemon.subscribe(to: "mac.debug") { [weak self] payload in
            guard let self else { return }
            let enabled = (payload["enabled"] as? Bool) ?? false
            self.stateQueue.async {
                self.debugEnabled = enabled
                os_log("Proxy debug logging %{public}@", log: self.log, type: .default,
                       enabled ? "enabled" : "disabled")
            }
        }

        let settings = NETransparentProxyNetworkSettings(tunnelRemoteAddress: proxyHost)

        // Intercept all outbound TCP; per-flow gating (tracked PIDs) happens in
        // handleNewFlow so untracked processes are passed straight through.
        let allTCP = NENetworkRule(
            remoteNetwork: nil,
            remotePrefix: 0,
            localNetwork: nil,
            localPrefix: 0,
            protocol: .TCP,
            direction: .outbound
        )
        settings.includedNetworkRules = [allTCP]

        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self else { completionHandler(error); return }
            if let error {
                os_log("Failed to apply transparent proxy settings: %{public}@",
                       log: self.log, type: .error, String(describing: error))
                self.debugEvent("proxy.start", ["status": "error", "error": String(describing: error)])
            } else {
                os_log("Transparent proxy started (relaying to %{public}@:%{public}d)",
                       log: self.log, type: .default, self.proxyHost, self.proxyPort.rawValue)
                self.debugEvent("proxy.start", ["status": "started",
                                                "relay": "\(self.proxyHost):\(self.proxyPort.rawValue)"])
            }
            completionHandler(error)
        }
    }

    /// Emit a verbose diagnostic to the daemon (visible in the readable daemon log)
    /// only when debug logging is enabled. Consolidates the transparent-proxy
    /// instrumentation behind the single LEASH_MAC_DEBUG-controlled gate.
    private func debugEvent(_ name: String, _ details: [String: String]) {
        stateQueue.async { [weak self] in
            guard let self, self.debugEnabled else { return }
            self.daemon.sendEvent(name: name, details: details, severity: "info", source: "leash.proxy")
        }
    }

    override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        os_log("Transparent proxy stopping: reason=%{public}d", log: log, type: .default, reason.rawValue)
        completionHandler()
    }

    // MARK: - Tracked PIDs

    private func handlePIDUpdate(_ payload: [String: Any]) {
        guard let entries = payload["entries"] as? [[String: Any]] else { return }
        var pids: Set<pid_t> = []
        for entry in entries {
            if let pid = entry["pid"] as? Int {
                pids.insert(pid_t(pid))
            }
        }
        stateQueue.async { [weak self] in
            guard let self else { return }
            self.trackedPIDs = pids
            os_log("Proxy tracking %{public}d PIDs", log: self.log, type: .default, pids.count)
            if self.debugEnabled {
                self.daemon.sendEvent(name: "proxy.pids", details: ["count": String(pids.count)],
                                      severity: "info", source: "leash.proxy")
            }
        }
    }

    /// The source PID for a flow, from its audit token (0 if unavailable).
    private func sourcePID(for flow: NEAppProxyFlow) -> pid_t {
        guard let tokenData = flow.metaData.sourceAppAuditToken else { return 0 }
        return tokenData.withUnsafeBytes { buffer in
            guard let pointer = buffer.baseAddress?.assumingMemoryBound(to: audit_token_t.self) else {
                return 0
            }
            return audit_token_to_pid(pointer.pointee)
        }
    }

    // MARK: - Flow handling

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        guard let tcpFlow = flow as? NEAppProxyTCPFlow else {
            return false // Not TCP — let the system handle it.
        }

        // Only route leash-tracked processes through the proxy; everything else passes
        // straight through untouched.
        let pid = sourcePID(for: flow)
        let dest = originalDestination(for: tcpFlow)
        let (isTracked, trackedCount, debug) = stateQueue.sync {
            (pid != 0 && trackedPIDs.contains(pid), trackedPIDs.count, debugEnabled)
        }

        // Verbose per-flow diagnostic (LEASH_MAC_DEBUG): shows whether leash-tracked
        // flows reach the provider and how PID gating resolves. Details are only built
        // when debug is on, so the normal path stays allocation-free here.
        if debug && pid != 0 {
            daemon.sendEvent(name: "proxy.flow", details: [
                "pid": String(pid),
                "tracked": isTracked ? "yes" : "no",
                "tracked_count": String(trackedCount),
                "dest": dest.map { "\($0.host):\($0.port)" } ?? "unresolved",
            ], severity: "info", source: "leash.proxy")
        }

        guard isTracked else {
            return false
        }

        guard let dest else {
            os_log("Tracked flow (pid=%{public}d) has no resolvable destination", log: log, type: .error, pid)
            return false
        }

        os_log("Routing tracked flow pid=%{public}d → %{public}@:%{public}d",
               log: log, type: .default, pid, dest.host, Int(dest.port))
        relay(tcpFlow, originalDest: dest)
        return true
    }

    /// The flow's original remote endpoint as an "ip:port" / "[ipv6]:port" string.
    private func originalDestination(for flow: NEAppProxyTCPFlow) -> ProxyDestination? {
        guard let endpoint = flow.remoteEndpoint as? NWHostEndpoint else {
            return nil
        }
        guard let port = UInt16(endpoint.port) else { return nil }
        return ProxyDestination(host: endpoint.hostname, port: port)
    }

    // MARK: - Relay

    private func relay(_ flow: NEAppProxyTCPFlow, originalDest dest: ProxyDestination) {
        let connection = NWConnection(
            host: Network.NWEndpoint.Host(proxyHost),
            port: proxyPort,
            using: .tcp
        )

        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                self.startRelay(flow: flow, connection: connection, dest: dest)
            case .failed(let error):
                os_log("Proxy connection failed: %{public}@", log: self.log, type: .error, String(describing: error))
                flow.closeReadWithError(error)
                flow.closeWriteWithError(error)
                connection.cancel()
            default:
                break
            }
        }
        connection.start(queue: relayQueue)
    }

    private func startRelay(flow: NEAppProxyTCPFlow, connection: NWConnection, dest: ProxyDestination) {
        flow.open(withLocalEndpoint: nil) { [weak self] error in
            guard let self else { return }
            if let error {
                os_log("Failed to open flow: %{public}@", log: self.log, type: .error, String(describing: error))
                connection.cancel()
                return
            }

            // Write the PROXY protocol v1 header first so the Go proxy learns the
            // original destination, then pump bytes in both directions.
            let header = Data(dest.proxyProtocolV1Header().utf8)
            connection.send(content: header, completion: .contentProcessed { [weak self] sendError in
                guard let self else { return }
                if let sendError {
                    os_log("Failed to send PROXY header: %{public}@", log: self.log, type: .error, String(describing: sendError))
                    connection.cancel()
                    flow.closeReadWithError(sendError)
                    flow.closeWriteWithError(sendError)
                    return
                }
                self.pumpFlowToConnection(flow, connection)
                self.pumpConnectionToFlow(connection, flow)
            })
        }
    }

    /// Close both flow directions and cancel the proxy connection.
    private func teardown(_ flow: NEAppProxyTCPFlow, _ connection: NWConnection, error: Error?) {
        flow.closeReadWithError(error)
        flow.closeWriteWithError(error)
        connection.cancel()
    }

    /// workload → proxy
    private func pumpFlowToConnection(_ flow: NEAppProxyTCPFlow, _ connection: NWConnection) {
        flow.readData { [weak self] data, error in
            guard let self else { return }
            if let error {
                self.teardown(flow, connection, error: error)
                return
            }
            guard let data, !data.isEmpty else {
                // EOF from the workload — half-close the send side to the proxy.
                connection.send(content: nil, isComplete: true, completion: .contentProcessed { _ in })
                return
            }
            connection.send(content: data, completion: .contentProcessed { [weak self] sendError in
                guard let self else { return }
                if let sendError {
                    self.teardown(flow, connection, error: sendError)
                    return
                }
                self.pumpFlowToConnection(flow, connection)
            })
        }
    }

    /// proxy → workload
    private func pumpConnectionToFlow(_ connection: NWConnection, _ flow: NEAppProxyTCPFlow) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, isComplete, error in
            guard let self else { return }

            if let data, !data.isEmpty {
                flow.write(data) { [weak self] writeError in
                    guard let self else { return }
                    if let writeError {
                        self.teardown(flow, connection, error: writeError)
                    } else if isComplete {
                        // Only tear down after the final chunk is actually written,
                        // otherwise the last bytes can be truncated.
                        self.teardown(flow, connection, error: nil)
                    } else {
                        self.pumpConnectionToFlow(connection, flow)
                    }
                }
            } else if isComplete || error != nil {
                self.teardown(flow, connection, error: error)
            }
        }
    }
}

/// A resolved flow destination plus its PROXY protocol v1 rendering.
struct ProxyDestination {
    let host: String
    let port: UInt16

    /// "PROXY TCP4|TCP6 <src> <dst> <sport> <dport>\r\n". We don't have the real
    /// source address here (unknown-src is acceptable — the proxy only uses the
    /// destination), so a placeholder loopback source is used.
    func proxyProtocolV1Header() -> String {
        let isIPv6 = host.contains(":")
        let family = isIPv6 ? "TCP6" : "TCP4"
        let src = isIPv6 ? "::1" : "127.0.0.1"
        return "PROXY \(family) \(src) \(host) 0 \(port)\r\n"
    }
}
