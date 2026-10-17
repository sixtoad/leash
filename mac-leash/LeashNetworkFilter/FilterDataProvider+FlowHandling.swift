import Foundation
import NetworkExtension
import Network
import os.log
import Darwin

extension FilterDataProvider {
// MARK: - Flow Handling

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        guard let socketFlow = flow as? NEFilterSocketFlow else {
            return .allow()
        }

        // The source PID decides whether the flow is leashed at all. A flow
        // without one cannot be attributed to a leashed process.
        guard let auditTokenData = socketFlow.sourceAppAuditToken else {
            return .allow()
        }
        let pid: pid_t = auditTokenData.withUnsafeBytes { buffer in
            guard let pointer = buffer.baseAddress?.assumingMemoryBound(to: audit_token_t.self) else {
                return 0
            }
            return audit_token_to_pid(pointer.pointee)
        }

        refreshRuntimeConfiguration()
        let allowSystemWideFallback = syncQueue.sync { systemWideEnforcementEnabled }
        let delayRange = syncQueue.sync { flowDelayEnabled ? flowDelayRange : nil }
        if let delayRange {
            let delay = Double.random(in: delayRange)
            if delay > 0 {
                Thread.sleep(forTimeInterval: delay)
            }
        }

        var pidInfo: TrackedPIDInfo?
        syncQueue.sync {
            pidInfo = trackedPIDs[pid]
        }
        let leashed = pidInfo != nil

        // A leashed flow whose destination is not a host endpoint cannot be
        // decided by address: deny it rather than let it through unexamined.
        guard let hostEndpoint = socketFlow.remoteEndpoint as? NWHostEndpoint else {
            if leashed {
                os_log("NET[pid=%{public}d] leashed flow without a host endpoint → DENY", log: log, type: .default, pid)
                return .drop()
            }
            return .allow()
        }
        let hostname = hostEndpoint.hostname
        let port = hostEndpoint.port

        let socketType = socketFlow.socketFamily == AF_INET ? "IPv4" :
                        socketFlow.socketFamily == AF_INET6 ? "IPv6" : "unknown"
        let socketProtocolNumber = socketFlow.socketProtocol
        let socketProtocol = describeSocketProtocol(socketProtocolNumber)
        // DNS is decided like any other flow (to the resolver's address); it is
        // only recognised here so the query name can be logged.
        let isDNSQuery = socketFlow.socketProtocol == IPPROTO_UDP && port == "53"

        var usedFallbackInfo = false
        if pidInfo == nil, allowSystemWideFallback {
            if let inferred = inferTrackedInfo(for: pid) {
                pidInfo = inferred
                usedFallbackInfo = true
            }
        }

        guard let info = pidInfo else {
            if allowSystemWideFallback {
                recordPendingFlow(
                    pid: pid,
                    hostname: hostname,
                    originalHostname: hostname,
                    port: port,
                    socketType: socketType,
                    socketProtocolNumber: socketProtocolNumber,
                    isDNSQuery: isDNSQuery,
                    direction: socketFlow.direction
                )
            }
            return .allow()
        }

        let decision = evaluateFlow(
            hostname: hostname,
            port: port,
            direction: socketFlow.direction,
            exemptLocalScope: usedFallbackInfo
        )

        switch decision {
        case .allow:
            if isDNSQuery {
                let flowKey = ObjectIdentifier(flow)
                syncQueue.sync {
                    pendingDNSInspections[flowKey] = DNSInspectionState(
                        pidInfo: info,
                        pid: pid,
                        originalHostname: hostname,
                        port: port,
                        socketType: socketType,
                        socketProtocolName: socketProtocol,
                        buffer: Data()
                    )
                }
                return .filterDataVerdict(
                    withFilterInbound: false,
                    peekInboundBytes: 0,
                    filterOutbound: true,
                    peekOutboundBytes: 512
                )
            }

            emitNetworkEvent(
                info: info,
                pid: pid,
                hostname: hostname,
                port: port,
                socketType: socketType,
                socketProtocol: socketProtocol,
                decision: decision,
                isDNSQuery: isDNSQuery,
                originalHostname: hostname
            )
            return .allow()

        case .deny:
            emitNetworkEvent(
                info: info,
                pid: pid,
                hostname: hostname,
                port: port,
                socketType: socketType,
                socketProtocol: socketProtocol,
                decision: decision,
                isDNSQuery: isDNSQuery,
                originalHostname: hostname
            )
            return .drop()
        }
    }

    override func handleOutboundData(from flow: NEFilterFlow, readBytesStartOffset offset: Int, readBytes: Data) -> NEFilterDataVerdict {
        let flowKey = ObjectIdentifier(flow)
        if let dnsVerdict = handleDNSOutbound(flow: flow, flowKey: flowKey, readBytes: readBytes) {
            return dnsVerdict
        }
        return .allow()
    }
}
