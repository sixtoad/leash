import Foundation
import NetworkExtension
import Network
import os.log
import Darwin

extension FilterDataProvider {
// MARK: - Pending Flow Management

    func recordPendingFlow(
        pid: pid_t,
        hostname: String,
        originalHostname: String,
        port: String,
        socketType: String,
        socketProtocolNumber: Int32,
        isDNSQuery: Bool,
        direction: NETrafficDirection
    ) {
        guard pid > 0 else { return }
        let allowQueue = syncQueue.sync { systemWideEnforcementEnabled }
        guard allowQueue else { return }

        let pending = QueuedFlow(
            pid: pid,
            hostname: hostname,
            originalHostname: originalHostname,
            port: port,
            socketType: socketType,
            socketProtocolNumber: socketProtocolNumber,
            isDNSQuery: isDNSQuery,
            direction: direction,
            enqueueTime: Date()
        )

        var queued = false
        syncQueue.sync {
            evictExpiredPendingFlowsLocked(now: pending.enqueueTime)
            var queue = pendingFlowsByPID[pid] ?? []
            queue.append(pending)
            if queue.count > maxPendingFlowsPerPID {
                queue.removeFirst(queue.count - maxPendingFlowsPerPID)
            }
            pendingFlowsByPID[pid] = queue
            queued = true
        }

        if queued {
            os_log("NET pending flow queued: pid=%{public}d %{public}@:%{public}@ (dns=%{public}@) awaiting PID metadata",
                   log: log, type: .info,
                   pid, hostname, port,
                   isDNSQuery ? "yes" : "no")
        }
    }

    func evictExpiredPendingFlowsLocked(now: Date) {
        guard !pendingFlowsByPID.isEmpty else { return }
        pendingFlowsByPID = pendingFlowsByPID.compactMapValues { flows in
            let filtered = flows.filter { now.timeIntervalSince($0.enqueueTime) <= pendingFlowTTL }
            return filtered.isEmpty ? nil : filtered
        }
    }

    func dequeuePendingFlowsLocked(
        availableInfo: [pid_t: TrackedPIDInfo],
        now: Date
    ) -> [(TrackedPIDInfo, [QueuedFlow])] {
        guard !pendingFlowsByPID.isEmpty else { return [] }
        evictExpiredPendingFlowsLocked(now: now)

        if pendingFlowsByPID.isEmpty {
            return []
        }

        var drained: [(TrackedPIDInfo, [QueuedFlow])] = []
        for (pid, flows) in pendingFlowsByPID {
            guard let info = availableInfo[pid], !flows.isEmpty else {
                continue
            }
            drained.append((info, flows))
        }

        for (info, _) in drained {
            pendingFlowsByPID.removeValue(forKey: info.pid)
        }

        return drained
    }

    /// Flows of processes whose PID metadata arrived late were already let
    /// through (system-wide mode only); this records what the policy would
    /// have decided, for the event log.
    func processPendingFlowBatches(_ batches: [(TrackedPIDInfo, [QueuedFlow])]) {
        let allowFallback = syncQueue.sync { systemWideEnforcementEnabled }
        guard allowFallback else { return }

        for (info, flows) in batches {
            for flow in flows {
                let decision = evaluateFlow(hostname: flow.hostname, port: flow.port, direction: flow.direction, exemptLocalScope: true)
                emitNetworkEvent(
                    info: info,
                    pid: flow.pid,
                    hostname: flow.hostname,
                    port: flow.port,
                    socketType: flow.socketType,
                    socketProtocol: describeSocketProtocol(flow.socketProtocolNumber),
                    decision: decision,
                    isDNSQuery: flow.isDNSQuery,
                    originalHostname: flow.originalHostname
                )
            }
        }
    }

    func refreshRuntimeConfiguration(reason: String = "provider configuration") {
        let vendorConfiguration = filterConfiguration.vendorConfiguration ?? [:]

        var systemWideEnabled = false
        if let value = vendorConfiguration[LeashIdentifiers.systemWideEnforcementConfigKey] {
            if let bool = value as? Bool {
                systemWideEnabled = bool
            } else if let number = value as? NSNumber {
                systemWideEnabled = number.boolValue
            }
        }

        var delayEnabled = false
        if let value = vendorConfiguration[LeashIdentifiers.flowDelayEnabledConfigKey] {
            if let bool = value as? Bool {
                delayEnabled = bool
            } else if let number = value as? NSNumber {
                delayEnabled = number.boolValue
            }
        }

        var minDelay = FlowDelayDefaults.min
        if let value = vendorConfiguration[LeashIdentifiers.flowDelayMinConfigKey] {
            if let doubleValue = value as? Double {
                minDelay = doubleValue
            } else if let number = value as? NSNumber {
                minDelay = number.doubleValue
            }
        }

        var maxDelay = FlowDelayDefaults.max
        if let value = vendorConfiguration[LeashIdentifiers.flowDelayMaxConfigKey] {
            if let doubleValue = value as? Double {
                maxDelay = doubleValue
            } else if let number = value as? NSNumber {
                maxDelay = number.doubleValue
            }
        }

        minDelay = max(FlowDelayDefaults.lowerBound, minDelay)
        maxDelay = max(minDelay, min(maxDelay, FlowDelayDefaults.upperBound))
        var delayRange: ClosedRange<TimeInterval>? = nil
        if delayEnabled && maxDelay > 0 {
            delayRange = minDelay...maxDelay
        } else {
            delayEnabled = false
        }

        updateSystemWideEnforcementEnabled(systemWideEnabled, reason: reason)
        updateFlowDelayConfiguration(enabled: delayEnabled, range: delayRange, reason: reason)
    }

    func updateSystemWideEnforcementEnabled(_ enabled: Bool, reason: String) {
        var changed = false
        syncQueue.sync {
            if systemWideEnforcementEnabled != enabled {
                systemWideEnforcementEnabled = enabled
                if !enabled {
                    pendingFlowsByPID.removeAll()
                }
               changed = true
           }
       }

       guard changed else { return }
       if enabled {
           os_log("System-wide enforcement enabled (%{public}@). Untracked flows will be evaluated using proc metadata.",
                  log: log, type: .info, reason)
       } else {
           os_log("System-wide enforcement disabled (%{public}@). Flows without PID metadata bypass leash rules.",
                  log: log, type: .info, reason)
       }
   }

    func updateFlowDelayConfiguration(enabled: Bool, range: ClosedRange<TimeInterval>?, reason: String) {
        var changed = false
        var currentEnabled = false
        var currentRange: ClosedRange<TimeInterval>?
        syncQueue.sync {
            let normalizedRange = enabled ? range : nil
            if flowDelayEnabled != (normalizedRange != nil) || flowDelayRange != normalizedRange {
                flowDelayEnabled = normalizedRange != nil
                flowDelayRange = normalizedRange
                changed = true
            }
            currentEnabled = flowDelayEnabled
            currentRange = flowDelayRange
        }

        guard changed else { return }

        if currentEnabled, let range = currentRange {
            let lowerMs = Int(range.lowerBound * 1000)
            let upperMs = Int(range.upperBound * 1000)
            os_log("Flow delay enabled (%{public}@). Applying random delay between %{public}d–%{public}d ms for new flows.",
                   log: log, type: .info, reason, lowerMs, upperMs)
        } else {
            os_log("Flow delay disabled (%{public}@). New flows will be evaluated immediately.",
                   log: log, type: .info, reason)
        }
    }

    
}
