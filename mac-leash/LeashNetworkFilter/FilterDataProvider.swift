import Foundation
import NetworkExtension
import Network
import os.log
import Darwin

class FilterDataProvider: NEFilterDataProvider {
    let log = OSLog(subsystem: LeashIdentifiers.bundle, category: "network-filter")
    var trackedPIDs: [pid_t: TrackedPIDInfo] = [:]
    var networkRules: [NetworkRule] = []
    // Connect default posture forwarded from policy (Cedar ConnectDefaultAllow).
    // Defaults to allow so we never fail closed before a policy has been applied.
    var networkDefaultAllow = true
    // True once the daemon has delivered a network rule set (query or broadcast),
    // gating default-deny so we don't deny in the connect→first-snapshot window.
    var networkRulesLoaded = false
    let syncQueue = DispatchQueue(label: LeashIdentifiers.namespaced("filter.sync"))
    let persistenceQueue = DispatchQueue(label: LeashIdentifiers.namespaced("filter.persistence"), qos: .utility)
    let daemon = DaemonSync.shared

    /// On-disk location for the resolved-domain cache. Best-effort — nil if the
    /// Application Support directory can't be resolved; callers must tolerate that.
    /// Resolved once (path is static and read from multiple threads).
    let resolvedDomainsStoreURL: URL? = {
        guard let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else {
            return nil
        }
        return base
            .appendingPathComponent(LeashIdentifiers.bundle, isDirectory: true)
            .appendingPathComponent("resolved-domains.json")
    }()
    var domainResolutionCache: [String: DomainResolution] = [:]
    var pendingInspections: [ObjectIdentifier: PendingInspectionState] = [:]
    var pendingDNSInspections: [ObjectIdentifier: DNSInspectionState] = [:]
    var pendingFlowsByPID: [pid_t: [QueuedFlow]] = [:]
    let maxPendingFlowsPerPID = 16
    let pendingFlowTTL: TimeInterval = 60
    var systemWideEnforcementEnabled = false
    var flowDelayEnabled = false
    var flowDelayRange: ClosedRange<TimeInterval>?

    enum FlowDelayDefaults {
        static let min: TimeInterval = 0.1
        static let max: TimeInterval = 0.5
        static let lowerBound: TimeInterval = 0.0
        static let upperBound: TimeInterval = 1.0
    }

    struct DomainResolution {
        let ips: Set<String>
        let expiry: Date
    }

    let domainResolutionTTL: TimeInterval = 300 // seconds

    struct TrackedPIDInfo {
        let pid: pid_t
        let leashPID: pid_t
        let executablePath: String
        let ttyPath: String?
        let cwd: String?
    }

    struct PendingInspectionState {
        var pidInfo: TrackedPIDInfo
        var pid: pid_t
        var originalHostname: String
        var port: String
        var socketType: String
        var socketProtocolName: String
        var socketProtocolNumber: Int32
        var buffer: Data
    }

    struct DNSInspectionState {
        var pidInfo: TrackedPIDInfo
        var pid: pid_t
        var originalHostname: String
        var port: String
        var socketType: String
        var socketProtocolName: String
        var buffer: Data
    }

    struct QueuedFlow {
        let pid: pid_t
        let hostname: String
        let originalHostname: String
        let port: String
        let socketType: String
        let socketProtocolNumber: Int32
        let isDNSQuery: Bool
        let enqueueTime: Date
    }

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        os_log("Network filter starting...", log: log, type: .default)

        daemon.subscribe(to: "mac.pid.sync") { [weak self] payload in
            self?.handlePIDUpdate(payload)
        }

        refreshRuntimeConfiguration(reason: "startup")

        daemon.subscribe(to: "mac.network_rule.update") { [weak self] payload in
            self?.handleNetworkRuleBroadcast(payload)
        }

        reloadNetworkRules()
        reloadResolvedDomains()

        completionHandler(nil)
    }

    override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        os_log("Network filter stopping: reason=%{public}d", log: log, type: .default, reason.rawValue)

        syncQueue.sync {
            trackedPIDs.removeAll()
            networkRules.removeAll()
        }

        completionHandler()
    }
}
