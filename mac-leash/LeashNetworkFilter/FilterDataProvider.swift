import Foundation
import NetworkExtension
import Network
import os.log
import Darwin

class FilterDataProvider: NEFilterDataProvider {
    let log = OSLog(subsystem: LeashIdentifiers.bundle, category: "network-filter")
    var trackedPIDs: [pid_t: TrackedPIDInfo] = [:]
    /// The daemon's policy tables (nil until a usable version arrives), and
    /// why the last version was refused. Guarded by `syncQueue`.
    var policyTables: LeashPolicyMatcher?
    var tablesRefusal: String?
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
    var pendingDNSInspections: [ObjectIdentifier: DNSInspectionState] = [:]
    var pendingFlowsByPID: [pid_t: [QueuedFlow]] = [:]
    let maxPendingFlowsPerPID = 16
    let pendingFlowTTL: TimeInterval = 60
    var systemWideEnforcementEnabled = false
    var flowDelayEnabled = false
    var flowDelayRange: ClosedRange<TimeInterval>?

    /// Fail-closed state (#62); see FilterDataProvider+PolicyAvailability.
    /// (How long the daemon has been gone is owned by DaemonSync, which stamps
    /// the actual moment of the drop.)
    var failClosedEngaged = false
    var filterStartTime = Date()
    let policyStartupGrace: TimeInterval = 15
    let policyDisconnectGrace: TimeInterval = 30

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
        let direction: NETrafficDirection
        let enqueueTime: Date
    }

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        os_log("Network filter starting...", log: log, type: .default)

        // Anchor the fail-closed startup grace at the moment the provider
        // actually starts, not at object construction.
        syncQueue.sync {
            filterStartTime = Date()
            policyTables = nil
            failClosedEngaged = false
        }

        daemon.subscribe(to: "mac.pid.sync") { [weak self] payload in
            self?.handlePIDUpdate(payload)
        }

        refreshRuntimeConfiguration(reason: "startup")

        daemon.subscribe(to: "mac.policy.tables") { [weak self] payload in
            self?.applyTables(payload)
        }

        reloadPolicyTables()
        reloadResolvedDomains()

        completionHandler(nil)
    }

    override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        os_log("Network filter stopping: reason=%{public}d", log: log, type: .default, reason.rawValue)

        syncQueue.sync {
            trackedPIDs.removeAll()
            policyTables = nil
        }

        completionHandler()
    }
}
