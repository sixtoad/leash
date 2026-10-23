import Foundation
import os.log

/// The Endpoint Security extension's link to the daemon: it receives the
/// policy tables, answers every decision from them, and reports events.
final class LeashCommunicationService: NSObject {
    let log = OSLog(subsystem: LeashIdentifiers.bundle, category: "communication")
    let daemon = DaemonSync.shared
    let queue = DispatchQueue(label: LeashIdentifiers.namespaced("communication"))
    weak var monitor: LeashMonitor?

    /// The tables this extension enforces; nil until the daemon delivered a
    /// version this build can apply. Guarded by `matcherLock` so ES handlers
    /// can read it without hopping queues (they must answer before the
    /// message deadline).
    private var matcher: LeashPolicyMatcher?
    private let matcherLock = NSLock()

    /// How long the extension keeps enforcing its last tables after the daemon
    /// connection drops. After that every decision for a leashed process is a
    /// deny: the policy may have changed since, and the daemon going away must
    /// not leave the workload running on a policy nobody can update (on Linux
    /// the workload is stopped when leashd exits).
    let daemonLossGrace: TimeInterval = 30

    override init() {
        super.init()
        daemon.subscribe(to: "mac.policy.tables") { [weak self] payload in
            self?.applyTables(payload)
        }
        // The daemon replays the tracked set on every hello; after a restart
        // this is how the extension picks up a workload that is still running.
        daemon.subscribe(to: "mac.pid.sync") { [weak self] payload in
            self?.monitor?.restoreTrackedPIDs(payload)
        }
    }

    func start() {
        os_log("Communication service started (using WebSocket)", log: self.log, type: .info)
        daemon.queryPolicyTables { [weak self] result in
            guard let self else { return }
            switch result {
            case .success(let payload):
                self.applyTables(payload)
            case .failure(let error):
                os_log("Failed to query policy tables: %{public}@ (they arrive on the next hello)",
                       log: self.log, type: .error, String(describing: error))
            }
        }
    }

    /// Replaces the enforced tables. Tables this build cannot apply leave the
    /// extension with none, so it denies, and the refusal is reported: keeping
    /// the previous tables would enforce a policy the daemon no longer has.
    func applyTables(_ payload: [String: Any]) {
        let version = payload["version"] as? String ?? ""
        do {
            let tables = try LeashPolicyTables.decode(from: payload)
            let next = try LeashPolicyMatcher(tables: tables)
            matcherLock.lock()
            let previous = matcher?.version
            matcher = next
            matcherLock.unlock()
            if previous != next.version {
                os_log("Applied policy tables %{public}@ (exec rules=%d file entries=%d)",
                       log: log, type: .default, next.version,
                       tables.exec.rules.count, tables.file.exact.count + tables.file.prefix.count)
            }
            daemon.sendPolicyApplied(version: next.version)
        } catch {
            matcherLock.lock()
            matcher = nil
            matcherLock.unlock()
            os_log("REFUSED policy tables %{public}@: %{public}@; denying leashed operations until usable tables arrive",
                   log: log, type: .fault, version, String(describing: error))
            daemon.sendPolicyApplied(version: version, error: String(describing: error))
        }
    }

    /// The matcher to decide with, or the reason there is none.
    func currentMatcher() -> (LeashPolicyMatcher?, String) {
        matcherLock.lock()
        let m = matcher
        matcherLock.unlock()
        guard let m else {
            return (nil, "no policy tables from the leash daemon")
        }
        if !daemon.isConnected, let since = daemon.disconnectedSince,
           Date().timeIntervalSince(since) > daemonLossGrace {
            return (nil, "leash daemon connection lost; policy may be stale")
        }
        return (m, "")
    }

    func logEvent(_ event: LeashPolicyEvent, decision: LeashPolicyDecision.Action, reason: String? = nil) {
        queue.async { [weak self] in
            guard let self else { return }

            self.daemon.sendPolicyEvent(event) { error in
                if let error {
                    os_log("Failed to send policy event: %{public}@", log: self.log, type: .error, String(describing: error))
                }
            }

            var details: [String: String] = [
                "process_path": event.processPath,
                "pid": String(event.pid),
                "kind": event.kind.rawValue,
                "decision": decision == .allow ? "allowed" : "denied"
            ]

            if !event.processArguments.isEmpty {
                details["args"] = event.processArguments.joined(separator: " ")
                details["argc"] = String(event.processArguments.count)
            }
            if let cwd = event.currentWorkingDirectory {
                details["cwd"] = cwd
            }
            if let filePath = event.filePath {
                details["file_path"] = filePath
            }
            if let tty = event.ttyPath {
                details["tty_path"] = tty
            }
            if let leashPid = event.leashPid {
                details["leash_pid"] = String(leashPid)
            }
            if let leashPath = event.leashProcessPath {
                details["leash_process"] = leashPath
            }
            if let parent = event.parentProcessPath {
                details["parent_process"] = parent
            }
            if let leashArgs = event.leashArguments, !leashArgs.isEmpty {
                details["leash_args"] = leashArgs.joined(separator: " ")
            }
            if let leashTTY = event.leashTTYPath {
                details["leash_tty"] = leashTTY
            }
            if let reason {
                details["reason"] = reason
            }
            let eventName: String
            switch event.kind {
            case .processExec:
                eventName = "proc.exec"
            case .fileAccess:
                let fileOperation = event.fileOperation ?? .open
                details["operation"] = fileOperation.rawValue
                switch fileOperation {
                case .create, .write, .truncate:
                    eventName = "file.open:rw"
                case .open:
                    eventName = "file.open"
                case .mkdir, .symlink, .unlink, .rename, .link, .clone:
                    eventName = "file.mutation"
                }
            }

            details["action"] = decision == .allow ? "allow" : "deny"

            self.daemon.sendEvent(
                name: eventName,
                details: details,
                severity: decision == .allow ? "info" : "warning",
                source: "leash.es",
                ruleID: nil
            )
        }
    }

    func pushTrackedPIDs(_ entries: [DaemonSync.PIDEntry]) {
        daemon.sendTrackedPIDs(entries)
        os_log("Synced %{public}d tracked PIDs", log: self.log, type: .info, entries.count)
    }
}
