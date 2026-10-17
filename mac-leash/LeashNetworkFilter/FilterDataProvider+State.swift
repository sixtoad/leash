import Foundation
import NetworkExtension
import Network
import os.log
import Darwin

extension FilterDataProvider {
// MARK: - State Management

    func handlePIDUpdate(_ payload: [String: Any]) {
        guard let entries = payload["entries"] as? [[String: Any]] else {
            os_log("Invalid PID update payload", log: log, type: .error)
            return
        }

        refreshRuntimeConfiguration()

        syncQueue.async { [weak self] in
            guard let self else { return }

            var loaded: [pid_t: TrackedPIDInfo] = [:]
            for entry in entries {
                guard let pid = entry["pid"] as? Int,
                      let leashPID = entry["leash_pid"] as? Int,
                      let executable = entry["executable"] as? String else {
                    continue
                }

                loaded[pid_t(pid)] = TrackedPIDInfo(
                    pid: pid_t(pid),
                    leashPID: pid_t(leashPID),
                    executablePath: executable,
                    ttyPath: entry["tty_path"] as? String,
                    cwd: entry["cwd"] as? String
                )
            }

            let oldPIDs = Set(self.trackedPIDs.keys)
            let newPIDs = Set(loaded.keys)

            let added = newPIDs.subtracting(oldPIDs)
            let removed = oldPIDs.subtracting(newPIDs)

            for pid in added {
                if let info = loaded[pid] {
                    os_log("NET tracking started: pid=%{public}d leash=%{public}d %{public}@ cwd=%{public}@",
                           log: self.log, type: .default,
                           pid, info.leashPID, info.executablePath, info.cwd ?? "none")
                }
            }

            for pid in removed {
                if let info = self.trackedPIDs[pid] {
                    os_log("NET tracking stopped: pid=%{public}d leash=%{public}d %{public}@",
                           log: self.log, type: .default,
                           pid, info.leashPID, info.executablePath)
                }
            }

            self.trackedPIDs = loaded

            if self.systemWideEnforcementEnabled {
                let drainedFlows = self.dequeuePendingFlowsLocked(availableInfo: loaded, now: Date())
                if !drainedFlows.isEmpty {
                    DispatchQueue.global(qos: .utility).async { [weak self] in
                        self?.processPendingFlowBatches(drainedFlows)
                    }
                }
            } else {
                self.pendingFlowsByPID.removeAll()
            }

            if !added.isEmpty || !removed.isEmpty {
                os_log("NET tracking state: %{public}d processes (added=%{public}d, removed=%{public}d)",
                       log: self.log, type: .default, loaded.count, added.count, removed.count)
            }
        }
    }

    func reloadPolicyTables() {
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

    /// Replaces the enforced tables (from the initial query or a daemon push)
    /// and acknowledges them. Tables this build cannot apply leave the filter
    /// with none, so leashed flows are denied, and the refusal is reported.
    func applyTables(_ payload: [String: Any]) {
        let version = payload["version"] as? String ?? ""
        do {
            let tables = try LeashPolicyTables.decode(from: payload)
            let matcher = try LeashPolicyMatcher(tables: tables)
            var previous: String?
            syncQueue.sync {
                previous = self.policyTables?.version
                self.policyTables = matcher
                self.tablesRefusal = nil
            }
            if previous != matcher.version {
                os_log("Applied network policy tables %{public}@: %{public}d rules, default %{public}@",
                       log: log, type: .default, matcher.version,
                       tables.network.rules.count, tables.network.defaultAllow ? "allow" : "deny")
            }
            daemon.sendPolicyApplied(version: matcher.version)
        } catch {
            syncQueue.sync {
                self.policyTables = nil
                self.tablesRefusal = "policy tables refused: \(error)"
            }
            os_log("REFUSED policy tables %{public}@: %{public}@", log: log, type: .fault, version, String(describing: error))
            daemon.sendPolicyApplied(version: version, error: String(describing: error))
        }
    }

    func reloadResolvedDomains() {
        guard let url = resolvedDomainsStoreURL else { return }
        persistenceQueue.async { [weak self] in
            guard let self else { return }
            guard let data = try? Data(contentsOf: url),
                  let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let entries = root["domains"] as? [[String: Any]] else {
                return
            }

            let now = Date()
            var restored: [String: DomainResolution] = [:]
            for entry in entries {
                guard let domain = entry["domain"] as? String,
                      let ips = entry["ips"] as? [String],
                      let expiryTS = entry["expiry"] as? TimeInterval else {
                    continue
                }
                let expiry = Date(timeIntervalSince1970: expiryTS)
                guard expiry > now else { continue }
                restored[domain] = DomainResolution(ips: Set(ips), expiry: expiry)
            }

            guard !restored.isEmpty else { return }
            self.syncQueue.async {
                // Only fill gaps — never clobber a mapping already learned since startup.
                var restoredCount = 0
                for (domain, res) in restored where self.domainResolutionCache[domain] == nil {
                    self.domainResolutionCache[domain] = res
                    restoredCount += 1
                }
                if restoredCount > 0 {
                    os_log("Restored %{public}d resolved domains from disk",
                           log: self.log, type: .default, restoredCount)
                }
            }
        }
    }
}
