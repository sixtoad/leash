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

    func reloadNetworkRules() {
        daemon.queryNetworkRules { [weak self] result in
            guard let self else { return }
            switch result {
            case .success(let loaded):
                self.applyNetworkRules(loaded.rules, defaultAllow: loaded.defaultAllow)
            case .failure(let error):
                os_log("Failed to query network rules: %{public}@", log: self.log, type: .error, String(describing: error))
            }
        }
    }

    func handleNetworkRuleBroadcast(_ payload: [String: Any]) {
        guard let rulesData = payload["rules"] as? [[String: Any]] else { return }
        let decoded = rulesData.compactMap { NetworkRule.fromDictionary($0) }
        applyNetworkRules(decoded, defaultAllow: payload["network_default_allow"] as? Bool)
    }

    func applyNetworkRules(_ loaded: [NetworkRule], defaultAllow: Bool? = nil) {
        syncQueue.async {
            if let defaultAllow {
                self.networkDefaultAllow = defaultAllow
            }
            self.networkRulesLoaded = true

            if loaded.count != self.networkRules.count {
                os_log("Network rules updated: %{public}d → %{public}d rules",
                       log: self.log, type: .default,
                       self.networkRules.count, loaded.count)

                for rule in loaded where rule.enabled {
                    let cwdInfo = rule.currentWorkingDirectory.map { " [cwd: \($0)]" } ?? ""
                    os_log("   Rule: %{public}@ %{public}@ (%{public}@)%{public}@",
                           log: self.log, type: .default,
                           rule.action.rawValue.uppercased(),
                           rule.target.displayValue,
                           rule.target.typeString,
                           cwdInfo)
                }
            }

            self.networkRules = loaded
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
