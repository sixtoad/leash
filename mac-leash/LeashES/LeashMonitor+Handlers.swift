import Foundation
import EndpointSecurity
import os.log
import Darwin

extension LeashMonitor {
    /// AUTH events decided for leashed processes. Besides exec and open these
    /// are the file-system mutations the Linux LSM decides (mkdir, unlink,
    /// rmdir, rename, hard link) and the macOS ways to create or replace a
    /// file without an AUTH_OPEN (create, truncate, clone, copyfile,
    /// exchangedata). Subscribed while any leashed process is alive.
    static let authEventTypes: [es_event_type_t] = [
        ES_EVENT_TYPE_AUTH_EXEC,
        ES_EVENT_TYPE_AUTH_OPEN,
        ES_EVENT_TYPE_AUTH_CREATE,
        ES_EVENT_TYPE_AUTH_UNLINK,
        ES_EVENT_TYPE_AUTH_RENAME,
        ES_EVENT_TYPE_AUTH_LINK,
        ES_EVENT_TYPE_AUTH_TRUNCATE,
        ES_EVENT_TYPE_AUTH_CLONE,
        ES_EVENT_TYPE_AUTH_COPYFILE,
        ES_EVENT_TYPE_AUTH_EXCHANGEDATA
    ]

    func handle(_ message: UnsafeMutablePointer<es_message_t>) {
        defer { es_release_message(message) }

        switch message.pointee.event_type {
        case ES_EVENT_TYPE_NOTIFY_EXEC:
            processNotifyExecMessage(message)
        case ES_EVENT_TYPE_NOTIFY_FORK:
            processForkMessage(message)
        case ES_EVENT_TYPE_AUTH_EXEC:
            processAuthExecMessage(message)
        case ES_EVENT_TYPE_AUTH_OPEN:
            processAuthOpenMessage(message)
        case ES_EVENT_TYPE_AUTH_CREATE, ES_EVENT_TYPE_AUTH_UNLINK, ES_EVENT_TYPE_AUTH_RENAME,
             ES_EVENT_TYPE_AUTH_LINK, ES_EVENT_TYPE_AUTH_TRUNCATE, ES_EVENT_TYPE_AUTH_CLONE,
             ES_EVENT_TYPE_AUTH_COPYFILE, ES_EVENT_TYPE_AUTH_EXCHANGEDATA:
            processAuthFileSystemMessage(message)
        case ES_EVENT_TYPE_NOTIFY_EXIT:
            processExitMessage(message)
        default:
            // Every AUTH message must be answered before its deadline, or the
            // kernel kills this client.
            if message.pointee.action_type == ES_ACTION_TYPE_AUTH {
                respondAuth(message, action: .allow, cache: false)
            }
        }
    }

    // MARK: - Decisions

    /// Decides with the daemon's policy tables. No tables (none delivered
    /// yet, a refused version, or a daemon gone for longer than the grace
    /// period) is a deny: a leashed process is never allowed something the
    /// policy was not consulted for.
    func decide(_ check: (LeashPolicyMatcher) -> Bool) -> (action: LeashPolicyDecision.Action, reason: String?) {
        guard let commService else {
            return (.deny, "no communication service")
        }
        let (matcher, reason) = commService.currentMatcher()
        guard let matcher else {
            return (.deny, reason)
        }
        return check(matcher) ? (.allow, nil) : (.deny, nil)
    }

    func leashedContext(for process: es_process_t) -> TrackedLeashProcess? {
        let pid = audit_token_to_pid(process.audit_token)
        return leashInfo(for: process) ?? trackedLeashProcesses[pid]
    }

    // MARK: - Process tracking

    func processNotifyExecMessage(_ message: UnsafeMutablePointer<es_message_t>) {
        let execEvent = message.pointee.event.exec
        let targetProcess = execEvent.target.pointee

        guard let executablePath = string(from: targetProcess.executable.pointee.path), !executablePath.isEmpty else { return }

        let pid = audit_token_to_pid(targetProcess.audit_token)
        let isLeash = isLeashExecutable(targetProcess, executablePath: executablePath)

        // Every leashcli is a leash root, with or without a terminal: it only
        // runs commands for `leash --darwin exec`, which waits for this
        // extension to report it tracked before letting it start the command.
        // (Requiring a TTY used to leave non-interactive runs unenforced.)
        if isLeash {
            let arguments = extractArguments(from: message)
            let ttyPath = ttyPath(for: targetProcess)
            let cwd = Optional(execEvent.cwd).flatMap { string(from: $0.pointee.path) }
            let signingIdentifier = string(from: targetProcess.signing_id)
            let teamIdentifier = string(from: targetProcess.team_id)

            trackedLeashProcesses[pid] = TrackedLeashProcess(
                pid: pid,
                executablePath: executablePath,
                arguments: arguments,
                ttyPath: ttyPath,
                signingIdentifier: signingIdentifier,
                teamIdentifier: teamIdentifier,
                currentWorkingDirectory: cwd,
                leashPID: pid,
                leashArguments: arguments,
                leashTTYPath: ttyPath,
                leashExecutablePath: executablePath
            )

            os_log("Leash CLI started: pid=%{public}d cwd=%{public}@", log: log, type: .default, pid, cwd ?? "unknown")

            if !authEventsEnabled {
                enableAuthEvents()
            }

            syncTrackedPIDsToNetwork()
            return
        }

        if let leashInfo = leashInfo(for: targetProcess), trackedLeashProcesses[pid] == nil {
            if let (tracked, event) = buildExecContext(message: message, process: targetProcess, leashInfo: leashInfo) {
                trackedLeashProcesses[pid] = tracked
                syncTrackedPIDsToNetwork()
                let decision = decide { $0.allowsExec(path: event.processPath, arguments: event.processArguments) }
                logEventAsync(event, decision: decision.action, reason: decision.reason)
            }
        }
    }

    /// A process forked by a leashed process is leashed too. Without this a
    /// child that never execs was unknown to the network filter and the
    /// transparent proxy, which only enforce for the PIDs this extension
    /// reports (its file opens were already caught by the parent lookup).
    func processForkMessage(_ message: UnsafeMutablePointer<es_message_t>) {
        let parent = message.pointee.process.pointee
        let parentPID = audit_token_to_pid(parent.audit_token)
        let child = message.pointee.event.fork.child.pointee
        let childPID = audit_token_to_pid(child.audit_token)

        guard let source = trackedLeashProcesses[parentPID] ?? leashInfo(for: parent) else { return }

        trackedLeashProcesses[childPID] = TrackedLeashProcess(
            pid: childPID,
            executablePath: source.executablePath,
            arguments: source.arguments,
            ttyPath: source.ttyPath,
            signingIdentifier: source.signingIdentifier,
            teamIdentifier: source.teamIdentifier,
            currentWorkingDirectory: source.currentWorkingDirectory,
            leashPID: source.leashPID ?? parentPID,
            leashArguments: source.leashArguments,
            leashTTYPath: source.leashTTYPath,
            leashExecutablePath: source.leashExecutablePath
        )
        syncTrackedPIDsToNetwork()
    }

    func processExitMessage(_ message: UnsafeMutablePointer<es_message_t>) {
        let process = message.pointee.process.pointee
        let pid = audit_token_to_pid(process.audit_token)

        // Each leashed process stays tracked until it exits itself. Processes
        // the workload left running after leashcli exited (a daemonized
        // server, a background job) used to be dropped with it and ran on
        // unenforced; on Linux they stay in the cgroup.
        if trackedLeashProcesses.removeValue(forKey: pid) != nil {
            os_log("Leash-tracked process exiting: pid=%{public}d", log: log, type: .default, pid)
            syncTrackedPIDsToNetwork()

            if authEventsEnabled && trackedLeashProcesses.isEmpty {
                scheduleAuthDisable()
            }
        }
    }

    /// Re-tracks processes the daemon still lists as leashed (the set this
    /// extension reported before it restarted): tracking lives in memory, so
    /// without this a restarted extension would stop enforcing for a
    /// workload that is still running. A PID is restored only while it is
    /// alive and still runs the executable that was reported for it.
    func restoreTrackedPIDs(_ payload: [String: Any]) {
        guard let entries = payload["entries"] as? [[String: Any]] else { return }
        callbackQueue.async { [weak self] in
            guard let self else { return }
            var restored = 0
            for entry in entries {
                guard let rawPID = entry["pid"] as? Int,
                      let executable = entry["executable"] as? String else { continue }
                let pid = pid_t(rawPID)
                guard self.trackedLeashProcesses[pid] == nil,
                      let current = self.processPath(pid: pid), current == executable else { continue }
                let leashPID = (entry["leash_pid"] as? Int).map { pid_t($0) } ?? pid
                self.trackedLeashProcesses[pid] = TrackedLeashProcess(
                    pid: pid,
                    executablePath: executable,
                    arguments: [],
                    ttyPath: entry["tty_path"] as? String,
                    signingIdentifier: nil,
                    teamIdentifier: nil,
                    currentWorkingDirectory: entry["cwd"] as? String,
                    leashPID: leashPID,
                    leashArguments: nil,
                    leashTTYPath: nil,
                    leashExecutablePath: nil
                )
                restored += 1
            }
            if restored > 0 {
                os_log("Restored %{public}d leashed processes from the daemon", log: self.log, type: .default, restored)
                if !self.authEventsEnabled {
                    self.enableAuthEvents()
                }
                self.syncTrackedPIDsToNetwork()
            }
        }
    }

    /// Debounced teardown: unsubscribe from AUTH events only if the tracked set is
    /// still empty after a short grace period. Avoids losing gating across a rapid
    /// exec chain that momentarily empties the set. Runs on callbackQueue (serial).
    func scheduleAuthDisable() {
        pendingAuthDisable?.cancel()
        let work = DispatchWorkItem { [weak self] in
            guard let self else { return }
            self.pendingAuthDisable = nil
            if self.authEventsEnabled && self.trackedLeashProcesses.isEmpty {
                self.disableAuthEvents()
            }
        }
        pendingAuthDisable = work
        callbackQueue.asyncAfter(deadline: .now() + authDisableGracePeriod, execute: work)
    }

    // MARK: - Exec and open

    func processAuthExecMessage(_ message: UnsafeMutablePointer<es_message_t>) {
        let targetProcess = message.pointee.event.exec.target.pointee

        guard let leashInfo = leashInfo(for: targetProcess) else {
            respondAuth(message, action: .allow, cache: false)
            return
        }

        guard let (trackedProcess, event) = buildExecContext(message: message, process: targetProcess, leashInfo: leashInfo) else {
            // A leashed exec whose path cannot be read cannot be decided.
            respondAuth(message, action: .deny, cache: false)
            return
        }

        trackedLeashProcesses[trackedProcess.pid] = trackedProcess

        let decision = decide { $0.allowsExec(path: event.processPath, arguments: event.processArguments) }

        os_log("AUTH_EXEC[leash=%{public}d]: %{public}@ (pid=%d) → %{public}@",
               log: log, type: .default,
               leashInfo.leashPID ?? -1,
               event.processPath, event.pid,
               decision.action == .allow ? "ALLOW" : "DENY")

        logEventAsync(event, decision: decision.action, reason: decision.reason)
        syncTrackedPIDsToNetwork()
        respondAuth(message, action: decision.action, cache: false)
    }

    func processAuthOpenMessage(_ message: UnsafeMutablePointer<es_message_t>) {
        let process = message.pointee.process.pointee
        let openEvent = message.pointee.event.open
        let requestedFlags = openEvent.fflag

        guard let leashInfo = leashedContext(for: process) else {
            respondOpen(message, action: .allow, requestedFlags: requestedFlags, cache: false)
            return
        }

        guard let path = resolvePath(for: openEvent.file), path.hasPrefix("/") else {
            respondOpen(message, action: .deny, requestedFlags: requestedFlags, cache: false)
            return
        }

        // The kernel's two open modes: a write is any open requesting FWRITE.
        let write = (requestedFlags & FWRITE) != 0
        let operation: LeashPolicyEvent.FileOperation
        if write && (requestedFlags & O_CREAT) != 0 {
            operation = .create
        } else if write {
            operation = .write
        } else {
            operation = .open
        }

        let decision = decide { $0.allowsOpen(path: path, write: write) }
        let event = fileEvent(process: process, leashInfo: leashInfo, path: path, operation: operation)

        os_log("AUTH_OPEN[leash=%{public}d]: %{public}@ → %{public}@ (%{public}@) → %{public}@",
               log: log, type: .default,
               leashInfo.leashPID ?? -1,
               event.processPath, path, operation.rawValue,
               decision.action == .allow ? "ALLOW" : "DENY")

        logEventAsync(event, decision: decision.action, reason: decision.reason)
        respondOpen(message, action: decision.action, requestedFlags: requestedFlags, cache: false)
    }

    // MARK: - File-system mutations

    /// One check a file-system AUTH event needs: the path it acts on and the
    /// table lookup that decides it. An event is allowed only when every one
    /// of its checks is.
    private struct FileCheck {
        let operation: LeashPolicyEvent.FileOperation
        let path: String?
        let check: (LeashPolicyMatcher, String) -> Bool
    }

    private static let creation: (LeashPolicyMatcher, String) -> Bool = { $0.allowsOpen(path: $1, write: true) }
    private static let mutation: (LeashPolicyMatcher, String) -> Bool = { $0.allowsMutation(path: $1) }
    private static let readSource: (LeashPolicyMatcher, String) -> Bool = { $0.allowsLink(source: $1) }

    private func fileChecks(_ message: UnsafeMutablePointer<es_message_t>) -> [FileCheck] {
        let event = message.pointee.event
        switch message.pointee.event_type {
        case ES_EVENT_TYPE_AUTH_CREATE:
            let create = event.create
            if create.destination_type == ES_DESTINATION_TYPE_NEW_PATH {
                let newPath = create.destination.new_path
                let path = joinPath(resolvePath(for: newPath.dir), string(from: newPath.filename))
                let type = newPath.mode & S_IFMT
                // A new regular file is a new directory entry and an open for
                // writing, as on Linux (path_mknod decides the entry before the
                // inode exists, #204; file_open then sees the created file).
                // mkdir is a mutation; so is any other object: fifo, socket and
                // device (path_mknod on Linux too) and symlink (path_symlink,
                // #226). The new name is decided, not the link's target, which
                // a later open decides at the resolved path.
                if type == 0 || type == S_IFREG {
                    return [
                        FileCheck(operation: .create, path: path, check: Self.mutation),
                        FileCheck(operation: .create, path: path, check: Self.creation)
                    ]
                }
                if type == S_IFLNK {
                    return [FileCheck(operation: .symlink, path: path, check: Self.mutation)]
                }
                return [FileCheck(operation: .mkdir, path: path, check: Self.mutation)]
            }
            return [FileCheck(operation: .create, path: resolvePath(for: create.destination.existing_file), check: Self.creation)]

        case ES_EVENT_TYPE_AUTH_UNLINK:
            return [FileCheck(operation: .unlink, path: resolvePath(for: event.unlink.target), check: Self.mutation)]

        case ES_EVENT_TYPE_AUTH_RENAME:
            let rename = event.rename
            let destination: String?
            if rename.destination_type == ES_DESTINATION_TYPE_NEW_PATH {
                destination = joinPath(resolvePath(for: rename.destination.new_path.dir), string(from: rename.destination.new_path.filename))
            } else {
                destination = resolvePath(for: rename.destination.existing_file)
            }
            return [
                FileCheck(operation: .rename, path: resolvePath(for: rename.source), check: Self.mutation),
                FileCheck(operation: .rename, path: destination, check: Self.mutation)
            ]

        case ES_EVENT_TYPE_AUTH_LINK:
            let link = event.link
            return [
                FileCheck(operation: .link, path: resolvePath(for: link.source), check: Self.readSource),
                FileCheck(operation: .link, path: joinPath(resolvePath(for: link.target_dir), string(from: link.target_filename)), check: Self.mutation)
            ]

        case ES_EVENT_TYPE_AUTH_TRUNCATE:
            return [FileCheck(operation: .truncate, path: resolvePath(for: event.truncate.target), check: Self.creation)]

        case ES_EVENT_TYPE_AUTH_CLONE:
            let clone = event.clone
            return [
                FileCheck(operation: .clone, path: resolvePath(for: clone.source), check: Self.readSource),
                FileCheck(operation: .clone, path: joinPath(resolvePath(for: clone.target_dir), string(from: clone.target_name)), check: Self.creation)
            ]

        case ES_EVENT_TYPE_AUTH_COPYFILE:
            let copy = event.copyfile
            let target = copy.target_file.flatMap { resolvePath(for: $0) }
                ?? joinPath(resolvePath(for: copy.target_dir), string(from: copy.target_name))
            return [
                FileCheck(operation: .clone, path: resolvePath(for: copy.source), check: Self.readSource),
                FileCheck(operation: .clone, path: target, check: Self.creation)
            ]

        case ES_EVENT_TYPE_AUTH_EXCHANGEDATA:
            let exchange = event.exchangedata
            return [
                FileCheck(operation: .rename, path: resolvePath(for: exchange.file1), check: Self.creation),
                FileCheck(operation: .rename, path: resolvePath(for: exchange.file2), check: Self.creation)
            ]

        default:
            return []
        }
    }

    func processAuthFileSystemMessage(_ message: UnsafeMutablePointer<es_message_t>) {
        let process = message.pointee.process.pointee
        guard let leashInfo = leashedContext(for: process) else {
            respondAuth(message, action: .allow, cache: false)
            return
        }

        let checks = fileChecks(message)
        var decision: (action: LeashPolicyDecision.Action, reason: String?) = (checks.isEmpty ? .deny : .allow, nil)
        var decided = checks.first
        for c in checks {
            guard let path = c.path, path.hasPrefix("/") else {
                decision = (.deny, "unreadable path")
                decided = c
                break
            }
            let d = decide { c.check($0, path) }
            if d.action == .deny {
                decision = d
                decided = c
                break
            }
        }

        let path = decided?.path ?? ""
        let operation = decided?.operation ?? .create
        let event = fileEvent(process: process, leashInfo: leashInfo, path: path, operation: operation)
        os_log("AUTH_FS[leash=%{public}d]: %{public}@ → %{public}@ (%{public}@) → %{public}@",
               log: log, type: .default,
               leashInfo.leashPID ?? -1,
               event.processPath, path, operation.rawValue,
               decision.action == .allow ? "ALLOW" : "DENY")
        logEventAsync(event, decision: decision.action, reason: decision.reason)
        respondAuth(message, action: decision.action, cache: false)
    }

    func joinPath(_ dir: String?, _ name: String?) -> String? {
        guard let dir, let name, !name.isEmpty, !name.contains("/") else { return nil }
        return dir.hasSuffix("/") ? dir + name : dir + "/" + name
    }

    func fileEvent(process: es_process_t, leashInfo: TrackedLeashProcess, path: String, operation: LeashPolicyEvent.FileOperation) -> LeashPolicyEvent {
        let pid = audit_token_to_pid(process.audit_token)
        let tracked = trackedLeashProcesses[pid]
        return LeashPolicyEvent(
            id: UUID(),
            timestamp: Date(),
            kind: .fileAccess,
            processPath: tracked?.executablePath ?? processPath(pid: pid) ?? "",
            processArguments: tracked?.arguments ?? [],
            currentWorkingDirectory: tracked?.currentWorkingDirectory,
            filePath: path,
            fileOperation: operation,
            parentProcessPath: leashInfo.executablePath,
            ttyPath: tracked?.ttyPath,
            leashProcessPath: leashInfo.executablePath,
            leashPid: leashInfo.leashPID,
            leashArguments: leashInfo.arguments,
            leashTTYPath: leashInfo.ttyPath,
            pid: pid,
            parentPid: process.ppid
        )
    }

    func logEventAsync(_ event: LeashPolicyEvent, decision: LeashPolicyDecision.Action, reason: String? = nil) {
        guard let commService else { return }
        DispatchQueue.global(qos: .utility).async {
            commService.logEvent(event, decision: decision, reason: reason)
        }
    }

    func respondAuth(_ message: UnsafeMutablePointer<es_message_t>,
                     action: LeashPolicyDecision.Action,
                     cache: Bool) {
        guard let client else { return }
        let result: es_auth_result_t = action == .allow ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY
        let response = es_respond_auth_result(client, message, result, cache)
        if response != ES_RESPOND_RESULT_SUCCESS {
            os_log("es_respond_auth_result failed: result=%{public}d eventType=%{public}d",
                   log: log, type: .error,
                   response.rawValue,
                   message.pointee.event_type.rawValue)
        }
    }

    func respondOpen(_ message: UnsafeMutablePointer<es_message_t>,
                     action: LeashPolicyDecision.Action,
                     requestedFlags: Int32,
                     cache: Bool) {
        guard let client else { return }
        let flags: UInt32 = action == .allow ? UInt32.max : 0
        let response = es_respond_flags_result(client, message, flags, cache)
        if response != ES_RESPOND_RESULT_SUCCESS {
            os_log("es_respond_flags_result failed: result=%{public}d eventType=%{public}d",
                   log: log, type: .error,
                   response.rawValue,
                   message.pointee.event_type.rawValue)
        }
    }

    func enableAuthEvents() {
        // A new tracked leash process arrived — cancel any pending debounced teardown.
        pendingAuthDisable?.cancel()
        pendingAuthDisable = nil
        guard let client, !authEventsEnabled else { return }

        var events = Self.authEventTypes
        let result = es_subscribe(client, &events, UInt32(events.count))
        if result == ES_RETURN_SUCCESS {
            authEventsEnabled = true
            os_log("Subscribed to AUTH events", log: log, type: .default)
        } else {
            os_log("Failed to subscribe to AUTH events: %{public}d", log: log, type: .error, result.rawValue)
        }
    }

    func disableAuthEvents() {
        guard let client, authEventsEnabled else { return }

        var events = Self.authEventTypes
        if es_unsubscribe(client, &events, UInt32(events.count)) == ES_RETURN_SUCCESS {
            authEventsEnabled = false
            os_log("Unsubscribed from AUTH events", log: log, type: .default)
        } else {
            os_log("Failed to unsubscribe from AUTH events", log: log, type: .error)
        }
    }

    func resolvePath(for filePointer: UnsafeMutablePointer<es_file_t>?) -> String? {
        guard let filePointer else { return nil }
        if let existing = string(from: filePointer.pointee.path), !existing.isEmpty {
            return existing
        }
        return nil
    }

    func leashInfo(for process: es_process_t) -> TrackedLeashProcess? {
        if let direct = trackedLeashProcesses[process.ppid] {
            return direct
        }

        let originalParent = process.original_ppid
        if originalParent > 0, let tracked = trackedLeashProcesses[originalParent] {
            return tracked
        }

        return nil
    }

    func isLeashExecutable(_ process: es_process_t, executablePath path: String) -> Bool {
        if matchesEmbeddedLeashExecutable(path: path) {
            return true
        }

        if let signingID = string(from: process.signing_id), !signingID.isEmpty {
            guard signingID == leashSigningIdentifier else {
                return false
            }
            if let teamID = string(from: process.team_id), !teamID.isEmpty {
                return teamID == leashTeamIdentifier
            }
            return true
        }

        guard let lastComponent = path.split(separator: "/").last else { return false }
        return leashExecutableNames.contains(String(lastComponent))
    }

    func matchesEmbeddedLeashExecutable(path: String) -> Bool {
        let normalizedPath = (path as NSString).standardizingPath
        if normalizedPath == embeddedLeashExecutableSuffix {
            return true
        }
        return normalizedPath.hasSuffix(embeddedLeashExecutableSuffix)
    }

    func respondsToAllowedTerminal(_ parentPath: String) -> Bool {
        let name = parentPath.split(separator: "/").last.map(String.init) ?? parentPath
        return terminalExecutableHints.contains(where: { hint in
            name.caseInsensitiveCompare(hint) == .orderedSame || parentPath.localizedCaseInsensitiveContains("/\(hint).app/")
        })
    }

    func originatesFromInteractiveTerminal(_ process: es_process_t) -> Bool {
        if let ttyPointer = process.tty?.pointee.path, let tty = string(from: ttyPointer) {
            if tty.contains("/dev/ttys") || tty.contains("/dev/pts") || tty.contains("/dev/tty.") {
                return true
            }
        }

        if process.ppid > 1, let parentPath = processPath(pid: process.ppid), respondsToAllowedTerminal(parentPath) {
            return true
        }

        return false
    }

    func extractArguments(from message: UnsafeMutablePointer<es_message_t>) -> [String] {
        var execCopy = message.pointee.event.exec
        return withUnsafePointer(to: &execCopy) { pointer -> [String] in
            let count = Int(es_exec_arg_count(pointer))
            guard count > 0 else { return [] }
            var arguments: [String] = []
            arguments.reserveCapacity(count)
            for index in 0..<count {
                let argumentToken = es_exec_arg(pointer, UInt32(index))
                if let argument = string(from: argumentToken) {
                    arguments.append(argument)
                }
            }
            return arguments
        }
    }

    func ttyPath(for process: es_process_t) -> String? {
        guard let ttyPointer = process.tty?.pointee.path else { return nil }
        return string(from: ttyPointer)
    }

    func processPath(pid: pid_t) -> String? {
        guard pid > 0 else { return nil }
        var buffer = [CChar](repeating: 0, count: Int(PATH_MAX))
        let result = buffer.withUnsafeMutableBufferPointer { ptr -> Int32 in
            guard let base = ptr.baseAddress else { return -1 }
            return proc_pidpath(pid, base, UInt32(ptr.count))
        }
        guard result > 0 else { return nil }
        return String(cString: buffer)
    }

    func buildExecContext(message: UnsafeMutablePointer<es_message_t>,
                                  process: es_process_t,
                                  leashInfo: TrackedLeashProcess) -> (TrackedLeashProcess, LeashPolicyEvent)? {
        guard let executablePath = string(from: process.executable.pointee.path), !executablePath.isEmpty else {
            return nil
        }

        let pid = audit_token_to_pid(process.audit_token)
        let arguments = extractArguments(from: message)
        let execEvent = message.pointee.event.exec
        let cwd = Optional(execEvent.cwd).flatMap { string(from: $0.pointee.path) } ?? leashInfo.currentWorkingDirectory
        let tty = ttyPath(for: process)

        let trackedProcess = TrackedLeashProcess(
            pid: pid,
            executablePath: executablePath,
            arguments: arguments,
            ttyPath: tty,
            signingIdentifier: string(from: process.signing_id),
            teamIdentifier: string(from: process.team_id),
            currentWorkingDirectory: cwd,
            leashPID: leashInfo.leashPID,
            leashArguments: leashInfo.arguments,
            leashTTYPath: leashInfo.ttyPath,
            leashExecutablePath: leashInfo.executablePath
        )

        let event = LeashPolicyEvent(
            id: UUID(),
            timestamp: Date(),
            kind: .processExec,
            processPath: executablePath,
            processArguments: arguments,
            currentWorkingDirectory: cwd,
            filePath: nil,
            fileOperation: nil,
            parentProcessPath: leashInfo.executablePath,
            ttyPath: tty,
            leashProcessPath: leashInfo.executablePath,
            leashPid: leashInfo.leashPID,
            leashArguments: leashInfo.arguments,
            leashTTYPath: leashInfo.ttyPath,
            pid: pid,
            parentPid: process.ppid
        )

        return (trackedProcess, event)
    }

    func string(from token: es_string_token_t?) -> String? {
        guard let token else { return nil }
        return string(from: token)
    }

    func string(from token: es_string_token_t) -> String? {
        guard token.length > 0, let dataPtr = token.data else { return nil }
        let data = Data(bytes: UnsafeRawPointer(dataPtr), count: Int(token.length))
        return String(data: data, encoding: .utf8)
    }

    func notifyFullDiskAccessMissing(reason: String) {
        let userInfo: [String: String] = ["message": reason]
        let notification = LeashNotifications.fullDiskAccessMissing
        DistributedNotificationCenter.default().post(name: notification,
                                                     object: nil,
                                                     userInfo: userInfo)

        DaemonSync.shared.sendEvent(
            name: "es.full_disk_access.missing",
            details: ["reason": reason],
            severity: "warning",
            source: "leash.es"
        )
    }
}

extension es_process_t {
    var pid: pid_t {
        audit_token_to_pid(self.audit_token)
    }
}
