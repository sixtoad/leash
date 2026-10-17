import Foundation
import os.log

extension DaemonSync {
    // MARK: - Public API

    /// Sends the complete tracked set, including an empty one: the daemon
    /// replaces its set with this, and a set that never empties would keep
    /// the network filter and the proxy enforcing on PIDs the OS has since
    /// reused for unrelated processes.
    func sendTrackedPIDs(_ pids: [PIDEntry]) {
        queue.async { [weak self] in
            guard let self else { return }
            self.ensureConnection()

            let entriesPayload: [[String: Any]] = pids.map { entry in
                var dict: [String: Any] = [
                    "pid": Int(entry.pid),
                    "leash_pid": Int(entry.leashPID),
                    "executable": entry.executable
                ]
                if let tty = entry.ttyPath { dict["tty_path"] = tty }
                if let cwd = entry.cwd { dict["cwd"] = cwd }
                if let description = entry.description { dict["description"] = description }
                return dict
            }

            self.sendEnvelope(
                type: "mac.pid.sync",
                payload: ["entries": entriesPayload],
                requestID: nil
            )
        }
    }

    func sendEvent(name: String, details: [String: String]? = nil, severity: String? = nil, source: String? = nil, ruleID: String? = nil) {
        queue.async { [weak self] in
            guard let self else { return }
            self.ensureConnection()

            let formatter = ISO8601DateFormatter()
            var payload: [String: Any] = [
                "time": formatter.string(from: Date()),
                "event": name
            ]
            if let details { payload["details"] = details }
            if let severity { payload["severity"] = severity }
            if let source { payload["source"] = source }
            if let ruleID { payload["rule_id"] = ruleID }

            self.sendEnvelope(type: "mac.event", payload: payload, requestID: nil)
        }
    }

    // MARK: - Policy Events & Decisions

    func sendPolicyEvent(_ event: LeashPolicyEvent, completion: ((Error?) -> Void)? = nil) {
        queue.async { [weak self] in
            guard let self else { return }
            self.ensureConnection()

            let payload: [String: Any] = [
                "id": event.id.uuidString,
                "timestamp": ISO8601DateFormatter().string(from: event.timestamp),
                "kind": event.kind.rawValue,
                "process_path": event.processPath,
                "process_arguments": event.processArguments,
                "current_working_directory": event.currentWorkingDirectory as Any,
                "file_path": event.filePath as Any,
                "file_operation": event.fileOperation?.rawValue as Any,
                "parent_process_path": event.parentProcessPath as Any,
                "tty_path": event.ttyPath as Any,
                "leash_process_path": event.leashProcessPath as Any,
                "leash_pid": event.leashPid as Any,
                "leash_arguments": event.leashArguments as Any,
                "leash_tty_path": event.leashTTYPath as Any,
                "pid": event.pid,
                "parent_pid": event.parentPid
            ]

            self.sendRequest(type: "mac.policy.event", payload: payload) { result in
                switch result {
                case .success:
                    completion?(nil)
                case .failure(let error):
                    completion?(error)
                }
            }
        }
    }

    // MARK: - Policy tables

    /// Asks the daemon for the policy tables the extensions must enforce
    /// (`mac.policy.tables.query`). The daemon also pushes them unsolicited
    /// on every hello and every policy change (`mac.policy.tables`).
    func queryPolicyTables(completion: @escaping (Result<[String: Any], Error>) -> Void) {
        queue.async { [weak self] in
            guard let self else { return }
            self.ensureConnection()
            self.sendRequest(type: "mac.policy.tables.query", payload: [:]) { result in
                switch result {
                case .success(let payload):
                    guard let tables = payload["tables"] as? [String: Any] else {
                        completion(.failure(NSError(
                            domain: LeashIdentifiers.namespaced("daemon-sync"),
                            code: -4,
                            userInfo: [NSLocalizedDescriptionKey: "daemon sent no policy tables"])))
                        return
                    }
                    completion(.success(tables))
                case .failure(let error):
                    completion(.failure(error))
                }
            }
        }
    }

    /// Reports that this component now enforces `version` (error == nil) or
    /// refused it. `leash --darwin exec` starts a workload only once the ES and
    /// NE extensions have applied the daemon's current version.
    func sendPolicyApplied(version: String, error: String? = nil) {
        queue.async { [weak self] in
            guard let self else { return }
            self.ensureConnection()
            var payload: [String: Any] = ["version": version]
            if let error { payload["error"] = error }
            self.sendEnvelope(type: "mac.policy.applied", payload: payload, requestID: nil)
        }
    }

    /// Ask the daemon which leash components currently hold a websocket
    /// connection (see LeashIdentifiers.Component). Used by the app to spot a
    /// system extension that is loaded but not talking to the daemon — the
    /// content filter in that state enforces nothing (#62).
    func queryConnectedComponents(timeout: TimeInterval = 10.0,
                                  completion: @escaping (Result<Set<String>, Error>) -> Void) {
        queue.async { [weak self] in
            guard let self else { return }
            self.ensureConnection()

            self.sendRequest(type: "mac.client.query", payload: [:], timeout: timeout) { result in
                switch result {
                case .success(let payload):
                    guard let components = payload["components"] as? [String] else {
                        // A daemon older than this message type answers with an
                        // "unsupported message type" ack. That is "can't tell",
                        // not "nothing is connected" — reporting an empty set
                        // here would make the app declare a healthy filter
                        // degraded and restart it for nothing.
                        completion(.failure(NSError(
                            domain: LeashIdentifiers.namespaced("daemon-sync"),
                            code: -3,
                            userInfo: [NSLocalizedDescriptionKey: "daemon does not report connected components"])))
                        return
                    }
                    completion(.success(Set(components)))
                case .failure(let error):
                    completion(.failure(error))
                }
            }
        }
    }

    // MARK: - Message Subscriptions

    func subscribe(to messageType: String, handler: @escaping MessageHandler) {
        queue.async { [weak self] in
            guard let self else { return }
            // Subscribing is a statement of intent to receive broadcasts, so it
            // must bring the connection up. The websocket was previously
            // established only by send paths: the transparent proxy provider
            // subscribes to mac.pid.sync and (with debug logging off) never
            // sends anything, so it never connected, never registered with the
            // daemon, and never received a single PID update — leaving it unable
            // to route tracked flows. Same failure shape as #62, permanent
            // rather than post-update.
            self.ensureConnection()
            if self.messageHandlers[messageType] == nil {
                self.messageHandlers[messageType] = []
            }
            self.messageHandlers[messageType]?.append(handler)
        }
    }

    func unsubscribe(from messageType: String) {
        queue.async { [weak self] in
            guard let self else { return }
            self.messageHandlers.removeValue(forKey: messageType)
        }
    }

    // MARK: - Connection Lifecycle

    func ensureConnection() {
        if let currentTask = task {
            switch currentTask.state {
            case .running, .suspended:
                return
            case .completed:
                task = nil
            case .canceling:
                return
            @unknown default:
                return
            }
        }
        os_log("Attempting websocket connection to %{public}@...", log: log, type: .info, endpointURL.absoluteString)
        connectAttempts += 1
        shimID = UUID().uuidString

        let url = endpointURL
        let task = session.webSocketTask(with: url)
        task.maximumMessageSize = 16 * 1024 * 1024 // allow up to 16MB payloads
        self.task = task
        isConnected = false
        task.resume()

        os_log("Connecting to leash daemon websocket at %{public}@", log: log, type: .info, url.absoluteString)
        listen()
        sendHello()
    }

    func listen() {
        guard let task else { return }

        task.receive { [weak self] result in
            guard let self else { return }
            switch result {
            case .failure(let error):
                if let urlError = error as? URLError, urlError.code == .cancelled {
                    os_log("Websocket receive cancelled", log: self.log, type: .debug)
                } else {
                    os_log("Websocket receive error: %{public}@", log: self.log, type: .error, error.localizedDescription)
                }
                self.queue.async {
                    self.isConnected = false
                    self.scheduleReconnect()
                }
            case .success(let message):
                self.queue.async {
                    // Bytes from the daemon: the connection is real. This is also
                    // where the reconnect backoff resets, so a socket that opens
                    // and immediately dies keeps backing off.
                    self.isConnected = true
                    self.connectAttempts = 0
                }
                switch message {
                case .string(let text):
                    os_log("Websocket message len=%{public}d", log: self.log, type: .debug, text.utf8.count)
                    self.queue.async {
                        self.handleIncomingMessages(text)
                    }
                case .data(let data):
                    os_log("Websocket binary message (%{public}d bytes)", log: self.log, type: .debug, data.count)
                    if let text = String(data: data, encoding: .utf8) {
                        self.queue.async {
                            self.handleIncomingMessages(text)
                        }
                    }
                @unknown default:
                    os_log("Websocket unknown message", log: self.log, type: .error)
                }
                self.listen()
            }
        }
    }

    /// Record that this process holds Full Disk Access, so every future
    /// `client.hello` says so.
    ///
    /// Deliberately only affects FUTURE hellos: the caller (LeashES's main)
    /// already emits `es.full_disk_access.ready` on the connection it is holding
    /// right now, which covers this daemon. What the capability adds is every
    /// connection AFTER this one — reconnects, and above all the reconnect that
    /// follows a daemon restart, where the startup event is long gone.
    ///
    /// Idempotent, and hopped onto `queue` because `capabilities` is read there
    /// by sendHello.
    func advertiseFullDiskAccess() {
        queue.async { [weak self] in
            guard let self else { return }
            guard !self.capabilities.contains(LeashIdentifiers.Capability.fullDiskAccess) else { return }
            self.capabilities.append(LeashIdentifiers.Capability.fullDiskAccess)
            os_log("Advertising Full Disk Access in future hellos", log: self.log, type: .info)
        }
    }

    func sendHello() {
        let helloPayload: [String: Any] = [
            "platform": "darwin",
            "component": component,
            "capabilities": capabilities,
            "version": Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "dev"
        ]
        sendEnvelope(type: "client.hello", payload: helloPayload, requestID: nil)
        // Deliberately NOT marking the connection live here. Sending the hello
        // proves nothing — with the daemon down, every reconnect attempt would
        // flip isConnected true for a moment, which both hides real outages from
        // anything watching the flag (the filter's fail-closed check) and resets
        // the reconnect backoff on failure. `listen()` sets it once bytes
        // actually arrive from the daemon, which is the real signal.
        os_log("Websocket hello sent (component=%{public}@ capabilities=%{public}@)",
               log: log, type: .info, component, capabilities.joined(separator: ","))
    }

    func scheduleReconnect() {
        reconnectWorkItem?.cancel()
        reconnectWorkItem = DispatchWorkItem { [weak self] in
            guard let self else { return }
            self.task?.cancel(with: .goingAway, reason: nil)
            self.task = nil
            self.ensureConnection()
        }
        let delay = min(pow(2.0, Double(connectAttempts)), 30.0)
        let delayString = String(format: "%.1f", delay)
        os_log("Scheduling websocket reconnect in %{public}@ seconds (attempt %{public}d)", log: log, type: .info, delayString, connectAttempts)
        queue.asyncAfter(deadline: .now() + delay, execute: reconnectWorkItem!)
    }

    func sendEnvelope(type: String, payload: [String: Any], requestID: String?) {
        var envelope: [String: Any] = [
            "type": type,
            "version": 1,
            "session_id": sessionID,
            "shim_id": shimID
        ]
        if let requestID {
            envelope["request_id"] = requestID
        }
        envelope["payload"] = payload

        guard JSONSerialization.isValidJSONObject(envelope) else {
            os_log("Failed to encode websocket payload (invalid JSON) type=%{public}@", log: log, type: .error, type)
            return
        }

        do {
            let data = try JSONSerialization.data(withJSONObject: envelope)
            guard let string = String(data: data, encoding: .utf8) else {
                os_log("Failed to encode websocket message as UTF8", log: log, type: .error)
                return
            }
            os_log("Sending websocket message type=%{public}@ size=%{public}d bytes requestID=%{public}@", log: log, type: .debug, type, string.utf8.count, requestID ?? "none")
            sendRaw(string)
        } catch {
            os_log("Failed to encode websocket payload: %{public}@", log: log, type: .error, error.localizedDescription)
        }
    }

    func sendRequest(type: String, payload: [String: Any], timeout: TimeInterval = 30.0, completion: @escaping (Result<[String: Any], Error>) -> Void) {
        let requestID = UUID().uuidString

        pendingRequests[requestID] = completion

        queue.asyncAfter(deadline: .now() + timeout) { [weak self] in
            guard let self else { return }
            if let handler = self.pendingRequests.removeValue(forKey: requestID) {
                handler(.failure(NSError(domain: LeashIdentifiers.namespaced("daemon-sync"), code: -1, userInfo: [NSLocalizedDescriptionKey: "Request timed out"])))
            }
        }

        guard JSONSerialization.isValidJSONObject(payload) else {
            completion(.failure(NSError(domain: LeashIdentifiers.namespaced("daemon-sync"), code: -2, userInfo: [NSLocalizedDescriptionKey: "Failed to encode payload"])))
            return
        }

        sendEnvelope(type: type, payload: payload, requestID: requestID)
    }

    func handleIncomingMessages(_ text: String) {
        let lines = text.components(separatedBy: .newlines)
        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty else { continue }
            handleIncomingMessage(trimmed)
        }
    }

    func handleIncomingMessage(_ text: String) {
        guard let data = text.data(using: .utf8) else {
            os_log("Failed to decode incoming message as UTF-8", log: log, type: .error)
            return
        }

        // Try to decode as envelope first.
        //
        // No .convertFromSnakeCase here: IncomingEnvelope already maps the
        // snake_case wire names in its CodingKeys, and the strategy is applied
        // to the JSON keys *before* they are matched against those keys — so
        // "request_id" arrived as "requestId", matched nothing, and every
        // response decoded with requestID == nil. Requests were therefore never
        // correlated with their responses and every sendRequest() sat until its
        // timeout. It went unnoticed because the daemon also pushes rules and
        // PIDs unsolicited on each hello, which is what actually kept the
        // extensions in sync.
        do {
            let decoder = JSONDecoder()
            let envelope = try decoder.decode(IncomingEnvelope.self, from: data)

            os_log("Received message type=%{public}@ requestID=%{public}@", log: log, type: .debug, envelope.type, envelope.requestID ?? "none")

            // Convert AnyCodable payload to [String: Any]
            let payload = envelope.payload.mapValues { $0.value }

            // Check if this is a response to a pending request
            if let requestID = envelope.requestID, let handler = pendingRequests.removeValue(forKey: requestID) {
                handler(.success(payload))
                return
            }

            // Otherwise, route to message handlers
            if let handlers = messageHandlers[envelope.type] {
                for handler in handlers {
                    handler(payload)
                }
            }
        } catch {
            // Silently ignore messages that aren't envelopes (like bulk LogEntry objects)
            // These are historical events sent on connection and don't need processing
            if data.count < 1000 {
                os_log("Received non-envelope message (likely historical event)", log: log, type: .debug)
            }
        }
    }

    func sendRaw(_ string: String) {
        guard let task else {
            os_log("No active websocket task, dropping message", log: log, type: .error)
            return
        }
        task.send(.string(string)) { [weak self] error in
            if let error {
                if let urlError = error as? URLError, urlError.code == .cancelled {
                    os_log("Websocket send cancelled", log: self?.log ?? .disabled, type: .debug)
                } else {
                    os_log("Websocket send failed: %{public}@", log: self?.log ?? .disabled, type: .error, error.localizedDescription)
                }
                self?.queue.async {
                    self?.isConnected = false
                    self?.scheduleReconnect()
                }
            } else {
                os_log("Websocket send succeeded", log: self?.log ?? .disabled, type: .debug)
            }
        }
    }
}
