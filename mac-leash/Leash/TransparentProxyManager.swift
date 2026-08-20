import Foundation
import NetworkExtension

/// Configures and enables the LeashProxy transparent proxy (NETransparentProxyManager),
/// which routes leash-tracked TCP flows through the local darwind MITM proxy.
/// Mirrors the NEFilterManager activation flow used for the content filter.
final class TransparentProxyManager {
    static let shared = TransparentProxyManager()
    private init() {}

    enum State {
        case notConfigured
        case configuredDisabled
        case configuredEnabled
    }

    // Persisted user intent. macOS drops the transparent-proxy NE config to disabled
    // when the LeashProxy sysext is replaced (a version bump / app update), and the
    // launch path only re-activates the sysext — not the config. We record whether the
    // user last enabled the proxy so reconcileOnLaunch() can restore it, without
    // auto-enabling a proxy the user never turned on.
    private let userIntentKey = "leash.proxy.userEnabled"
    private var userIntendsEnabled: Bool {
        get { UserDefaults.standard.bool(forKey: userIntentKey) }
        set { UserDefaults.standard.set(newValue, forKey: userIntentKey) }
    }

    /// Load the existing LeashProxy manager, or a fresh one if none is configured.
    private func loadManager() async throws -> NETransparentProxyManager {
        let managers = try await NETransparentProxyManager.loadAllFromPreferences()
        return managers.first { manager in
            (manager.protocolConfiguration as? NETunnelProviderProtocol)?
                .providerBundleIdentifier == LeashIdentifiers.transparentProxyExtension
        } ?? NETransparentProxyManager()
    }

    func activate() async throws {
        // Any explicit activation records that the user wants the proxy on, so a
        // later sysext replacement can restore it (reconcileOnLaunch).
        userIntendsEnabled = true

        let manager = try await loadManager()

        // Skip the save only if the provider is genuinely running. isEnabled alone is
        // unreliable — loadAllFromPreferences can return a stale isEnabled=true while
        // the provider is not actually running (e.g. after a sysext replacement), so we
        // also require the connection to be connected before short-circuiting.
        if manager.isEnabled, manager.connection.status == .connected,
           let existing = manager.protocolConfiguration as? NETunnelProviderProtocol,
           existing.providerBundleIdentifier == LeashIdentifiers.transparentProxyExtension {
            return
        }

        try await applyEnabledConfig(manager)
    }

    /// (Re)start the provider by forcing an off->on transition. Re-saving an already-
    /// (stale-)enabled config is a no-op the system ignores — it only (re)launches the
    /// provider on an actual isEnabled false->true edge. So if it currently reads
    /// enabled, disable+save first, then enable+save. This mirrors what toggling "Leash
    /// Proxy" off then on in System Settings does.
    private func forceRestart(_ manager: NETransparentProxyManager) async throws {
        if manager.isEnabled {
            manager.isEnabled = false
            try await manager.saveToPreferences()
            try await manager.loadFromPreferences()
        }
        try await applyEnabledConfig(manager)
    }

    /// Build the enabled LeashProxy config on `manager`, save it, and reload so the
    /// change takes effect. NE requires a reload after every save to sync the in-memory
    /// manager with what was persisted; without it isEnabled can fail to apply and the
    /// provider won't (re)start.
    private func applyEnabledConfig(_ manager: NETransparentProxyManager) async throws {
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = LeashIdentifiers.transparentProxyExtension
        // serverAddress is required by the API but unused for a transparent proxy;
        // the provider relays to 127.0.0.1:<proxyPort> itself.
        proto.serverAddress = "127.0.0.1"

        manager.protocolConfiguration = proto
        manager.localizedDescription = "Leash Proxy"
        manager.isEnabled = true

        try await manager.saveToPreferences()
        try await manager.loadFromPreferences()

        // Explicitly start the provider session. The system auto-starts it on a fresh
        // enable, but after a sysext replacement the session stays disconnected until
        // started — save alone doesn't launch the provider. Best-effort: throws e.g. if
        // already connected, which is fine.
        do {
            try manager.connection.startVPNTunnel()
        } catch {
            DaemonSync.shared.sendEvent(name: "proxy.reconcile",
                                        details: ["start_error": "\(error)"],
                                        severity: "error", source: "leash.app")
        }
    }

    func deactivate() async throws {
        let managers = try await NETransparentProxyManager.loadAllFromPreferences()
        guard let manager = managers.first(where: {
            ($0.protocolConfiguration as? NETunnelProviderProtocol)?
                .providerBundleIdentifier == LeashIdentifiers.transparentProxyExtension
        }) else {
            return
        }
        // Only save when actually changing state (saving in a loop / when already
        // disabled is redundant and can disturb NE preferences serialization).
        if manager.isEnabled {
            manager.isEnabled = false
            try await manager.saveToPreferences()
            try await manager.loadFromPreferences() // reload so the disable takes effect
        }
        // The user turned the proxy off; don't resurrect it on the next launch.
        userIntendsEnabled = false
    }

    /// How long to let an in-flight sysext replacement land before reading the config,
    /// and how long to give the provider to reach the daemon afterwards. Same values
    /// the content filter settled on (NetworkFilterManager) — a replacement is not
    /// instantaneous, and reading either state too early is what made the previous
    /// version of this method a no-op on the one launch that mattered.
    private var settleDelay: Duration { .seconds(5) }
    private var connectDelay: Duration { .seconds(12) }

    /// Restore the transparent proxy on app launch if the user previously enabled it.
    /// macOS disables the NE config when the LeashProxy sysext is replaced (version
    /// bump / update); the launch path re-activates the sysext but not the config, so
    /// without this the user must re-enable "Leash Proxy" in System Settings after every
    /// update. Acts only on a recorded prior enable, and no-ops when the provider is
    /// genuinely running (so it won't trigger a redundant authorization prompt).
    ///
    /// `extensionReplaced` must be read from the controller BEFORE
    /// `ensureExtensionIsActive()` clears it — it is what makes this correct on the only
    /// launch where it matters. `ensureExtensionIsActive()` requests the replacement
    /// asynchronously, so without the settle delay below this method read the
    /// PRE-replacement config: the outgoing provider was still enabled and connected, we
    /// took the early return, and the replacement then landed and dropped the config
    /// with no second reconcile to catch it. That is #58's actual remaining failure — the proxy
    /// stayed dead until the user quit and relaunched the app.
    ///
    /// Note: it cannot distinguish a config disabled by a sysext replacement from one
    /// the user disabled directly in System Settings (both read as configuredDisabled),
    /// so a Settings-side disable is overridden on next launch. Use the app's own
    /// disable control (deactivate) to turn the proxy off persistently.
    func reconcileOnLaunch(extensionReplaced: Bool) async {
        guard userIntendsEnabled else {
            report(["intent": "no"])
            return
        }

        // Let a replacement requested moments ago actually land before we look.
        try? await Task.sleep(for: settleDelay)

        do {
            let manager = try await loadManager()
            let enabled = manager.isEnabled
            let status = manager.connection.status
            report(["intent": "yes",
                    "enabled": enabled ? "yes" : "no",
                    "status": "\(status.rawValue)",
                    "extension_replaced": extensionReplaced ? "yes" : "no"])

            // Truly running only if enabled AND the provider session is connected:
            // isEnabled alone reads stale-true after a replacement while the provider
            // is dead. Even that is not enough on a replacement launch, though —
            // the config can look healthy because we are seeing the OUTGOING provider,
            // so a version change always forces the restart.
            if enabled, status == .connected, !extensionReplaced { return }
            try await forceRestart(manager)
            report(["result": extensionReplaced ? "restarted_after_version_change" : "restarted"])
        } catch {
            report(["result": "error", "error": "\(error)"], severity: "error")
            return
        }

        await verifyProviderConnected()
    }

    /// Confirm the provider reached the daemon, and repair once if it did not.
    ///
    /// A restarted config is not a working proxy: `systemextensionsctl` reports
    /// `[activated enabled]` for an extension whose provider process does not exist,
    /// and a provider that never connects holds no tracked PIDs, so it gates nothing.
    /// The daemon's client registry is the only place that distinction is visible.
    private func verifyProviderConnected() async {
        try? await Task.sleep(for: connectDelay)

        guard let components = await connectedComponents() else {
            // No usable answer: the daemon isn't running, or predates mac.client.query.
            // Restarting on a guess would be worse than reporting what we know.
            report(["health": "unknown"])
            return
        }

        if components.contains(LeashIdentifiers.Component.transparentProxy) {
            report(["health": "connected"])
            return
        }

        report(["health": "degraded", "components": components.sorted().joined(separator: ",")],
               severity: "error")

        do {
            let manager = try await loadManager()
            try await forceRestart(manager)
        } catch {
            report(["health": "repair_failed", "error": "\(error)"], severity: "error")
            return
        }

        try? await Task.sleep(for: connectDelay)
        let after = await connectedComponents()
        let recovered = after?.contains(LeashIdentifiers.Component.transparentProxy) ?? false
        report(["health": recovered ? "repaired" : "still_degraded"],
               severity: recovered ? "info" : "error")
    }

    private func connectedComponents() async -> Set<String>? {
        await withCheckedContinuation { continuation in
            DaemonSync.shared.queryConnectedComponents { result in
                switch result {
                case .success(let components):
                    continuation.resume(returning: components)
                case .failure:
                    continuation.resume(returning: nil)
                }
            }
        }
    }

    /// Report to the daemon log — the app's os_log doesn't surface in the dev VM.
    private func report(_ details: [String: String], severity: String = "info") {
        DaemonSync.shared.sendEvent(name: "proxy.reconcile",
                                    details: details,
                                    severity: severity,
                                    source: LeashIdentifiers.Component.app)
    }

    func currentState() async -> State {
        do {
            let managers = try await NETransparentProxyManager.loadAllFromPreferences()
            guard let manager = managers.first(where: {
                ($0.protocolConfiguration as? NETunnelProviderProtocol)?
                    .providerBundleIdentifier == LeashIdentifiers.transparentProxyExtension
            }) else {
                return .notConfigured
            }
            return manager.isEnabled ? .configuredEnabled : .configuredDisabled
        } catch {
            return .notConfigured
        }
    }
}
