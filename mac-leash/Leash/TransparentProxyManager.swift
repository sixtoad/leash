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

        // Skip the save if already configured + enabled — an unconditional
        // saveToPreferences can trigger a redundant system authorization prompt.
        if manager.isEnabled,
           let existing = manager.protocolConfiguration as? NETunnelProviderProtocol,
           existing.providerBundleIdentifier == LeashIdentifiers.transparentProxyExtension {
            return
        }

        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = LeashIdentifiers.transparentProxyExtension
        // serverAddress is required by the API but unused for a transparent proxy;
        // the provider relays to 127.0.0.1:<proxyPort> itself.
        proto.serverAddress = "127.0.0.1"

        manager.protocolConfiguration = proto
        manager.localizedDescription = "Leash Proxy"
        manager.isEnabled = true

        try await manager.saveToPreferences()
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
        }
        // The user turned the proxy off; don't resurrect it on the next launch.
        userIntendsEnabled = false
    }

    /// Restore the transparent proxy on app launch if the user previously enabled it.
    /// macOS disables the NE config when the LeashProxy sysext is replaced (version
    /// bump / update); the launch path re-activates the sysext but not the config, so
    /// without this the user must re-enable "Leash Proxy" in System Settings after every
    /// update. Acts only on a recorded prior enable, and no-ops when already enabled
    /// (so it won't trigger a redundant authorization prompt in the common case).
    ///
    /// Note: it cannot distinguish a config disabled by a sysext replacement from one
    /// the user disabled directly in System Settings (both read as configuredDisabled),
    /// so a Settings-side disable is overridden on next launch. Use the app's own
    /// disable control (deactivate) to turn the proxy off persistently.
    func reconcileOnLaunch() async {
        guard userIntendsEnabled else { return }
        switch await currentState() {
        case .configuredEnabled:
            return
        case .configuredDisabled, .notConfigured:
            try? await activate()
        }
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
