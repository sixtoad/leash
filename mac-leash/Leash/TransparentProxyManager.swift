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

    /// Load the existing LeashProxy manager, or a fresh one if none is configured.
    private func loadManager() async throws -> NETransparentProxyManager {
        let managers = try await NETransparentProxyManager.loadAllFromPreferences()
        return managers.first { manager in
            (manager.protocolConfiguration as? NETunnelProviderProtocol)?
                .providerBundleIdentifier == LeashIdentifiers.transparentProxyExtension
        } ?? NETransparentProxyManager()
    }

    func activate() async throws {
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
