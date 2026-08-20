import Foundation

enum LeashIdentifiers {
    static let bundle: String = {
        if let override = ProcessInfo.processInfo.environment["LEASH_BUNDLE_IDENTIFIER"], !override.isEmpty {
            return override
        }

        if let bundleIdentifier = Bundle.main.bundleIdentifier {
            for suffix in ["LeashES", "LeashNetworkFilter", "LeashProxy", "cli"] {
                let suffixWithSeparator = ".\(suffix)"
                if bundleIdentifier.hasSuffix(suffixWithSeparator) {
                    return String(bundleIdentifier.dropLast(suffixWithSeparator.count))
                }
            }
            return bundleIdentifier
        }

        return "com.strongdm.leash"
    }()

    static let teamIdentifier: String = {
        if let override = ProcessInfo.processInfo.environment["LEASH_TEAM_IDENTIFIER"], !override.isEmpty {
            return override
        }

        let bundle = Bundle.main
        if let prefix = bundle.object(forInfoDictionaryKey: "AppIdentifierPrefix") {
            let sanitize: (String) -> String = { value in
                value.trimmingCharacters(in: CharacterSet(charactersIn: "."))
            }

            if let string = prefix as? String {
                return sanitize(string)
            }

            if let array = prefix as? [String], let first = array.first {
                return sanitize(first)
            }
        }

        return "W5HSYBBJGA"
    }()

    static let endpointSecurityExtension = "\(bundle).LeashES"
    static let networkFilterExtension = "\(bundle).LeashNetworkFilter"
    static let transparentProxyExtension = "\(bundle).LeashProxy"
    static let cli = "\(bundle).cli"

    /// Component names reported to the daemon in `client.hello`. They match the
    /// `source` tags the extensions already put on events, so daemon logs read
    /// consistently. The daemon uses them to tell which of the three system
    /// extensions is actually connected — a loaded-but-disconnected content
    /// filter enforces nothing (#62).
    enum Component {
        static let endpointSecurity = "leash.es"
        static let networkFilter = "leash.netfilter"
        static let transparentProxy = "leash.proxy"
        static let app = "leash.app"
        static let cli = "leash.cli"
    }

    /// Capability tags reported alongside the component in `client.hello`.
    ///
    /// `fullDiskAccess` is the answer to a question macOS refuses to answer any
    /// other way: no API lets one process read another's TCC grant, and probing
    /// a TCC-gated path only tells you about the prober. LeashES knows, because
    /// `es_new_client` returns ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED without
    /// the grant — so it advertises it here once that call has succeeded.
    ///
    /// It lives in the hello rather than in a one-off event because the hello is
    /// re-sent on EVERY reconnect. The event LeashES emits at startup is sent
    /// once per process launch, so a daemon started after the extension — the
    /// normal case, since macOS launches extensions at boot — never saw it, and
    /// `leash doctor` could never confirm the grant. Carrying it in the hello
    /// makes the signal self-healing: it reappears within one reconnect of any
    /// daemon restart, and it disappears with the client if LeashES dies.
    enum Capability {
        static let fullDiskAccess = "full-disk-access"
    }

    /// Derived from the running bundle identifier rather than set by each entry
    /// point, so a new target can't silently ship an unlabelled hello.
    static let component: String = {
        guard let identifier = Bundle.main.bundleIdentifier else { return Component.app }
        if identifier.hasSuffix(".LeashES") { return Component.endpointSecurity }
        if identifier.hasSuffix(".LeashNetworkFilter") { return Component.networkFilter }
        if identifier.hasSuffix(".LeashProxy") { return Component.transparentProxy }
        if identifier.hasSuffix(".cli") { return Component.cli }
        return Component.app
    }()
    static let systemWideEnforcementConfigKey = "systemwide_enforcement"
    static let flowDelayEnabledConfigKey = "flow_delay_enabled"
    static let flowDelayMinConfigKey = "flow_delay_min_seconds"
    static let flowDelayMaxConfigKey = "flow_delay_max_seconds"

    static func namespaced(_ suffix: String) -> String {
        "\(bundle).\(suffix)"
    }
}
