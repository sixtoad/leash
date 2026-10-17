import Foundation

/// The policy the macOS extensions enforce, as the daemon sends it in
/// `mac.policy.tables` (internal/macsync/tables.go).
///
/// These are the Linux kernel's tables, compiled from the Cedar policy by the
/// same code (transpiler.CompileKernel, then lsm.MacTablesFor), plus leash's
/// own protected paths and ports. `LeashPolicyMatcher` implements the kernel's
/// lookups over them and nothing else, so a decision here is the decision the
/// eBPF LSM would make for the same request, which the daemon's parity tests
/// prove equal to cedar.Authorize.
struct LeashPolicyTables: Decodable, Equatable {
    /// The decision procedure these tables need. Tables with any other value
    /// are refused: an extension must not guess at semantics it does not
    /// implement.
    static let supportedSemantics = "leash-kernel-v1"

    let version: String
    let semantics: String
    let file: FileTable
    let mutation: MutationTable
    let exec: ExecTable
    let network: NetworkTable
    let protected: ProtectedTable

    struct FileTable: Decodable, Equatable {
        let defaultAllow: Bool
        let exact: [FileEntry]
        let prefix: [FileEntry]

        enum CodingKeys: String, CodingKey {
            case defaultAllow = "default_allow"
            case exact, prefix
        }

        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            defaultAllow = try c.decode(Bool.self, forKey: .defaultAllow)
            exact = try c.decodeIfPresent([FileEntry].self, forKey: .exact) ?? []
            prefix = try c.decodeIfPresent([FileEntry].self, forKey: .prefix) ?? []
        }
    }

    struct FileEntry: Decodable, Equatable {
        /// "read" (an open without FWRITE) or "write".
        let op: String
        let path: String
        let allow: Bool
        let spec: UInt32
        let order: UInt32
    }

    struct MutationTable: Decodable, Equatable {
        let allow: [MutationPrefix]
        let deny: [MutationPrefix]
        let exactDeny: [String]

        enum CodingKeys: String, CodingKey {
            case allow, deny
            case exactDeny = "exact_deny"
        }

        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            allow = try c.decodeIfPresent([MutationPrefix].self, forKey: .allow) ?? []
            deny = try c.decodeIfPresent([MutationPrefix].self, forKey: .deny) ?? []
            exactDeny = try c.decodeIfPresent([String].self, forKey: .exactDeny) ?? []
        }
    }

    struct MutationPrefix: Decodable, Equatable {
        let path: String
        let spec: UInt32
    }

    struct ExecTable: Decodable, Equatable {
        let defaultAllow: Bool
        let rules: [ExecEntry]

        enum CodingKeys: String, CodingKey {
            case defaultAllow = "default_allow"
            case rules
        }

        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            defaultAllow = try c.decode(Bool.self, forKey: .defaultAllow)
            rules = try c.decodeIfPresent([ExecEntry].self, forKey: .rules) ?? []
        }
    }

    struct ExecEntry: Decodable, Equatable {
        let path: String
        let exact: Bool
        let allow: Bool
        let args: [String]

        enum CodingKeys: String, CodingKey {
            case path, exact, allow, args
        }

        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            path = try c.decode(String.self, forKey: .path)
            exact = try c.decodeIfPresent(Bool.self, forKey: .exact) ?? false
            allow = try c.decode(Bool.self, forKey: .allow)
            args = try c.decodeIfPresent([String].self, forKey: .args) ?? []
        }
    }

    struct NetworkTable: Decodable, Equatable {
        let defaultAllow: Bool
        let rules: [NetworkEntry]

        enum CodingKeys: String, CodingKey {
            case defaultAllow = "default_allow"
            case rules
        }

        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            defaultAllow = try c.decode(Bool.self, forKey: .defaultAllow)
            rules = try c.decodeIfPresent([NetworkEntry].self, forKey: .rules) ?? []
        }
    }

    struct NetworkEntry: Decodable, Equatable {
        /// 0 any address, 4 IPv4, 6 IPv6.
        let family: Int
        let ip: String
        /// 0 any port.
        let port: UInt16
        let allow: Bool

        enum CodingKeys: String, CodingKey {
            case family, ip, port, allow
        }

        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            family = try c.decode(Int.self, forKey: .family)
            ip = try c.decodeIfPresent(String.self, forKey: .ip) ?? ""
            port = try c.decode(UInt16.self, forKey: .port)
            allow = try c.decode(Bool.self, forKey: .allow)
        }
    }

    struct ProtectedTable: Decodable, Equatable {
        let paths: [String]
        let ports: [UInt16]

        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            paths = try c.decodeIfPresent([String].self, forKey: .paths) ?? []
            ports = try c.decodeIfPresent([UInt16].self, forKey: .ports) ?? []
        }

        enum CodingKeys: String, CodingKey {
            case paths, ports
        }
    }

    enum DecodeError: Error, CustomStringConvertible {
        case unsupportedSemantics(String)
        case invalidEntry(String)

        var description: String {
            switch self {
            case .unsupportedSemantics(let s):
                return "unsupported policy table semantics \"\(s)\" (this extension implements \(LeashPolicyTables.supportedSemantics))"
            case .invalidEntry(let s):
                return "invalid policy table entry: \(s)"
            }
        }
    }

    /// Decodes the payload of a `mac.policy.tables` message.
    static func decode(from payload: [String: Any]) throws -> LeashPolicyTables {
        let data = try JSONSerialization.data(withJSONObject: payload)
        return try decode(from: data)
    }

    static func decode(from data: Data) throws -> LeashPolicyTables {
        // Explicit CodingKeys everywhere: no key conversion strategy.
        let tables = try JSONDecoder().decode(LeashPolicyTables.self, from: data)
        guard tables.semantics == supportedSemantics else {
            throw DecodeError.unsupportedSemantics(tables.semantics)
        }
        return tables
    }
}
