import Foundation
import Darwin

/// The kernel's lookups over `LeashPolicyTables`, for the Endpoint Security
/// and Network Extension providers.
///
/// Each method is the Swift form of one eBPF lookup (internal/lsm), and of
/// its Go model in internal/macsync/matcher_model_test.go, which the parity
/// tests compare with cedar.Authorize:
///
/// - `allowsOpen` — check_open_indexed_policy: longest prefix entry and exact
///   entry for the open mode, specificity then order between them, else the
///   default;
/// - `allowsMutation` — check_mutation_policy: an exact deny denies, else the
///   longest allow prefix must be strictly more specific than the longest deny
///   prefix;
/// - `allowsExec` — check_exec_policy: first rule (precedence order) whose path
///   is a prefix of the executable (an exact rule: equal), else the default;
/// - `allowsConnect` — check_connect_policy: first matching rule (every deny
///   first), IPv4-mapped IPv6 decided as IPv4, else the default.
///
/// Paths are compared as UTF-8 bytes, as the kernel compares them (Swift's
/// String comparison would treat canonically equivalent spellings as equal).
/// Before any lookup, leash's protected paths and ports are denied: the
/// workload runs on the host as the same user, and on Linux it could not see
/// them at all.
final class LeashPolicyMatcher {
    let tables: LeashPolicyTables
    var version: String { tables.version }

    private struct FileKey: Hashable {
        let write: Bool
        let path: [UInt8]
    }

    private struct FileValue {
        let allow: Bool
        let spec: UInt32
        let order: UInt32
    }

    private struct Prefix {
        let path: [UInt8]
        let value: FileValue
    }

    private struct MutationPrefix {
        let path: [UInt8]
        let spec: UInt32
    }

    private struct ExecRule {
        let path: [UInt8]
        let exact: Bool
        let allow: Bool
        let args: [String]
    }

    private struct NetworkRule {
        /// 0 any address, 4 IPv4, 6 IPv6.
        let family: Int
        let address: [UInt8]
        let port: UInt16
        let allow: Bool
    }

    private let fileExact: [FileKey: FileValue]
    private let readPrefixes: [Prefix]
    private let writePrefixes: [Prefix]
    private let mutationAllow: [MutationPrefix]
    private let mutationDeny: [MutationPrefix]
    private let mutationExactDeny: Set<[UInt8]>
    private let execRules: [ExecRule]
    private let networkRules: [NetworkRule]
    private let protectedPaths: [[UInt8]]
    private let protectedPorts: Set<UInt16>

    init(tables: LeashPolicyTables) throws {
        self.tables = tables

        func write(_ op: String) throws -> Bool {
            switch op {
            case "read": return false
            case "write": return true
            default: throw LeashPolicyTables.DecodeError.invalidEntry("file op \"\(op)\"")
            }
        }

        var exact: [FileKey: FileValue] = [:]
        for e in tables.file.exact {
            exact[FileKey(write: try write(e.op), path: Array(e.path.utf8))] = FileValue(allow: e.allow, spec: e.spec, order: e.order)
        }
        fileExact = exact
        var read: [Prefix] = []
        var writes: [Prefix] = []
        for e in tables.file.prefix {
            let p = Prefix(path: Array(e.path.utf8), value: FileValue(allow: e.allow, spec: e.spec, order: e.order))
            if try write(e.op) {
                writes.append(p)
            } else {
                read.append(p)
            }
        }
        readPrefixes = read
        writePrefixes = writes

        mutationAllow = tables.mutation.allow.map { MutationPrefix(path: Array($0.path.utf8), spec: $0.spec) }
        mutationDeny = tables.mutation.deny.map { MutationPrefix(path: Array($0.path.utf8), spec: $0.spec) }
        mutationExactDeny = Set(tables.mutation.exactDeny.map { Array($0.utf8) })

        execRules = tables.exec.rules.map { ExecRule(path: Array($0.path.utf8), exact: $0.exact, allow: $0.allow, args: $0.args) }

        networkRules = try tables.network.rules.map { r in
            switch r.family {
            case 0:
                return NetworkRule(family: 0, address: [], port: r.port, allow: r.allow)
            case 4, 6:
                guard let parsed = LeashPolicyMatcher.parseAddress(r.ip), parsed.family == r.family else {
                    throw LeashPolicyTables.DecodeError.invalidEntry("network address \"\(r.ip)\" for family \(r.family)")
                }
                return NetworkRule(family: r.family, address: parsed.bytes, port: r.port, allow: r.allow)
            default:
                throw LeashPolicyTables.DecodeError.invalidEntry("network family \(r.family)")
            }
        }

        protectedPaths = tables.protected.paths.map { Array($0.utf8) }
        protectedPorts = Set(tables.protected.ports)
    }

    // MARK: - Paths

    private static let firmlinks: [[UInt8]] = ["/private/etc", "/private/tmp", "/private/var"].map { Array($0.utf8) }
    private static let privatePrefixLength = "/private".utf8.count
    private static let slash = UInt8(ascii: "/")

    /// Maps the /private form Endpoint Security reports for /etc, /tmp and
    /// /var back to the short form policies name ("/private/tmp/x" ->
    /// "/tmp/x"). The daemon refuses any policy path this would hide.
    static func canonicalPath(_ path: [UInt8]) -> [UInt8] {
        for long in firmlinks where hasPrefix(path, long) {
            if path.count == long.count || path[long.count] == slash {
                return Array(path[privatePrefixLength...])
            }
        }
        return path
    }

    static func canonicalPath(_ path: String) -> String {
        String(decoding: canonicalPath(Array(path.utf8)), as: UTF8.self)
    }

    private static func hasPrefix(_ path: [UInt8], _ prefix: [UInt8]) -> Bool {
        guard prefix.count <= path.count else { return false }
        for i in 0..<prefix.count where path[i] != prefix[i] {
            return false
        }
        return true
    }

    private func isProtected(_ path: [UInt8]) -> Bool {
        for p in protectedPaths {
            if path == p {
                return true
            }
            if path.count > p.count && path[p.count] == Self.slash && Self.hasPrefix(path, p) {
                return true
            }
        }
        return false
    }

    // MARK: - Decisions

    /// File open. `write` is true for any open that requests FWRITE.
    func allowsOpen(path rawPath: String, write: Bool) -> Bool {
        let path = Self.canonicalPath(Array(rawPath.utf8))
        if isProtected(path) {
            return false
        }
        var prefix: Prefix?
        for p in (write ? writePrefixes : readPrefixes) where Self.hasPrefix(path, p.path) {
            if prefix == nil || p.path.count > prefix!.path.count {
                prefix = p
            }
        }
        let exact = fileExact[FileKey(write: write, path: path)]
        switch (exact, prefix) {
        case let (e?, nil):
            return e.allow
        case let (e?, p?):
            if e.spec > p.value.spec { return e.allow }
            if p.value.spec > e.spec { return p.value.allow }
            return e.order <= p.value.order ? e.allow : p.value.allow
        case let (nil, p?):
            return p.value.allow
        case (nil, nil):
            return tables.file.defaultAllow
        }
    }

    /// mkdir, unlink, rmdir, either side of a rename, a hard link's new name.
    func allowsMutation(path rawPath: String) -> Bool {
        let path = Self.canonicalPath(Array(rawPath.utf8))
        if isProtected(path) || mutationExactDeny.contains(path) {
            return false
        }
        func longest(_ prefixes: [MutationPrefix]) -> UInt32? {
            var best: MutationPrefix?
            for p in prefixes where Self.hasPrefix(path, p.path) {
                if best == nil || p.path.count > best!.path.count {
                    best = p
                }
            }
            return best?.spec
        }
        guard let allow = longest(mutationAllow) else {
            return false
        }
        return allow > (longest(mutationDeny) ?? 0)
    }

    /// The hard-link guard: the source must be readable.
    func allowsLink(source: String) -> Bool {
        allowsOpen(path: source, write: false)
    }

    func allowsExec(path rawPath: String, arguments: [String]) -> Bool {
        let path = Self.canonicalPath(Array(rawPath.utf8))
        if isProtected(path) {
            return false
        }
        for rule in execRules {
            let matches = rule.exact ? path == rule.path : Self.hasPrefix(path, rule.path)
            guard matches else { continue }
            if rule.args.isEmpty {
                return rule.allow
            }
            // A deny rule with arguments denies only on an argument match and
            // otherwise falls through (allow rules with arguments are never sent).
            if rule.args.contains(where: { arguments.contains($0) }) {
                return false
            }
        }
        return tables.exec.defaultAllow
    }

    /// A connection to `ip` (an IPv4 or IPv6 literal) on `port`. Anything that
    /// is not an address literal is denied: the kernel decides by address.
    func allowsConnect(ip: String, port: UInt16) -> Bool {
        guard let dest = Self.parseAddress(ip) else {
            return false
        }
        if protectedPorts.contains(port) && Self.isLoopbackOrUnspecified(dest) {
            return false
        }
        for rule in networkRules {
            if rule.family != 0 && (rule.family != dest.family || rule.address != dest.bytes) {
                continue
            }
            if rule.port != 0 && rule.port != port {
                continue
            }
            return rule.allow
        }
        return tables.network.defaultAllow
    }

    /// A connection whose destination address is unknown (the flow names a
    /// host, not an address): allowed only if every address would be allowed
    /// on `port`, so it is never looser than the address decision. Any rule
    /// that could deny some address on this port denies; an allow for one
    /// address proves nothing about the others.
    func allowsConnectToAnyAddress(port: UInt16) -> Bool {
        if protectedPorts.contains(port) {
            return false // the name could be localhost
        }
        for rule in networkRules where rule.port == 0 || rule.port == port {
            if rule.family == 0 {
                return rule.allow
            }
            if !rule.allow {
                return false
            }
        }
        return tables.network.defaultAllow
    }

    // MARK: - Addresses

    /// Parses an address literal; an IPv4-mapped IPv6 address is IPv4, as the
    /// kernel's read_inet_dest classifies it. A zone suffix ("fe80::1%en0") is
    /// ignored for matching.
    static func parseAddress(_ text: String) -> (family: Int, bytes: [UInt8])? {
        var literal = text.trimmingCharacters(in: .whitespaces)
        if literal.hasPrefix("[") && literal.hasSuffix("]") {
            literal = String(literal.dropFirst().dropLast())
        }
        if let zone = literal.firstIndex(of: "%") {
            literal = String(literal[..<zone])
        }
        var v4 = in_addr()
        if inet_pton(AF_INET, literal, &v4) == 1 {
            return (4, withUnsafeBytes(of: &v4) { Array($0) })
        }
        var v6 = in6_addr()
        if inet_pton(AF_INET6, literal, &v6) == 1 {
            let bytes = withUnsafeBytes(of: &v6) { Array($0) }
            if bytes[0..<10].allSatisfy({ $0 == 0 }) && bytes[10] == 0xff && bytes[11] == 0xff {
                return (4, Array(bytes[12..<16]))
            }
            return (6, bytes)
        }
        return nil
    }

    private static func isLoopbackOrUnspecified(_ dest: (family: Int, bytes: [UInt8])) -> Bool {
        if dest.family == 4 {
            return dest.bytes[0] == 127 || dest.bytes.allSatisfy { $0 == 0 }
        }
        let zeros = dest.bytes[0..<15].allSatisfy { $0 == 0 }
        return zeros && (dest.bytes[15] == 1 || dest.bytes[15] == 0)
    }
}
