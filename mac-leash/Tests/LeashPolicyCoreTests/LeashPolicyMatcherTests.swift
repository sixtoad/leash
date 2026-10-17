import XCTest
@testable import LeashPolicyCore

/// Replays the daemon's parity vectors (internal/macsync parity_test.go): for
/// random strict Cedar policies, the tables the daemon would send and the
/// decisions cedar.Authorize makes. The real Swift matcher must reproduce
/// every one of them.
final class LeashPolicyMatcherTests: XCTestCase {
    private struct Probe: Decodable {
        let kind: String
        let path: String?
        let ip: String?
        let port: UInt16?
        let allow: Bool
    }

    private struct Vector: Decodable {
        let policy: String
        let tables: LeashPolicyTables
        let probes: [Probe]
    }

    private func loadVectors() throws -> [Vector] {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "parity-vectors", withExtension: "json"))
        return try JSONDecoder().decode([Vector].self, from: Data(contentsOf: url))
    }

    func testParityVectorsMatchCedar() throws {
        let vectors = try loadVectors()
        XCTAssertGreaterThan(vectors.count, 100)
        var decisions = 0
        for vector in vectors {
            let matcher = try LeashPolicyMatcher(tables: vector.tables)
            for probe in vector.probes {
                let got: Bool
                switch probe.kind {
                case "open_read": got = matcher.allowsOpen(path: probe.path!, write: false)
                case "open_write": got = matcher.allowsOpen(path: probe.path!, write: true)
                case "mutation": got = matcher.allowsMutation(path: probe.path!)
                case "link": got = matcher.allowsLink(source: probe.path!)
                case "exec": got = matcher.allowsExec(path: probe.path!, arguments: [])
                case "connect": got = matcher.allowsConnect(ip: probe.ip!, port: probe.port!)
                case "connect_any": got = matcher.allowsConnectToAnyAddress(port: probe.port!)
                default:
                    XCTFail("unknown probe kind \(probe.kind)")
                    continue
                }
                decisions += 1
                if got != probe.allow {
                    XCTFail("\(probe.kind) \(probe.path ?? probe.ip ?? "") port=\(probe.port ?? 0): swift=\(got) cedar=\(probe.allow)\npolicy:\n\(vector.policy)")
                    return
                }
            }
        }
        XCTAssertGreaterThan(decisions, 4000)
    }

    // MARK: - Key cases, written out

    private func tables(_ json: String) throws -> LeashPolicyMatcher {
        try LeashPolicyMatcher(tables: LeashPolicyTables.decode(from: Data(json.utf8)))
    }

    private let empty = """
    "mutation": {"allow": [], "deny": [], "exact_deny": []},
    "exec": {"default_allow": false, "rules": []},
    "network": {"default_allow": false, "rules": []},
    "protected": {"paths": [], "ports": []}
    """

    /// permit everything under /, forbid writes under /etc/: a read of
    /// /etc/hosts is allowed (the old matcher denied it: it ignored the mode).
    func testOpenModeIsPartOfTheKey() throws {
        let m = try tables("""
        {"version": "v", "semantics": "leash-kernel-v1",
         "file": {"default_allow": true,
                  "exact": [],
                  "prefix": [{"op": "read", "path": "/", "allow": true, "spec": 1, "order": 2},
                             {"op": "write", "path": "/", "allow": true, "spec": 1, "order": 3},
                             {"op": "write", "path": "/etc/", "allow": false, "spec": 5, "order": 0}]},
         \(empty)}
        """)
        XCTAssertTrue(m.allowsOpen(path: "/etc/hosts", write: false))
        XCTAssertFalse(m.allowsOpen(path: "/etc/hosts", write: true))
        XCTAssertFalse(m.allowsOpen(path: "/private/etc/hosts", write: true), "the /private form is the same file")
        XCTAssertTrue(m.allowsOpen(path: "/etcetera", write: true), "a directory prefix ends at its slash")
    }

    /// A permit nested under a forbid wins by length (the old matcher put
    /// every file rule before every directory rule and every deny first).
    func testLongestPrefixWins() throws {
        let m = try tables("""
        {"version": "v", "semantics": "leash-kernel-v1",
         "file": {"default_allow": false, "exact": [],
                  "prefix": [{"op": "read", "path": "/", "allow": true, "spec": 1, "order": 3},
                             {"op": "read", "path": "/srv/", "allow": false, "spec": 5, "order": 1},
                             {"op": "read", "path": "/srv/ok/", "allow": true, "spec": 8, "order": 0}]},
         \(empty)}
        """)
        XCTAssertTrue(m.allowsOpen(path: "/x", write: false))
        XCTAssertFalse(m.allowsOpen(path: "/srv/x", write: false))
        XCTAssertTrue(m.allowsOpen(path: "/srv/ok/x", write: false))
        XCTAssertFalse(m.allowsOpen(path: "/srv/x", write: true), "no write entry: default deny")
    }

    func testExactEntryBeatsPrefixes() throws {
        let m = try tables("""
        {"version": "v", "semantics": "leash-kernel-v1",
         "file": {"default_allow": false,
                  "exact": [{"op": "read", "path": "/etc/shadow", "allow": false, "spec": 12, "order": 0}],
                  "prefix": [{"op": "read", "path": "/", "allow": true, "spec": 1, "order": 1}]},
         \(empty)}
        """)
        XCTAssertFalse(m.allowsOpen(path: "/etc/shadow", write: false))
        XCTAssertTrue(m.allowsOpen(path: "/etc/shadowx", write: false))
        XCTAssertTrue(m.allowsOpen(path: "/etc/shadow/", write: false))
    }

    func testPathsCompareAsBytes() throws {
        // "/caf" + "é" precomposed is a different byte string from "e" + U+0301.
        let m = try tables("""
        {"version": "v", "semantics": "leash-kernel-v1",
         "file": {"default_allow": false, "exact": [],
                  "prefix": [{"op": "read", "path": "/caf\\u00e9/", "allow": true, "spec": 7, "order": 0}]},
         \(empty)}
        """)
        XCTAssertTrue(m.allowsOpen(path: "/caf\u{e9}/x", write: false))
        XCTAssertFalse(m.allowsOpen(path: "/cafe\u{301}/x", write: false))
    }

    func testMutationTable() throws {
        let m = try tables("""
        {"version": "v", "semantics": "leash-kernel-v1",
         "file": {"default_allow": false, "exact": [], "prefix": []},
         "mutation": {"allow": [{"path": "/", "spec": 1}, {"path": "/srv/ok/", "spec": 8}],
                      "deny": [{"path": "/srv/", "spec": 5}],
                      "exact_deny": ["/work"]},
         "exec": {"default_allow": false, "rules": []},
         "network": {"default_allow": false, "rules": []},
         "protected": {"paths": [], "ports": []}}
        """)
        XCTAssertTrue(m.allowsMutation(path: "/x"))
        XCTAssertFalse(m.allowsMutation(path: "/srv/x"))
        XCTAssertTrue(m.allowsMutation(path: "/srv/ok/x"))
        XCTAssertFalse(m.allowsMutation(path: "/work"))
        XCTAssertTrue(m.allowsMutation(path: "/work/x"))
    }

    func testExecRulesInPrecedenceOrder() throws {
        let m = try tables("""
        {"version": "v", "semantics": "leash-kernel-v1",
         "file": {"default_allow": false, "exact": [], "prefix": []},
         "mutation": {"allow": [], "deny": [], "exact_deny": []},
         "exec": {"default_allow": false, "rules": [
             {"path": "/usr/bin/git", "allow": false, "args": ["push"]},
             {"path": "/usr/bin/rm", "exact": true, "allow": false},
             {"path": "/usr/bin/", "allow": true}]},
         "network": {"default_allow": false, "rules": []},
         "protected": {"paths": [], "ports": []}}
        """)
        XCTAssertFalse(m.allowsExec(path: "/usr/bin/rm", arguments: []))
        XCTAssertTrue(m.allowsExec(path: "/usr/bin/rmdir", arguments: []))
        XCTAssertFalse(m.allowsExec(path: "/usr/bin/git", arguments: ["git", "push"]))
        XCTAssertTrue(m.allowsExec(path: "/usr/bin/git", arguments: ["git", "status"]))
        XCTAssertFalse(m.allowsExec(path: "/bin/sh", arguments: []))
    }

    func testNetworkRulesPortsAndIPv6() throws {
        let m = try tables("""
        {"version": "v", "semantics": "leash-kernel-v1",
         "file": {"default_allow": false, "exact": [], "prefix": []},
         "mutation": {"allow": [], "deny": [], "exact_deny": []},
         "exec": {"default_allow": false, "rules": []},
         "network": {"default_allow": false, "rules": [
             {"family": 4, "ip": "10.0.0.1", "port": 22, "allow": false},
             {"family": 0, "port": 25, "allow": false},
             {"family": 4, "ip": "10.0.0.1", "port": 0, "allow": true},
             {"family": 6, "ip": "2001:db8::1", "port": 443, "allow": true}]},
         "protected": {"paths": [], "ports": [18080]}}
        """)
        XCTAssertTrue(m.allowsConnect(ip: "10.0.0.1", port: 443))
        XCTAssertFalse(m.allowsConnect(ip: "10.0.0.1", port: 22))
        XCTAssertFalse(m.allowsConnect(ip: "10.0.0.1", port: 25))
        XCTAssertTrue(m.allowsConnect(ip: "::ffff:10.0.0.1", port: 80), "IPv4-mapped is decided as IPv4")
        XCTAssertTrue(m.allowsConnect(ip: "2001:db8::1", port: 443))
        XCTAssertFalse(m.allowsConnect(ip: "2001:db8::1", port: 80))
        XCTAssertFalse(m.allowsConnect(ip: "10.0.0.2", port: 443), "default deny")
        XCTAssertFalse(m.allowsConnect(ip: "example.com", port: 443), "names are never matched")
        XCTAssertFalse(m.allowsConnectToAnyAddress(port: 443), "default deny: some address is denied")
    }

    func testProtectedPathsAndPortsBeatThePolicy() throws {
        let m = try tables("""
        {"version": "v", "semantics": "leash-kernel-v1",
         "file": {"default_allow": true, "exact": [],
                  "prefix": [{"op": "read", "path": "/", "allow": true, "spec": 1, "order": 0},
                             {"op": "write", "path": "/", "allow": true, "spec": 1, "order": 1}]},
         "mutation": {"allow": [{"path": "/", "spec": 1}], "deny": [], "exact_deny": []},
         "exec": {"default_allow": true, "rules": [{"path": "/", "allow": true}]},
         "network": {"default_allow": true, "rules": []},
         "protected": {"paths": ["/Users/u/Library/Application Support/leash", "/var/folders/x/T/leash/private"],
                       "ports": [18080, 18000]}}
        """)
        XCTAssertFalse(m.allowsOpen(path: "/Users/u/Library/Application Support/leash/policy.cedar", write: false))
        XCTAssertFalse(m.allowsOpen(path: "/Users/u/Library/Application Support/leash", write: true))
        XCTAssertTrue(m.allowsOpen(path: "/Users/u/Library/Application Support/leashx", write: true))
        XCTAssertFalse(m.allowsOpen(path: "/private/var/folders/x/T/leash/private/ca-key.pem", write: false))
        XCTAssertTrue(m.allowsOpen(path: "/private/var/folders/x/T/leash/ca-cert.pem", write: false))
        XCTAssertFalse(m.allowsMutation(path: "/Users/u/Library/Application Support/leash/policy.cedar"))
        XCTAssertFalse(m.allowsExec(path: "/Users/u/Library/Application Support/leash/x", arguments: []))
        XCTAssertFalse(m.allowsConnect(ip: "127.0.0.1", port: 18080))
        XCTAssertFalse(m.allowsConnect(ip: "::1", port: 18000))
        XCTAssertFalse(m.allowsConnect(ip: "0.0.0.0", port: 18080))
        XCTAssertTrue(m.allowsConnect(ip: "127.0.0.1", port: 3000))
        XCTAssertTrue(m.allowsConnect(ip: "192.0.2.1", port: 18080))
        XCTAssertTrue(m.allowsConnectToAnyAddress(port: 443))
        XCTAssertFalse(m.allowsConnectToAnyAddress(port: 18080), "a name could be localhost")
    }

    func testUnknownSemanticsAreRefused() {
        XCTAssertThrowsError(try LeashPolicyTables.decode(from: Data("""
        {"version": "v", "semantics": "leash-kernel-v2",
         "file": {"default_allow": true, "exact": [], "prefix": []},
         \(empty)}
        """.utf8)))
    }

    func testCanonicalPath() {
        XCTAssertEqual(LeashPolicyMatcher.canonicalPath("/private/tmp/x"), "/tmp/x")
        XCTAssertEqual(LeashPolicyMatcher.canonicalPath("/private/var"), "/var")
        XCTAssertEqual(LeashPolicyMatcher.canonicalPath("/private/tmpx"), "/private/tmpx")
        XCTAssertEqual(LeashPolicyMatcher.canonicalPath("/private"), "/private")
        XCTAssertEqual(LeashPolicyMatcher.canonicalPath("/Users/x"), "/Users/x")
    }
}
