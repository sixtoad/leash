import Foundation

/// An Endpoint Security decision, as reported to the daemon for the event log
/// and the Control UI. Decisions themselves are made by `LeashPolicyMatcher`
/// over the daemon's policy tables.
struct LeashPolicyEvent: Codable, Identifiable {
    enum Kind: String, Codable {
        case processExec
        case fileAccess
    }

    enum FileOperation: String, Codable {
        /// open without FWRITE
        case open
        /// open of an existing file with O_CREAT and FWRITE
        case create
        /// open with FWRITE
        case write
        /// truncate(2): decided as a write open
        case truncate
        /// mkdir, and the creation of any non-regular file
        case mkdir
        /// unlink and rmdir
        case unlink
        /// either side of a rename or an exchangedata
        case rename
        /// a hard link (new name; the source must be readable)
        case link
        /// clonefile / copyfile (the new file)
        case clone
    }

    let id: UUID
    let timestamp: Date
    let kind: Kind
    let processPath: String
    let processArguments: [String]
    let currentWorkingDirectory: String?
    let filePath: String?
    let fileOperation: FileOperation?
    let parentProcessPath: String?
    let ttyPath: String?
    let leashProcessPath: String?
    let leashPid: Int32?
    let leashArguments: [String]?
    let leashTTYPath: String?
    let pid: Int32
    let parentPid: Int32
}

struct LeashPolicyDecision {
    enum Action: String, Codable {
        case allow
        case deny
    }
}
