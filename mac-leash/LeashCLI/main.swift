import Foundation
import Darwin

private struct CLIConfig {
    var verbose = false
    var directory: String?
    var command: [String] = []
}

private enum CLIError: LocalizedError {
    case missingCommand
    case missingDirectoryValue
    case unknownOption(String)
    case executableNotFound(String)
    case notStartedByLeash
    case enforcementNotConfirmed

    var errorDescription: String? {
        switch self {
        case .missingCommand:
            return "No command specified."
        case .missingDirectoryValue:
            return "Option -C/--directory requires a value."
        case .unknownOption(let option):
            return "Unrecognized option: \(option)."
        case .executableNotFound(let executable):
            return "Unable to locate executable '\(executable)' in PATH."
        case .notStartedByLeash:
            return "leashcli runs commands only for `leash --darwin exec`, which confirms enforcement first."
        case .enforcementNotConfirmed:
            return "leash did not confirm that this command is leashed; not running it."
        }
    }
}

private func parseArguments(_ arguments: [String]) throws -> CLIConfig {
    var config = CLIConfig()
    var command: [String] = []

    var index = 0
    while index < arguments.count {
        let arg = arguments[index]

        if !command.isEmpty {
            command.append(contentsOf: arguments[index...])
            break
        }

        switch arg {
        case "-v", "--verbose":
            config.verbose = true
        case "-C", "--directory":
            index += 1
            guard index < arguments.count else {
                throw CLIError.missingDirectoryValue
            }
            config.directory = arguments[index]
        case "--":
            let remaining = arguments.suffix(from: index + 1)
            command.append(contentsOf: remaining)
            index = arguments.count
            continue
        default:
            if arg.hasPrefix("-") {
                throw CLIError.unknownOption(arg)
            }
            command.append(contentsOf: arguments.suffix(from: index))
            index = arguments.count
            continue
        }

        index += 1
    }

    config.command = command
    return config
}

/// Locate the leash MITM CA certificate so the launched workload can be told to
/// trust it. Best-effort: LEASH_CA_CERT overrides, else LEASH_DIR/ca-cert.pem, else
/// the default. Returns nil if no CA file is present (then no env is injected).
private func resolveLeashCACertPath(env: [String: String]) -> String? {
    let candidates: [String]
    if let explicit = env["LEASH_CA_CERT"], !explicit.isEmpty {
        candidates = [explicit]
    } else if let dir = env["LEASH_DIR"], !dir.isEmpty {
        candidates = ["\(dir)/ca-cert.pem"]
    } else {
        candidates = ["/leash/ca-cert.pem"]
    }
    return candidates.first { FileManager.default.fileExists(atPath: $0) }
}

/// Env vars that point common toolchains at a custom CA bundle.
private let caTrustEnvKeys = [
    "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "CURL_CA_BUNDLE",
    "REQUESTS_CA_BUNDLE", "GIT_SSL_CAINFO", "AWS_CA_BUNDLE"
]

private func resolveExecutable(_ executable: String, env: [String: String]) -> String? {
    if executable.contains("/") {
        return executable
    }
    let searchPaths = env["PATH"]?.split(separator: ":") ?? []
    for path in searchPaths {
        let candidate = URL(fileURLWithPath: String(path)).appendingPathComponent(executable)
        if FileManager.default.isExecutableFile(atPath: candidate.path) {
            return candidate.path
        }
    }
    return nil
}

private func awaitGoAhead(_ environment: [String: String]) throws {
    guard let text = environment["LEASH_START_FD"], let fd = Int32(text), fd > 2 else {
        throw CLIError.notStartedByLeash
    }
    defer { close(fd) }
    var received: [UInt8] = []
    var buffer = [UInt8](repeating: 0, count: 16)
    while received.count < 3 {
        let n = read(fd, &buffer, buffer.count)
        if n < 0 && errno == EINTR { continue }
        if n <= 0 { break }
        received.append(contentsOf: buffer[0..<n])
    }
    guard received.starts(with: Array("go".utf8)) else {
        throw CLIError.enforcementNotConfirmed
    }
}

private func runCommand(config: CLIConfig) throws -> Int32 {
    guard !config.command.isEmpty else {
        throw CLIError.missingCommand
    }

    let environment = ProcessInfo.processInfo.environment
    let executable = config.command[0]
    let resolvedExecutable = resolveExecutable(executable, env: environment) ?? executable

    guard FileManager.default.isExecutableFile(atPath: resolvedExecutable) else {
        throw CLIError.executableNotFound(executable)
    }

    // Wait for `leash --darwin exec` to confirm that the Endpoint Security
    // extension tracks this process (and so everything it spawns) and that
    // the extensions enforce the daemon's current policy. It writes "go" on
    // the descriptor named by LEASH_START_FD, or closes it to refuse. This
    // replaces a fixed half-second sleep that hoped the extension had
    // switched to AUTH mode in time.
    try awaitGoAhead(environment)

    var pid: pid_t = 0
    var attrs: posix_spawnattr_t?
    var fileActions: posix_spawn_file_actions_t?

    posix_spawnattr_init(&attrs)
    posix_spawn_file_actions_init(&fileActions)

    defer {
        posix_spawnattr_destroy(&attrs)
        posix_spawn_file_actions_destroy(&fileActions)
    }

    var argv: [UnsafeMutablePointer<CChar>?] = config.command.map { strdup($0) }
    argv.append(nil)

    // Trust the leash MITM CA so TLS through the transparent proxy isn't rejected.
    // Only injected when a CA file is actually present, and never overriding a value
    // the caller already set. See docs/MACOS-P1-PROXY.md.
    var env = environment
    env.removeValue(forKey: "LEASH_START_FD")
    if let caPath = resolveLeashCACertPath(env: environment) {
        for key in caTrustEnvKeys where env[key] == nil {
            env[key] = caPath
        }
        if config.verbose {
            FileHandle.standardError.write(Data("[leashcli] trusting leash CA at \(caPath)\n".utf8))
        }
    }

    let argsTail = config.command.dropFirst().joined(separator: " ")

    if config.verbose {
        FileHandle.standardError.write(Data("[leashcli] launching \(resolvedExecutable) \(argsTail)\n".utf8))
    }

    var envp: [UnsafeMutablePointer<CChar>?] = env.map { key, value in strdup("\(key)=\(value)") }
    envp.append(nil)

    defer {
        argv.forEach { free($0) }
        envp.forEach { free($0) }
    }

    if let directory = config.directory {
        let addResult: Int32 = directory.withCString { dirPath in
            posix_spawn_file_actions_addchdir_np(&fileActions, dirPath)
        }
        guard addResult == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: addResult) ?? .EPERM)
        }
    }

    let spawnResult = resolvedExecutable.withCString { execPath in
        posix_spawnp(&pid, execPath, &fileActions, &attrs, &argv, &envp)
    }

    guard spawnResult == 0 else {
        throw POSIXError(POSIXErrorCode(rawValue: spawnResult) ?? .ENOENT)
    }

    var status: Int32 = 0
    waitpid(pid, &status, 0)

    // A command killed by a signal (including an exec Endpoint Security
    // denied) is a failure, reported the shell's way as 128 + signal; it used
    // to come out as exit 0.
    let termSignal = status & 0x7f
    let exitStatus: Int32 = termSignal != 0 && termSignal != 0x7f
        ? 128 + termSignal
        : Int32((status >> 8) & 0xff)

    if config.verbose {
        FileHandle.standardError.write(Data("[leashcli] command exited with status \(exitStatus)\n".utf8))
    }

    return exitStatus
}

private func printUsage(to handle: FileHandle = .standardError) {
    let usage = """
    Usage: leashcli [-v] [-C directory] [--] command [args...]

    Options:
      -v, --verbose         Print diagnostic output.
      -C, --directory PATH  Change to PATH before running the command.
      --                    Treat the rest of the arguments as the command.
    """
    handle.write(Data(usage.utf8))
}

func main() {
    var args = CommandLine.arguments
    _ = args.removeFirst()

    do {
        let config = try parseArguments(args)
        if config.command.isEmpty {
            printUsage()
            throw CLIError.missingCommand
        }

        let status = try runCommand(config: config)
        exit(status)
    } catch let error as CLIError {
        FileHandle.standardError.write(Data("leashcli: \(error.localizedDescription)\n".utf8))
        printUsage()
        exit(64)
    } catch {
        FileHandle.standardError.write(Data("leashcli: \(error.localizedDescription)\n".utf8))
        exit(70)
    }
}

main()
