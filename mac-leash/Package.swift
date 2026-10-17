// swift-tools-version:5.9
// Unit tests for the policy matcher the Endpoint Security and Network
// Extension providers share (Shared/PolicyCore). The Xcode project compiles
// the same sources into the extensions; this package only exists so the
// matcher can be tested with `swift test --package-path mac-leash` without
// building or signing the system extensions.
import PackageDescription

let package = Package(
    name: "LeashPolicyCore",
    platforms: [.macOS(.v14)],
    targets: [
        .target(
            name: "LeashPolicyCore",
            path: "Shared/PolicyCore"
        ),
        .testTarget(
            name: "LeashPolicyCoreTests",
            dependencies: ["LeashPolicyCore"],
            path: "Tests/LeashPolicyCoreTests",
            resources: [.copy("Resources/parity-vectors.json")]
        ),
    ]
)
