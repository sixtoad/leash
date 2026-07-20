import Foundation
import NetworkExtension
import os.log

autoreleasepool {
    let log = OSLog(subsystem: LeashIdentifiers.bundle, category: "transparent-proxy-main")
    os_log("LeashProxy system extension starting...", log: log, type: .default)

    NEProvider.startSystemExtensionMode()
}

dispatchMain()
