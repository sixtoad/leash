import SwiftUI
import AppKit
import NetworkExtension
import os.log

struct MainStatusView: View {
    @ObservedObject var endpointSecurityController: SystemExtensionController
    @ObservedObject var networkExtensionController: SystemExtensionController
    @ObservedObject var transparentProxyController: SystemExtensionController
    @State var networkFilterStatus: FilterStatus = .loading
    @State var apiStatus: APIStatus = .loading

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                Text("Leash")
                    .font(.system(size: 18, weight: .semibold))

                Spacer()
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 14)
            .background(Color(nsColor: .controlBackgroundColor))

            Divider()

            ScrollView {
                VStack(spacing: 16) {
                    endpointSecuritySection
                    networkFilterSection
                    webInterfaceSection
                }
                .padding(20)
            }
        }
        .frame(minWidth: 400, minHeight: 450)
        .onAppear {
            Task { @MainActor in
                // Read before activating: ensureExtensionIsActive clears the flag
                // once the extension reports active.
                let filterExtensionReplaced = networkExtensionController.extensionVersionNeedsReplacement

                endpointSecurityController.ensureExtensionIsActive()
                networkExtensionController.ensureExtensionIsActive()
                transparentProxyController.ensureExtensionIsActive()
                // Restore the transparent-proxy NE config if the user had it enabled;
                // a sysext replacement (version bump) drops it to disabled and the
                // sysext re-activation above does not re-enable the config. See #58.
                await TransparentProxyManager.shared.reconcileOnLaunch()
                // Same for the content filter, plus a health check: after an
                // in-place sysext replacement the provider can read enabled while
                // being disconnected from the daemon, holding no rules. See #62.
                await NetworkFilterManager.shared.reconcileOnLaunch(extensionReplaced: filterExtensionReplaced)
            }
            refreshNetworkFilterStatus()
            checkAPIStatus()
        }
    }
}
