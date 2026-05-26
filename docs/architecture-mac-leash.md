# Architecture — mac-leash (macOS Native)

The macOS path replaces containers+eBPF with Apple's native security frameworks. The Go daemon (`darwind`) still runs on the host and exposes the same HTTP/WS API at `:18080`; instead of attaching BPF, it cooperates with two system extensions that ship inside the companion app `Leash.app`.

> **Adjacent docs:** [`MACOS.md`](MACOS.md) (user-facing setup) · [`api-contracts-leash-core.md`](api-contracts-leash-core.md#mac-envelopes-go--swift-over-api) (mac envelope schema) · [`integration-architecture.md`](integration-architecture.md#go--macos) (Go ↔ Swift surface) · [`data-models-leash-core.md`](data-models-leash-core.md#6-macos-rule-models-mac-leashshared) (Swift model types).

## 1. Xcode targets

| Target | Path | Type | Bundle ID suffix | Entitlements |
|---|---|---|---|---|
| Leash | `mac-leash/Leash/` | macOS app (status-bar) | (root) | `com.apple.developer.networking.networkextension`, `com.apple.developer.system-extension.install` |
| LeashCLI | `mac-leash/LeashCLI/` | macOS CLI bundled inside `Leash.app/Contents/Resources/leashcli` | (none) | (none — runs as user) |
| LeashES | `mac-leash/LeashES/` | System Extension (Endpoint Security) | `.LeashES` | `com.apple.developer.endpoint-security.client` |
| LeashNetworkFilter | `mac-leash/LeashNetworkFilter/` | System Extension (Network Extension content-filter) | `.LeashNetworkFilter` | `com.apple.developer.networking.networkextension` (`content-filter-provider`) |

Team ID: `W5HSYBBJGA`. Base bundle is derived from `LEASH_BUNDLE_IDENTIFIER` env or the parent app's identifier — default `com.strongdm.leash`.

## 2. Status-bar app (`Leash/`)

| File | Role |
|---|---|
| `LeashApp.swift` | App entry. Constructs two `SystemExtensionController` instances (ES auto-activates; NF requires manual approval). Sends an `app.boot` event over WebSocket. Window size 400×450 (min). |
| `MainStatusView.swift` + `MainStatusView+Sections.swift` | Three sections: EndpointSecurity, NetworkFilter, WebInterface. Each shows status + Activate / Refresh / FDA-check / Remove buttons. `onAppear` triggers `ensureExtensionIsActive()` on both controllers. |
| `SystemExtensionController.swift` + `SystemExtensionController+Internals.swift` | State machine for sysext activation. Status enum: `.checking` / `.inactive` / `.activating` / `.requiresApproval` / `.installedButDisabled` / `.requiresFullDiskAccess` / `.active` / `.failed(reason)`. Polls `/usr/bin/systemextensionsctl list` to detect state. Listens on `DistributedNotificationCenter` for `LeashNotifications.fullDiskAccessMissing` / `…Ready`. |
| `ExperimentalSettingsView.swift` | Toggles: "Enforce rules for untracked processes" (`systemwide_enforcement`), "Delay new flows" (`flow_delay_enabled` + min/max sliders 0.0–1.0 s). |
| `SparkleUpdater.swift` | Wraps `SPUStandardUpdater`. Auto-download disabled. Feed URL from `SUFeedURL` (Info.plist; AWS S3 appcast) or env override. First check ~10s after launch. |

### Sysext lifecycle

```
ensureExtensionIsActive()
  └─ checkCurrentStatus(activateIfNeeded: true, force: false)
       ├─ extensionState() → spawn `systemextensionsctl list`, parse → current state
       │     • If `.active` and embedded version == stored UserDefaults version → done
       │     • Else fall through to submitActivationRequest()
       └─ submitActivationRequest(force: false)
            └─ OSSystemExtensionManager.shared.submitRequest(activationRequest)
                 └─ Delegate callbacks
                      ├─ .requiresApproval        → status = .requiresApproval (user prompted in System Settings)
                      ├─ .willCompleteActivation  → pending cleared
                      ├─ .didFinishWithError      → status = .failed(message)
                      └─ (eventual) .didFinish    → re-check → status = .active
```

Embedded sysext version is compared against UserDefaults key `systemextension.version.<id>`. Mismatch forces re-activation, which prompts the user to approve the new version.

## 3. LeashES — Endpoint Security extension (`LeashES/`)

**Entry** (`main.swift`) wires `LeashCommunicationService` ↔ `LeashMonitor` (bidirectional weak/strong refs) and starts both. Sends `es.boot`, then `es.full_disk_access.ready` once FDA is confirmed.

**`LeashMonitor.swift` + `+Handlers.swift`**

- Creates ES client via `es_new_client` with a serial callback queue.
- Subscribes to: `ES_EVENT_TYPE_NOTIFY_EXEC`, `ES_EVENT_TYPE_AUTH_EXEC`, `ES_EVENT_TYPE_AUTH_OPEN`, `ES_EVENT_TYPE_NOTIFY_EXIT`.
- Maintains `trackedLeashProcesses: [pid_t: TrackedLeashProcess]`.
- After tracking changes, calls `commService.pushTrackedPIDs()` so the Network Filter has fresh PID metadata.

**Decision path**:
1. Event arrives → extract path / PID / parent.
2. Compute "is this leash or a leash child?" via `leashInfo()` — matches against `leashExecutableNames`, suffix `/Leash.app/Contents/Resources/leashcli`, plus signing ID and team ID checks.
3. Build `LeashPolicyEvent` (kind = `processExec` or `fileAccess`).
4. `checkPolicyOrAllowDefault()` → `commService.checkCachedPolicy(event)` → match against cached `[LeashPolicyRule]`. Default = allow (fail-open) unless a rule matches.
5. For AUTH events, respond immediately with `es_respond_auth_result()`. NOTIFY events are logged-only.
6. `logEventAsync()` forwards the full event + decision over WebSocket as `mac.policy.event` (request) or `mac.policy.decision` (response/broadcast).

**`LeashCommunicationService.swift` + `+Handlers.swift`**

- Subscribes to daemon messages `mac.policy.decision`, `mac.rule.add` / `remove` / `clear` / `snapshot`.
- `eventCache: [UUID: LeashPolicyEvent]` (LRU, cap 200).
- `cachedRules: [LeashPolicyRule]` — refreshed on every `mac.rule.snapshot`.
- `checkCachedPolicy(event)` walks the local rule cache for a hot-path match.

## 4. LeashNetworkFilter — Network Extension (`LeashNetworkFilter/`)

**Entry** (`main.swift`): `NEProvider.startSystemExtensionMode()` → `dispatchMain()`.

**`FilterDataProvider.swift` (+ five extension files)**

| File | Role |
|---|---|
| `FilterDataProvider.swift` | Base subclass of `NEFilterDataProvider`. Subscribes to `mac.pid.sync` and `mac.network_rule.update` daemon broadcasts. Holds `trackedPIDs: [pid_t: TrackedPIDInfo]` and `networkRules: [NetworkRule]`. |
| `+FlowHandling.swift` | `handleNewFlow` — extracts PID from the socket audit token, looks up hostname/port via `NWHostEndpoint`, detects DNS (UDP:53) and TLS candidates (TCP:443), applies optional flow-delay, dispatches to `evaluateFlow`. |
| `+RuleEvaluation.swift` (~27 KB) | The verdict logic. Public surface: `evaluateFlow(...) -> FlowDecision`, `handleDNSOutbound`, `parseClientHelloSNI`. Buffers TLS ClientHello, parses SNI extension (type 0), caches resolution in `domainResolutionCache`. Rule match per `NetworkRule`: domain exact, IP address, CIDR range. Returns `.allow`, `.deny(reason:)`, or `.needsInspection`. |
| `+PendingFlows.swift` | `pendingFlowsByPID: [pid_t: [QueuedFlow]]` (cap 16 per PID, TTL 60 s). When tracked-PID metadata arrives later, requeue and re-evaluate. |
| `+PIDMetadata.swift` | `TrackedPIDInfo { pid, leashPID, executablePath, ttyPath, cwd }`. Fallback for unknown PIDs (system-wide mode): `inferTrackedInfo()` shells out to `/bin/ps`. |
| `+State.swift` | `DispatchQueue`-serialised state. Config keys: `systemwide_enforcement`, `flow_delay_enabled`, `flow_delay_min_seconds`, `flow_delay_max_seconds`. |

**Verdict fast-path**:

```
incoming socket flow
   └─ extract PID from audit token (RFC 4253 NEFilterFlow API)
        └─ lookup trackedPIDs[pid]
             ├─ hit  → evaluateFlow against networkRules
             ├─ miss + systemwide enforcement off → allow (fail-open for untracked)
             └─ miss + systemwide enforcement on  → inferTrackedInfo (ps)
                  └─ queue for inspection if metadata not yet synced (PendingFlows)
```

TLS-inspect candidates pause the flow with `.needsInspection`, buffer the ClientHello, parse the SNI, then resolve to allow/deny against the rules. DNS queries are inspected at the wire level (no SNI needed) for domain extraction.

## 5. LeashCLI (`LeashCLI/`)

A thin process launcher. `main.swift`:

1. Parse args: `-v`/`--verbose`, `-C`/`--directory <path>`, `--`, command, args.
2. Resolve executable via `PATH`.
3. Sleep 0.5 s — gives Endpoint Security time to subscribe to AUTH events before a very-short-lived command finishes (comment explains the rationale).
4. `posix_spawnp()` with inherited env and optional `chdir`.
5. `waitpid()`; return child exit status.

It does **not** speak WebSocket and does **not** read rules — it exists purely to be observed by LeashES under a clearly identifiable process tree (leash binary → `leashcli` → target command).

## 6. Shared models (`Shared/`)

| File | Role |
|---|---|
| `DaemonSync.swift` + `+Extensions.swift` (23 KB) | WebSocket client to `ws://127.0.0.1:18080/api` (override via `LEASH_WS_URL`). Auto-reconnect via `URLSessionWebSocketTask`. Per-process `shim_id` (UUID); session-level `session_id`. Capabilities advertised on hello: `["pid-sync", "rule-sync", "event", "policy", "network-rules"]`. Public API in [§7](#7-public-api-of-daemonsync) below. |
| `PolicyModels.swift` | `LeashPolicyEvent`, `LeashPolicyDecision`, `LeashPolicyRule`. Full shape in [`data-models-leash-core.md`](data-models-leash-core.md#6-macos-rule-models-mac-leashshared). |
| `NetworkRule.swift` | `enum Action { case allow, deny }`, `enum Target { case domain(String), ipAddress(String), ipRange(String) }`. Optional CWD scope. `fromDictionary()` parses daemon responses. |
| `LeashIdentifiers.swift` | `bundle`, `teamIdentifier`, `endpointSecurityExtension`, `networkFilterExtension` — all resolvable from env overrides. |
| `LeashNotifications.swift` | `fullDiskAccessMissing` + `fullDiskAccessReady` distributed notifications. |

## 7. Public API of `DaemonSync`

All methods are queued on a serial DispatchQueue, ensure connection, encode the envelope, and send. Fire-and-forget unless flagged "request" (which awaits a response via `request_id`).

```swift
// Telemetry / observation
func sendEvent(name:, details:, severity:, source:)
func sendTrackedPIDs(_ pids: [PIDEntry])            // mac.pid.sync
func sendRuleSnapshot(ruleSet: RuleSet)             // mac.rule.sync

// Policy round-trip
func sendPolicyEvent(_ event: LeashPolicyEvent)              // request: mac.policy.event
func sendPolicyDecision(_ decision: LeashPolicyDecision)     // request: mac.policy.decision
func addRules / removeRules / clearAllRules(_ rules:)        // mac.rule.{add,remove,clear}
func queryRules(completion:)                                  // request: mac.rule.query

// Network filter
func updateNetworkRules(_ rules:)                            // request: mac.network_rule.update
```

`Envelope` fields: `type`, `version`, `session_id`, `shim_id`, `request_id?`, `payload`.

## 8. Activation requirements (operator view)

These are documented in [`MACOS.md`](MACOS.md); included here for cross-reference:

- macOS 14+ (Sonoma).
- System Settings → General → Login Items & Extensions → Extensions: approve both Network Filter and Endpoint Security entries.
- System Settings → Privacy & Security → Full Disk Access: enable for `LeashES`.
- System Settings → Network → VPN & Filters → "Leash Network Filter" should show green + Enabled.

Removal via `systemextensionsctl uninstall W5HSYBBJGA com.strongdm.leash.LeashES` and `…LeashNetworkFilter`, or via the app's per-section "Remove" buttons.

## 9. Known limitations (current)

From [`MACOS.md`](MACOS.md), validated against code:

- No HTTP header injection / rewrite on macOS — the local MITM proxy is not launched in this path.
- MCP logging is not emitted on macOS today (no MCP observer wired up in `darwind`).
- IP-range matching is at the per-host/per-IP level only — no full CIDR.
- Default network behaviour is fail-open for flows without PID metadata; enabling "Enforce rules for untracked processes" routes those through `inferTrackedInfo` instead.
- `leash --darwin exec …` expects the companion CLI at `/Applications/Leash.app/Contents/Resources/leashcli`; moving the app breaks launches.
- Control UI is only reachable at `localhost:18080`.
