# Integration Architecture

Three integration boundaries hold the three parts together. All three converge on one Go process (`leashd` or `darwind`) listening on `:18080`.

> **Adjacent docs:** [`api-contracts-leash-core.md`](api-contracts-leash-core.md) (full endpoint spec) · [`design/AUTOCOMPLETE.md`](design/AUTOCOMPLETE.md) (Cedar editor round-trip) · [`design/BOOT.md`](design/BOOT.md) (target↔manager bootstrap inside containers).

## 1. Topology

```
                                  ┌─────────────────────────────┐
                                  │  controlui-web (Next.js)    │
                                  │  • SPA embedded in Go bin   │
                                  │  • All calls → :18080       │
                                  └────────┬────────────────────┘
                            HTTP+WS (fetch + future WS)         
                                          │                     
                              ┌───────────▼──────────────┐      
                              │  leashd  /  darwind      │      
                              │  :18080  (HTTP + /api WS)│      
                              │  :18000  (MITM, Linux)   │      
                              │  Cedar engine / policy   │      
                              │  WebSocketHub            │      
                              │  macsync.Manager (mac)   │      
                              └───┬────────────────┬─────┘      
                       eBPF maps  │                │  WebSocket  
                       (Linux)    │                │ (mac envs)  
                                  ▼                ▼             
                        ┌───────────────┐   ┌─────────────────┐ 
                        │ Target Cgroup │   │  mac-leash app  │ 
                        │ (governed)    │   │  + LeashES + NF │ 
                        └───────────────┘   └─────────────────┘ 
```

Two transport channels carry everything except the kernel-side enforcement: HTTP for synchronous control-plane operations, and a single WebSocket at `/api` that multiplexes UI events and macOS shim envelopes.

## 2. controlui-web ↔ leash-core (HTTP + future WS)

The UI is statically built (`pnpm build` → `internal/ui/dist`) and embedded into the Go binary via `//go:embed`. At runtime `internal/ui.SPAHandler` serves it at `/` with appropriate cache headers — the only Go-side dependency is that the binary be built with a populated `dist/`.

### Synchronous control-plane

All UI server-state lives behind `/api/policies/*` (and `/suggest`). Every call goes through `controlui/web/src/lib/policy/api.ts`. See [api-contracts-leash-core.md § Cedar Policy CRUD](api-contracts-leash-core.md#cedar-policy-crud--policyapi).

Critical round-trips:

| UI action | Endpoint | Effect on the daemon |
|---|---|---|
| Type in Cedar editor | `POST /api/policies/validate` (debounced 500 ms) | Compile-only; returns rule counts + linter issues. |
| Trigger char in Cedar editor | `POST /api/policies/complete` | Hints merged from policy snapshot + MITM observer + WS event ring. |
| Ctrl-S | `POST /api/policies/persist?force=1` | Write source file; broadcast `policy.snapshot` over WS. |
| Add policy from event | `POST /api/policies/add-from-action` | Synthesises a Cedar statement; applies + broadcasts. |
| Mode switch | `POST /api/policies/permit-all` / `enforce-apply` | Updates `default_policy` BPF map and broadcasts. |

### Asynchronous event stream

The same `/api` endpoint upgrades to WebSocket. The UI is *not* yet wired to consume the live stream — `src/lib/mock/sim.tsx` simulates events for dev mode. When the UI later subscribes for real, the messages already streaming are described in [api-contracts § WebSocket](api-contracts-leash-core.md#websocket--api):

- `leash.hello`, `leash.heartbeat`
- `policy.snapshot` — fires after every CRUD mutation, so the UI can refresh React Query caches without polling.
- `proc.exec`, `file.open`, `connect`, `mcp.*`, `http.rewrite` — every LSM/proxy decision.

The mac-leash WebSocket client uses the same endpoint with a disjoint set of message `type`s (see § 4).

## 3. leashd ↔ leash-entry (inside containers, bootstrap)

Inside the manager container, `leashd` waits for `leash-entry` (inside the target container) to install the CA into the system trust store and signal completion. Fully documented in [`design/BOOT.md`](design/BOOT.md) — summary:

```
runner (host)
  ├─ writes /leash/leash-entry-linux-<arch>          (extracted from internal/entrypoint embed)
  ├─ writes /leash/leash-entry.ready
  └─ docker run target ─┐
                        │  ENTRYPOINT=/leash/leash-entry-linux-<arch>
                        ▼
                target container
                  ├─ leash-entry waits for ready file
                  ├─ records cgroup path → /leash/cgroup-path
                  ├─ polls for /leash/ca-cert.pem        (produced by leashd)
                  ├─ installs CA into trust store (update-ca-certificates / update-ca-trust)
                  └─ writes /leash/bootstrap.ready       (PID, hostname, ISO-8601 timestamp)
                              │
                              ▼
runner & leashd both observe bootstrap.ready
  ├─ runner reports readiness to user
  └─ leashd activates (attaches BPF programs, starts MITM proxy)
```

The `/leash` mount is world-readable (mode 0755); `/leash-private` is manager-only (mode 0700). Private CA key (`ca-key.pem`, mode 0600) lives in `/leash-private` and is never visible to the target. The runner enforces dir perms before launch; `internal/proxy/ca.go` writes the files atomically with the required modes; `internal/leashd/runtime.go` refuses to start if `LEASH_PRIVATE_DIR` is missing or too permissive (see [`design/SECURITY-MODEL.md`](design/SECURITY-MODEL.md)).

## 4. mac-leash ↔ leash-core (WebSocket envelopes)

`Shared/DaemonSync.swift` opens a `URLSessionWebSocketTask` to `ws://127.0.0.1:18080/api` (overridable via `LEASH_WS_URL`). The Go side is `internal/macsync.Manager` (instantiated by `darwind`). All envelopes are typed by `Envelope.Type` (`internal/messages/messages.go`).

```
Swift                                   Go
─────                                   ──
DaemonSync.connect
   └─ send client.hello
        capabilities = ["pid-sync", "rule-sync", "event", "policy", "network-rules"]
                            ──────────────────►
                                       macsync.Manager.RegisterClient
                                       (records ClientState by shim_id)

LeashMonitor (ES) detects exec/open
   ├─ build LeashPolicyEvent
   ├─ checkCachedPolicy → tentative decision
   └─ sendPolicyEvent (request)
                            ──────────────────►
                                       macsync.Manager handles mac.policy.event
                                       (correlate with PIDs, telemetry, etc.)
                            ◄──────────────────
                                       broadcasts mac.policy.decision

darwind reloads Cedar
   └─ macsync.ConvertPolicyToMacRules(activeRules)
                            ──────────────────►
                                       broadcast mac.rule.snapshot
LeashCommunicationService caches rules ───┘

LeashMonitor PID changes
   └─ sendTrackedPIDs       ──────────────────►
                                       store in macsync.trackedPIDs

NetworkFilter loads
   └─ subscribes mac.pid.sync, mac.network_rule.update
   └─ when needed: sendPolicyEvent for unresolved flow
```

### Envelope catalog

A summary table — full payload shapes in [`data-models-leash-core.md`](data-models-leash-core.md) and [`api-contracts-leash-core.md`](api-contracts-leash-core.md#mac-envelopes-go--swift-over-api).

**Swift → Go:**

| Type | Producer | Purpose |
|---|---|---|
| `client.hello` | `DaemonSync` on connect | Register shim. |
| `mac.pid.sync` | LeashES (PIDs); NF (subscribe only) | Push tracked-PID snapshot. |
| `mac.rule.sync` | LeashES / app | Mirror cached rule set. |
| `mac.policy.event` (request) | LeashES | Ask daemon for decision. |
| `mac.policy.decision` (request) | LeashES | Confirm/override decision. |
| `mac.network_rule.update` | NF / app | Mutate per-flow rules. |
| `mac.rule.add` / `remove` / `clear` / `query` | App | CRUD on rule cache. |
| `mac.event` | Any | Telemetry / audit. |

**Go → Swift (broadcast):**

| Type | Trigger | Audience |
|---|---|---|
| `mac.policy.decision` | After daemon evaluates `mac.policy.event` | LeashES |
| `mac.rule.snapshot` | After policy reload or rule mutation | All shims |
| `mac.network_rule.update` | After NF rule mutation | All shims |
| `mac.pid.sync` | Confirmation broadcast | NF |
| `policy.snapshot` (UI-style) | After any Cedar CRUD | UI clients (mac shims ignore) |

### Cedar → macOS rule translation

`internal/macsync/translator.go:ConvertPolicyToMacRules` walks an `lsm.PolicySet` and emits the macOS equivalents:

- `PolicySet.Exec` → `MacPolicyRule { kind: processExec, ExecutablePath, Action }`
- `PolicySet.Open` → `MacPolicyRule { kind: fileAccess, FilePath | Directory, Action }`
- `PolicySet.Connect` → `MacNetworkRule { Target: domain | ipAddress | ipRange, Action }`

Rule IDs are deterministic UUIDs so the Swift side can detect adds/removes by id.

### Policy enforcement asymmetry

Same Cedar source applies to both paths, but enforcement coverage differs:

| Capability | Linux containers | macOS native |
|---|---|---|
| `Action::"FileOpen"` | ✅ eBPF LSM `file_open` | ✅ EndpointSecurity `ES_EVENT_TYPE_AUTH_OPEN` |
| `Action::"ProcessExec"` | ✅ eBPF LSM `bprm_check_security` | ✅ EndpointSecurity `ES_EVENT_TYPE_AUTH_EXEC` |
| `Action::"NetworkConnect"` | ✅ eBPF LSM `socket_connect` + MITM | ✅ NetworkExtension content-filter (per-flow + TLS SNI) |
| `Action::"HttpRewrite"` | ✅ MITM proxy | ❌ no MITM on macOS |
| `Action::"McpCall"` | ✅ MITM MCP observer | ⚠️ no MCP logging today |
| Live mode toggle | ✅ BPF map | ✅ rule cache + daemon broadcast |

## 5. Hint sources for autocomplete

Worth calling out as its own integration: `POST /api/policies/complete` blends three runtime contributors before scoring:

1. **`policy.Manager.Snapshot()`** — known files, dirs, hosts, MCP servers/tools, HTTP headers in the active policy.
2. **`mcpObserver.SnapshotServers()` / `SnapshotTools()`** — last 32 MCP server hosts and tool names observed by the MITM proxy.
3. **`websocketHub` event-ring scan** — recent hostnames + header names from streamed events.

Client `idHints` (supplied by the editor) are merged last so user-typed identifiers don't outrank server-derived ones.

Diagram and engine internals in [`design/AUTOCOMPLETE.md`](design/AUTOCOMPLETE.md).

## 6. Network ports

| Port | Bound by | Purpose |
|---|---|---|
| `18080` | `leashd` / `darwind` | HTTP + WebSocket API + embedded SPA |
| `18000` | `leashd` MITM proxy (Linux only) | iptables-redirected HTTP/HTTPS for governed container |
| 443 / 80 / etc. | Outbound target traffic | Redirected to 18000 by iptables; SO_MARK 0x2000 on proxy-originated traffic prevents loop |

`--listen` / `LEASH_LISTEN` can be set blank to disable the Control UI listener entirely. The MITM port is fixed in the runtime image (`LEASH_PROXY_PORT=18000`).
