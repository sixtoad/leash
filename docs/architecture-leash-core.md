# Architecture — leash-core (Go CLI + Daemon)

This document complements the existing design corpus. Conceptual rationale (why eBPF LSM, why MITM proxy, why Cedar) lives in [`design/ARCHITECTURE.md`](design/ARCHITECTURE.md). The job here is to describe **the actual Go package layout, public surface, and call graph** so a contributor can find their way around without reading every file first.

> **Adjacent docs:** [`source-tree-analysis.md`](source-tree-analysis.md) (where each package lives) · [`api-contracts-leash-core.md`](api-contracts-leash-core.md) (HTTP/WS surface) · [`data-models-leash-core.md`](data-models-leash-core.md) (Cedar/IR/BPF/config/macOS types) · [`integration-architecture.md`](integration-architecture.md) (Go↔Web, Go↔Swift).

## 1. Binary multiplexer

A single binary, `leash`, is dispatched by `cmd/leash/main.go`:

```
leash --version            → printVersion()
leash --daemon ...         → leashd.Main(args)     # in-container, Linux only
leash --darwin <subcmd>    → darwind.Main(args)    # macOS native
leash <anything else>      → runner.Main(args)     # host-side orchestrator
```

A separate binary, `leash-entry` (`cmd/leash-entry/main.go`), ships embedded as compressed bytes inside `leash` (`internal/entrypoint`). The runner extracts the right arch into the `/leash` shared volume and the target container `ENTRYPOINT`s it.

## 2. Three top-level call paths

### 2.1 Runner path (host CLI launcher)

Default for any `leash <cmd>` invocation. End-to-end:

1. `runner.Main` parses flags (see [API contracts § flag table](api-contracts-leash-core.md) — actually see runner README; full table in the agent report) and `configstore.LoadWithOverlay(callerDir)` to merge global + `.leash.toml` settings.
2. `entrypoint.InflateBinaries(shareDir)` decompresses the two `leash-entry-linux-{amd64,arm64}` blobs and writes `leash-entry.ready`.
3. Two `docker run` invocations:
   - **Target container** — `--entrypoint /leash/leash-entry-linux-<arch>`, with `/leash` and `/leash-private` bind mounts plus user `-v`/`-e`/auto-mounts (`~/.claude` etc., gated by `configstore`).
   - **Leash manager container** — `--leash-image`, `--privileged`, `--cap-add NET_ADMIN`, `--cgroupns=host`, `--network container:<target>`. Runs `leash --daemon`.
4. `waitForBootstrap()` polls `/leash/bootstrap.ready` (500ms cadence, default `LEASH_BOOTSTRAP_TIMEOUT=2m`). On success the runner reports the Control UI URL and (if `--open`) launches a browser via `openflag`.
5. On `SIGTERM`/`SIGINT` or natural exit, `cleanup()` removes the bootstrap marker, deletes temp mounts, and `docker rm -f`s both containers.

### 2.2 Daemon path (`leashd`)

Linux-only, runs inside the manager container. Lifecycle (matches [`design/BOOT.md`](design/BOOT.md)):

1. **Staging** — `initRuntime` constructs the SharedLogger, WebSocketHub, LSMManager (without attaching), HeaderRewriter, OTEL Provider, Cedar `Compilation`, MITMProxy, policy.Manager.
2. **Frontend** — `startFrontend` mounts `/api` (WS), `/api/policies/*` (policyAPI), `/suggest` (suggestAPI), `/healthz`, `/health/policy`, and `/` (embedded SPA).
3. **Bootstrap wait** — polls for `/leash/bootstrap.ready` produced by `leash-entry` in the target. Times out with a targeted error if missing.
4. **Activation** — `policy.WatchCedar` starts; `lsmManager.LoadAndStart()` attaches the three BPF programs; `mitmProxy.Run()` starts in a goroutine.
5. **Steady state** — file watcher reloads on Cedar change; UI/API mutations route through `policy.Manager` and broadcast `policy.snapshot` over the WebSocket.

### 2.3 Darwin path (`darwind`)

macOS native equivalent of leashd. Binds the *same* HTTP+WS surface on `:18080` (controlled by `-serve`), but:

- Skips eBPF/LSM (defaults `--skip-cgroup=true`; `--allow-lsm-failure` is also supported).
- Does **not** start the local MITM proxy.
- Spawns `internal/macsync.Manager` and routes `mac.*` envelopes between the policy engine and the Swift `Shared/DaemonSync.swift` client (see [integration architecture](integration-architecture.md#mac-leash--leash-core)).

## 3. Package map

### 3.1 Enforcement core

| Package | Public surface (selected) | Notes |
|---|---|---|
| `internal/lsm` | `LSMManager`, `PolicySet`, `PolicyRule`, `MCPPolicyRule`, `SharedLogger`, `ConvertToFileOpenRules`, `ConvertToExecRules`, `ConvertToConnectRules` | Owns three modules (Open/Exec/Connect). Each module loads a BPF program, owns a ringbuf, and writes its rule table on `UpdateRuntimeRules`. |
| `internal/cedar` | `CompileFile`, `CompileString`, `Compilation`, `ErrorDetail` | Wraps `cedar-go` parsing; formats parse errors with line/column/snippet/suggestion. |
| `internal/cedar/autocomplete` | `Complete()`, `CompletionItem`, `ReplaceRange` | Backs `/api/policies/complete`. Hint merge happens in `policyAPI` (see [`design/AUTOCOMPLETE.md`](design/AUTOCOMPLETE.md)). |
| `internal/transpiler` | `CedarToLeashTranspiler`, `TranspilePolicySet`, `LintFromString` | Cedar AST → `(lsm.PolicySet, []proxy.HeaderRewriteRule, []Issue, error)`. Per-`Action` dispatch and MCP special-case (forbid McpCall → both MCP rule + `net.send` deny) live here. Has its own [README](../internal/transpiler/README.md). |
| `internal/policy` | `Manager`, `WatchCedar`, `Snapshot`, `UpdateFileRules`, `SetRuntimeRules`, `AddRule`, `RemoveRule` | Two-layer rule store (file + runtime). `applyChanges` pushes merged rules to LSM and proxy in lock-step. Cedar file change → `WatchCedar` poller → `UpdateFileRules` → `applyChanges`. |
| `internal/proxy` | `MITMProxy`, `CertificateAuthority`, `HeaderRewriter`, `mcpObserver`, `PolicyChecker` | iptables-redirected MITM. CA: public cert in `/leash`, private key in `/leash-private` (see [`design/SECURITY-MODEL.md`](design/SECURITY-MODEL.md)). SO_MARK 0x2000 prevents proxy→proxy loop. HTTP/2 ALPN tunneling. MCP observer parses JSON-RPC + SSE. |
| `internal/messages` | `Envelope`, payload types (`MacPIDSyncPayload`, `MacRulesSyncPayload`, `MacPolicyEventPayload`, `MacPolicyDecisionPayload`, `MacMITMConfigPayload`, …), `WrapPayload`, `UnmarshalPayload` | Wire format for `mac.*` WebSocket envelopes. |

### 3.2 Control plane

| Package | Public surface | Notes |
|---|---|---|
| `internal/leashd` | `Main(args)`; package-private `runtimeState`, `policyAPI`, `suggestAPI` | Daemon entry + HTTP wiring. `runtime.go` holds lifecycle; `http_api.go` (~2800 LOC) holds the full Cedar/LSM/UI surface. |
| `internal/darwind` | `Main(args)`; `parseConfig`, `initRuntime`, `Run` | macOS counterpart. Reuses websocket/policy/proxy/macsync. |
| `internal/httpserver` | `NewWebServer(addr, handler)` | Returns `*http.Server` with sensible timeouts (30s/30s/2m). |
| `internal/websocket` | `WebSocketHub`, `NewWebSocketHub`, `HandleWebSocket`, `LogEntry`, `ClientMessage` | Ring buffer + bulk dump on connect + heartbeat. |
| `internal/ui` | `SPAHandler`, `NewSPAHandler`, `NewSPAHandlerWithTitle` | Embeds `dist/**` via `//go:embed`. Falls back to `index.html` for client-routed paths; injects `<title>`. |
| `internal/openflag` | `Enabled`, `IsTruthy` | Browser auto-open gate. |
| `internal/assets` | `ApplyIptablesScript`, `ApplyIp6tablesScript`, `ApplyNftablesScript`, `LeashPromptScript` | Embedded shell scripts for iptables/nftables redirection rules and the interactive prompt. |
| `internal/log2cedar` | `Generator`, `Ingest`, `Render` | Event log → Cedar proposal. Backs `/suggest`. |
| `internal/telemetry/otel` | `Setup`, `Provider`, `MCPInstruments`, `LoadConfigFromEnv` | Stdout exporter by default; OTLP if `LEASH_OTEL_ENDPOINT` set. |
| `internal/telemetry/statsig` | `Configure`, `Start`, `Stop`, `IncPolicyUpdate`, `RecordPolicyUpdate` | Opt-out via `LEASH_DISABLE_TELEMETRY`. |

### 3.3 Orchestration & bootstrap

| Package | Public surface | Notes |
|---|---|---|
| `internal/runner` | `Main(args)`, `ExitCodeError`, `SetVersion` | Host CLI. Docker detection, volume construction, double-container launch, bootstrap watcher, teardown. |
| `internal/entrypoint` | `InflateBinaries(dir)`, `ReadyFileName`, `BootstrapReadyFileName`, `LocateExternalLeashEntry` | Decompresses embedded leash-entry binaries; fallback to `LEASH_ENTRY_BIN`, `/usr/local/bin/leash-entry`, or `$PATH`. |
| `internal/configstore` | `Load`, `LoadWithOverlay`, `Save`, `GetEffectiveVolume`, `GetTargetImage`, `ResolveEnvVars`, `ResolveCustomVolumes`, `ComputeExtraMountsFor`, `GetLocalConfigPath` | TOML config with project overlay; full schema in [`data-models-leash-core.md`](data-models-leash-core.md#5-persisted-config-configstore) and [`docs/CONFIG.md`](CONFIG.md). |
| `internal/macsync` | `Manager`, `NewManager`, `RegisterClient`, `UpdateTrackedPIDs`, `UpdateRules`, `ConvertPolicyToMacRules` | Holds per-client state (PID snapshot, rule snapshot, MITM snapshot). Receives `mac.*` envelopes; broadcasts rule deltas. |

## 4. Cedar → IR → enforcement pipeline

End-to-end, with file:line anchors (sampled — verify before relying):

```
Cedar source file               →  cedar.CompileFile               (internal/cedar/compile.go)
  │                                  │
  │  cedar-go parser                 ▼
  ▼                                CedarPolicySet (AST)
*.cedar text                        │
                                    ▼
                              transpiler.TranspilePolicySet         (internal/transpiler/cedar_to_leash.go)
                                    │
                  ┌─────────────────┼──────────────────────┐
                  ▼                 ▼                      ▼
        lsm.PolicySet      []proxy.HeaderRewriteRule    []lsm.MCPPolicyRule
            │                       │                      │
            ▼                       ▼                      ▼
  lsm.Manager.UpdateRuntimeRules    proxy.HeaderRewriter   proxy.PolicyChecker
            │                       │                      │
            ▼                       ▼                      ▼
   BPF maps (policy_rules,    in-mem rule slice      MITMProxy.CheckMCPCall()
   num_policy_rules, dns_cache)
            │
            ▼
   Kernel evaluates on every file_open / bprm_check_security / socket_connect hook
```

Hot reload path:

```
policy.Manager.UpdateFileRules / SetRuntimeRules / AddRule / RemoveRule
     │
     ▼  (RWLock + atomic swap)
applyChanges(activeRules, activeHTTPRules)
     │
     ├──> lsm.Manager.UpdateRuntimeRules(activeRules)        # rewrites BPF maps in place
     ├──> headerRewriter.SetRules(activeHTTPRules)           # swaps in-memory slice
     └──> wsHub.EmitJSON("policy.snapshot", response)        # broadcasts to UI + mac shim
```

Notable invariants (from the agent report; verify before relying on edge cases):

- Deny-by-default for `file.open` and `proc.exec`; connect default tracks `ConnectDefaultAllow`/`ConnectExplicitAll`.
- BPF programs short-circuit non-monitored cgroups via `allowed_cgroups` lookup.
- `forbid Action::"McpCall"` on a server transpiles to both an MCP rule *and* a `net.send` deny.
- `permit Action::"McpCall"` is informational only in v1 → linter emits `mcp_allow_noop`.
- HTTP rewrites do not currently hot-reload via the file watcher (rules loaded at boot from `rewrite.conf`-style config).

## 5. Runtime wiring at a glance

```
leashd.Main
 └─ initRuntime
     ├─ lsm.NewSharedLogger ─┐
     ├─ websocket.NewWebSocketHub(logger, bufferSize)        # subscribes to logger
     │   └─ go hub.Run()
     ├─ lsm.NewLSMManager(cgroupPath, logger)
     ├─ proxy.NewHeaderRewriter
     ├─ otel.Setup(ctx, LoadConfigFromEnv) → Provider
     ├─ policy.Parse(policyPath) → (LSMPolicies, HTTPRules)
     ├─ proxy.NewMITMProxy(port, rewriter, checker, logger, mcpInstruments)
     └─ policy.NewManager(lsmManager, proxyUpdater)
 └─ Run
     ├─ startFrontend
     │   ├─ mux.HandleFunc("/api", wsHub.HandleWebSocket)
     │   ├─ newPolicyAPI(mgr, path, wsHub, mitmProxy, wsHub).register(mux)
     │   ├─ newSuggestAPI(mgr, wsHub).register(mux)
     │   ├─ mux.HandleFunc("/healthz", ...)
     │   ├─ mux.Handle("/", spaHandler)
     │   └─ httpserver.NewWebServer(bind, mux).ListenAndServe()
     ├─ waitForBootstrap                       # polls /leash/bootstrap.ready
     └─ activate
         ├─ startPolicyWatcher                 # WatchCedar polling loop
         ├─ lsmManager.LoadAndStart            # attaches BPF programs
         └─ go mitmProxy.Run                   # serves on LEASH_PROXY_PORT (18000)
```

## 6. Where complex things live (quick index)

- **eBPF C source:** `internal/lsm/bpf/{lsm_open,lsm_exec,lsm_connect}.bpf.c` — generated via `make lsm-generate` (Docker on non-Linux hosts).
- **MITM CA generation:** `internal/proxy/ca.go` — public-private split enforced via `LEASH_PRIVATE_DIR`.
- **MCP observer:** `internal/proxy/mcp_observer.go` — body inspection capped at 1MB, hint snapshots capped at 32.
- **Cedar completion engine:** `internal/cedar/autocomplete/` — see [`design/AUTOCOMPLETE.md`](design/AUTOCOMPLETE.md) for the React→Go round-trip.
- **Bootstrap orchestration:** `cmd/leash-entry/main.go` (target side) + `internal/leashd/runtime.go:waitForBootstrap` (manager side). Schema in [`design/BOOT.md`](design/BOOT.md).
- **Suggest pipeline:** `internal/policy/suggest/` + `internal/log2cedar/` — backs `GET /suggest`.
- **Test fixtures:** `e2e/mcpserver/` (test MCP stub) + `e2e/integration/` (containerized enforcement scenarios).

## 7. Operating modes

| Mode | Default policy map value | LSM behaviour | Use case |
|---|---|---|---|
| `record` | always-allow | All hooks observe + log, none deny | Initial deployment / learning |
| `shadow` | observe-deny | Hooks evaluate but never deny; events carry `would_deny: true` | Validating new rules pre-cutover |
| `enforce` | enforce | Hooks deny per policy | Production |

Mode is a BPF map value → live transitions, no daemon restart needed. Toggled via `POST /api/policies/permit-all` / `POST /api/policies/enforce-apply` from the Control UI.
