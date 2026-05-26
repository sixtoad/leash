# API Contracts — leash-core

All endpoints are exposed by the daemon (`leashd` in Linux containers, `darwind` on macOS native) on the address controlled by `--listen` / `LEASH_LISTEN` (default `:18080`). Both bind the same routes; macOS does not run the local MITM proxy.

The Next.js Control UI is embedded into the Go binary at `internal/ui/dist` and served by `SPAHandler` (`internal/ui/handler.go`) at `/`. Everything not under a registered API path falls through to the SPA.

> **Cross-references:** Cedar policy syntax → [`design/CEDAR.md`](design/CEDAR.md). Completion design → [`design/AUTOCOMPLETE.md`](design/AUTOCOMPLETE.md). Bootstrap lifecycle → [`design/BOOT.md`](design/BOOT.md). CA + secrets boundary → [`design/SECURITY-MODEL.md`](design/SECURITY-MODEL.md).

## Health & Liveness

| Method | Path | Purpose | Response |
|---|---|---|---|
| `GET` | `/healthz` | Liveness | `200 ok` |
| `GET` | `/health/policy` | Policy ready (post-bootstrap, post-activation) | `200 ready` or `503 not ready` |

## Cedar Policy CRUD — `policyAPI`

Defined in `internal/leashd/http_api.go`. All bodies are JSON unless noted.

| Method | Path | Body | Response | Purpose |
|---|---|---|---|---|
| `GET` | `/api/policies` | — | `PoliciesResponse` | Fetch active + runtime + file layers, current Cedar source, enforcement mode. |
| `POST` | `/api/policies` | `{ cedar: string }` | `PoliciesResponse` | Replace runtime overlay wholesale. |
| `PATCH` | `/api/policies` | `{ add?: PatchAdd[], remove?: PatchRemove[], applyMode? }` | `PoliciesResponse` | Incremental edits. |
| `POST` | `/api/policies/persist?force=1` | `{ cedar?: string }` (body optional) | `PoliciesResponse` | Write current Cedar to the policy file (source-of-truth). |
| `POST` | `/api/policies/validate` | `{ cedar?: string }` | `ValidateSummary` | Compile-only — returns rule counts + linter issues, no side effects. |
| `POST` | `/api/policies/complete` | `CompletionRequest` | `CompletionResponse` | Monaco autocomplete (see § Completion below and [design/AUTOCOMPLETE.md](design/AUTOCOMPLETE.md)). |
| `POST` | `/api/policies/permit-all` | — | `PoliciesResponse` (mode=`permit-all`) | Enable permissive runtime overlay. |
| `POST` | `/api/policies/enforce-apply` | — | `PoliciesResponse` (mode=`enforce`) | Drop overlays, re-enforce file layer. |
| `GET` | `/api/policies/lines` | — | `{ lines: PolicyLine[] }` | Cedar parsed into UI-friendly lines (id, effect, humanized text, sequence). |
| `POST` | `/api/policies/add` | `{ cedar: string }` | `PoliciesResponse` | Append a statement (idempotent). |
| `POST` | `/api/policies/add-from-action` | `{ effect: "permit"\|"forbid", action: {type, name, tool?, server?} }` | `PoliciesResponse` | Build Cedar from a captured event. |
| `POST` | `/api/policies/delete` | `{ id?: string, cedar?: string }` | `PoliciesResponse` | Remove by line id or by literal source. |

### `PoliciesResponse` shape
```jsonc
{
  "cedar": "permit (...) ...",            // operative source
  "cedarRuntime": "...",
  "cedarFile": "...",
  "cedarBaseline": "...",                  // shipped default
  "enforcementMode": "enforce|permit-all|shadow|record",
  "lsm":  { "open": [...], "exec": [...], "connect": [...] },
  "http": { "rewrites": [...] }
}
```

### `ValidateSummary` shape
Counts per action-type and lint issues:
```jsonc
{
  "allowOpen": 4, "allowExec": 2, "allowConnect": 1,
  "denyOpen":  0, "denyExec":  1, "denyConnect": 0,
  "allowAllConnect": false,
  "issues": [{ "policyId": "...", "severity": "error|warning",
               "code": "mcp_allow_noop|unsupported_principal|...",
               "message": "...", "suggestion": "..." }]
}
```

### `CompletionRequest` / `CompletionResponse`
```jsonc
// Request
{
  "cedar":  "permit (principal, action == , resource);",
  "cursor": { "line": 1, "column": 33 },
  "maxItems": 50,                          // optional cap
  "idHints": { "tools": [...], "servers": [...] }  // optional client hints, merged after server hints
}
// Response (always 200; malformed Cedar yields empty items)
{
  "items": [
    {
      "label": "Action::\"FileOpen\"",
      "kind":  "keyword|action|entityType|resource|conditionKey|snippet|tool|server|header",
      "insertText": "Action::\"FileOpen\"",
      "detail": "Allow reading or writing files (per v1 semantics)",
      "documentation": "Maps to LSM file open rules.",
      "range": { "start": {"line": 1, "column": 29}, "end": {"line": 1, "column": 33} },
      "sortText": "...",
      "commitCharacters": [","]
    }
  ]
}
```
Hint sources blended server-side (priority order):
1. `policy.Manager` snapshot (files, dirs, hosts, MCP servers/tools, HTTP headers in active policy)
2. MITM proxy's `mcp_observer` recent servers/tools (capped 32 each)
3. WebSocketHub recent HTTP metadata (hostnames, header names)
4. Client `idHints` (lowest priority)

## Suggest API

| Method | Path | Query | Response |
|---|---|---|---|
| `GET` | `/suggest` | `tail=<int>`, `window=<duration>` | `{ generated_at, event_count, sequence_count, suggestions: [...] }` |

Backed by `internal/policy/suggest` + `internal/log2cedar.Generator`. Reads recent events from the WebSocketHub ring buffer, groups by action+resource, emits Cedar policy proposals.

## WebSocket — `/api`

Single endpoint; upgrades GET → WebSocket. Implemented by `WebSocketHub` (`internal/websocket/hub.go`).

**Transport.** Text frames containing NDJSON. The first frame after handshake is a bulk dump of buffered history (configurable via `bulkMaxEvents` / `bulkMaxBytes`, default ~25k events).

**Server → client message types:**

| `event` | Trigger | Notable fields |
|---|---|---|
| `leash.hello` | On hub init | `startedAt` |
| `leash.heartbeat` | Every 10s | `uptime_s`, `last_seq` |
| `policy.snapshot` | After any policy CRUD | Full `PoliciesResponse` payload |
| `proc.exec`, `file.open`, `connect` (et al.) | Every LSM decision | `pid`, `tgid`, `comm`, `exe`/`path`/`addr`, `hostname`, `decision`, `reason`, `seq` |
| `mcp.*` | MITM MCP observer | `server`, `tool`, `method`, decision |
| `http.rewrite` | Header rewriter fired | `host`, `header` |

**Client → server.** Free-form text payloads parsed by `hub.Incoming()`. Today consumed by the suggest pipeline and reserved for future real-time subscriptions. The mac-leash WebSocket client sends a separate set of envelopes — see § Mac envelopes below — but uses the same `/api` upgrade.

**Heartbeat.** Hub emits a heartbeat every 10s; clients should reconnect if no frame seen within ~30s.

## Mac envelopes (Go ↔ Swift, over `/api`)

The same `/api` WebSocket is the transport between `Shared/DaemonSync.swift` and `internal/macsync/manager.go`. Envelopes are typed by `Envelope.Type` (`internal/messages/messages.go`).

**Inbound to daemon (from extensions/app):**

| Type | Payload (selected fields) | Purpose |
|---|---|---|
| `client.hello` | `ClientHelloPayload{ shim_id, platform, capabilities, version }` | Register a client (Swift app, ES, NF). |
| `mac.pid.sync` | `MacPIDSyncPayload{ entries: [{pid, leash_pid, executable, tty_path?, cwd?}] }` | Push tracked-PID snapshot. |
| `mac.rule.sync` | `MacRuleSyncPayload{ file_rules, exec_rules, network_rules, version }` | Push macOS rule snapshot. |
| `mac.policy.event` | Full `LeashPolicyEvent` (process exec or file access with leash context) | Request a decision. |
| `mac.policy.decision` | `LeashPolicyDecision{ event_id, action, scope }` | Confirm/override a decision. |
| `mac.network_rule.update` | `{ rules: [MacNetworkRule] }` | NF pushes/changes per-flow rules. |
| `mac.rule.add` / `remove` / `clear` / `query` | Rule mutations | CRUD on cached rule set. |
| `mac.event` | `{ time, event, details?, severity?, source?, rule_id? }` | Telemetry / audit. |

**Outbound from daemon (broadcast):** `mac.policy.decision`, `mac.rule.snapshot`, `mac.network_rule.update`, `mac.pid.sync`, plus the standard LSM-style events also broadcast to web clients.

## Embedded SPA fallthrough

Everything not matching above resolves under `SPAHandler` (`internal/ui/handler.go`):

- `/_next/static/*` → static file from `embed.FS`, `Cache-Control: public, max-age=31536000, immutable`
- Other static asset → served from embed.FS
- Anything else (e.g. `/policies`, `/events`) → `index.html` with `Cache-Control: no-store` and a dynamic `<title>` injected by `injectTitle`.

## Notable header & error conventions

- All API responses set `Content-Type: application/json` unless noted.
- Errors carry `{ "error": { "message": "...", "detail"?: { "line": int, "column": int, "code": string, "suggestion": string } } }` (Cedar parse errors populate `detail`).
- `validate` always returns `200` — issues live inside the body so the editor can render them as markers.
- `complete` always returns `200` with `items` (empty on malformed input, comment context, or zero hints).
- No CSRF/auth today — the listener defaults to `127.0.0.1:18080`. Operators that change `--listen` to a non-loopback address are responsible for fronting it with auth.
