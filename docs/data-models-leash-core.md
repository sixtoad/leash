# Data Models — leash-core

Cross-cutting model reference for everything persisted, exchanged, or pushed into the kernel. Not an ORM map — leash has no database; "data" lives in Cedar files, BPF maps, in-memory snapshots, TOML config, and message envelopes.

## 1. Cedar policy source (authoritative state)

**On-disk format:** Cedar 4.x policy language, single text file.

**Default location:** `$LEASH_POLICY` or `--policy` (typical: `/cfg/leash.cedar` inside the manager container).

**Persistence rule:** Cedar is the *only* policy artifact persisted to disk. Leash IR is generated in memory and never written. See [`design/CEDAR.md`](design/CEDAR.md) for full syntax and [`design/ARCHITECTURE.md`](design/ARCHITECTURE.md#policy-language-cedar-integration) for the rationale.

### Supported `Action` identifiers and resource entity types

| Action | Resource entity types | IR operation |
|---|---|---|
| `Action::"FileOpen"` | `Dir::"/path/"`, `File::"/path"` | `file.open` |
| `Action::"FileOpenReadOnly"` | same | `file.open:ro` |
| `Action::"FileOpenReadWrite"` | same | `file.open:rw` |
| `Action::"ProcessExec"` | `Dir::"/path/"`, `File::"/path"` | `proc.exec` |
| `Action::"NetworkConnect"` | `Host::"name"`, `Host::"*.example.com"`, `Host::"ip:port"` | `net.send` |
| `Action::"HttpRewrite"` | `Host::"host"` (with `context.header` + `context.value`) | `http.rewrite` |
| `Action::"McpCall"` | `MCP::Server::"host"`, `MCP::Tool::"tool"` | `mcp.*` |

## 2. Leash IR (in-memory)

Produced by `internal/transpiler/cedar_to_leash.go:TranspilePolicySet`; consumed by `internal/lsm`, `internal/proxy.HeaderRewriter`, and `internal/proxy.PolicyChecker`.

### `lsm.PolicySet` — root container (`internal/lsm/common.go`)
```go
type PolicySet struct {
    Open    []PolicyRule       // file open rules
    Exec    []PolicyRule       // process exec rules (may include Args blacklist for denies)
    Connect []PolicyRule       // network connect rules
    MCP     []MCPPolicyRule

    ConnectDefaultAllow bool   // tracks implicit vs explicit net posture
    ConnectExplicitAll  bool
}
```

### `lsm.PolicyRule` — universal rule
```go
type PolicyRule struct {
    Action    int8   // 1 = allow, 0 = deny
    Operation string // "open", "open:ro", "open:rw", "exec", "connect"
    Path      string // file/dir path or exec path
    PathLen   uint32
    DestIP    [16]byte
    DestPort  uint16
    Hostname  string
    ArgCount  uint32
    Args      [4][32]byte    // exec deny argument patterns (max 4 args, 32 bytes each)
    ArgLens   [4]uint32
}
```

### `lsm.MCPPolicyRule`
```go
type MCPPolicyRule struct {
    Action int8    // 1 = allow, 0 = deny
    Server string  // empty = wildcard
    Tool   string  // empty = wildcard
}
```

### Module-specific BPF rule formats

The generic `PolicyRule` is converted to fixed-size structs that match the C definitions in `internal/lsm/bpf/*.bpf.c` so they can be memcpy'd into BPF array maps:

- `OpenPolicyRule` (`file_open.go`): `{action, op, PathLen, Path[256], IsDirectory}`
- `ExecPolicyRule` (`proc_exec.go`): `{action, op, Path[256], PathLen, ArgCount, Args[4][32], ArgLens[4]}`
- `ConnectPolicyRule` (`net_connect.go`): `{action, op, DestIP, DestPort, Hostname[128], HostnameLen, IsWildcard}` — hostnames also resolved to IPs and cached in `dns_cache` BPF hash map.

### `proxy.HeaderRewriteRule`
```go
type HeaderRewriteRule struct {
    Host   string  // case-insensitive hostname match
    Header string  // canonical header name
    Value  string  // value to inject (secret material)
}
```

## 3. BPF maps (kernel-resident)

Populated by `internal/lsm/manager.go` after each policy reload. Maximum 256 rules per operation type (eBPF verifier limit; can be raised by splitting programs).

| Map | Type | Purpose |
|---|---|---|
| `allowed_cgroups` | hash | Cgroup IDs the BPF programs should evaluate; other cgroups bypass. |
| `policy_rules` | array (per program) | Rule table read on each hook invocation. |
| `num_policy_rules` | array (size 1) | Current count of valid rules in `policy_rules`. |
| `default_policy` | array (size 1) | Mode toggle (`record` / `shadow` / `enforce`). Atomic update enables live mode change. |
| `dns_cache` | hash | IP → hostname for connect-event annotation. |
| `target_cgroup` | array (size 1) | Connect-hook enable flag. |
| `events` | ringbuf | Per-program ring buffer for event streaming. |

## 4. WebSocket event envelope (`/api`)

Two distinct schemas share the `/api` WebSocket transport:

**A. UI-facing LSM/proxy events** (`internal/websocket/hub.go:LogEntry`):
```jsonc
{
  "event":     "proc.exec | file.open | connect | mcp.tools/call | http.rewrite | leash.hello | leash.heartbeat | policy.snapshot",
  "timestamp": "2026-05-26T12:34:56.789Z",
  "decision":  "allowed | denied",
  "pid":       4321,
  "tgid":      4321,
  "comm":      "claude",
  "exe":       "/usr/local/bin/claude",
  "path":      "/workspace/secrets/.env",
  "addr":      "1.2.3.4:443",
  "hostname":  "api.anthropic.com",
  "reason":    "policy: forbid Dir::\"/workspace/secrets/\" ...",
  "header":    "Authorization",       // http.rewrite only
  "tool":      "...", "server": "...", // mcp.* only
  "seq":       12345
}
```

**B. Mac shim envelopes** (`internal/messages/messages.go:Envelope`):
```go
type Envelope struct {
    Type      string          // "mac.pid.sync", "client.hello", ...
    Version   string
    SessionID string
    ShimID    string
    RequestID string
    Payload   json.RawMessage  // discriminated by Type — see api-contracts-leash-core.md § Mac envelopes
}
```

## 5. Persisted config (`configstore`)

Two-tier TOML; user file plus optional per-project overlay (commit `fd8e0c1` added the overlay).

**Global file:** `$XDG_CONFIG_HOME/leash/config.toml` (or `~/.config/leash/config.toml`).
**Per-project overlay:** `.leash.toml` in the current working directory.

```toml
[leash]
target_image = "ghcr.io/example/dev:latest"   # global default

[leash.envvars]                                # injected into both containers
OPENAI_API_KEY = "sk-..."
DOTENV_PATH    = "/workspace/.env"

[volumes]                                      # global tool-mount toggles
codex   = true                                 # mount ~/.codex
claude  = false
"~/devtools" = "/workspace/devtools:ro"        # custom bind

[projects."/Users/alice/src/app"]              # per-project overrides
codex = true
target_image = "ghcr.io/example/app-dev:latest"

[projects."/Users/alice/src/app".volumes]
"./.dev" = "/workspace/dev:rw"
"~/devtools" = false                           # suppress an inherited global volume

[projects."/Users/alice/src/app".envvars]
DOTENV_PATH = "/workspace/app/.env"
BACKEND_URL = "http://localhost:4000"
```

**Precedence (highest wins):** CLI flags / `-e KEY=value` → project overlay → global config → auto-detected host env. See [`docs/CONFIG.md`](CONFIG.md) for the full schema and prompt workflow.

Public API (`internal/configstore`): `Load`, `LoadWithOverlay(dir)`, `Save`, `GetEffectiveVolume`, `GetTargetImage`, `ResolveEnvVars`, `ResolveCustomVolumes`, `ComputeExtraMountsFor`.

## 6. macOS rule models (`mac-leash/Shared/`)

Equivalent of LSM rules for the macOS native path. Produced from Cedar by `internal/macsync/translator.go:ConvertPolicyToMacRules`.

```swift
struct LeashPolicyEvent {
    let id: UUID, timestamp: Date
    enum Kind { case processExec, fileAccess }
    enum FileOperation { case open, create, write }
    let kind: Kind
    let processPath: String, processArguments: [String]
    let currentWorkingDirectory, filePath, parentProcessPath, ttyPath: String?
    let fileOperation: FileOperation?
    let leashProcessPath: [String]?           // chain back to original leash CLI invocation
    let pid, parentPid: Int32
}

struct LeashPolicyDecision {
    enum Action { case allow, deny }
    enum Scope  { case once, always, directory(String) }
    let eventID: UUID
    let action: Action
    let scope:  Scope
}

struct LeashPolicyRule {
    let kind: LeashPolicyEvent.Kind
    let action: LeashPolicyDecision.Action
    let executablePath, directory, filePath: String?
    let coversCreates: Bool
    func matches(_ event: LeashPolicyEvent) -> Bool
}

struct NetworkRule: Identifiable {
    enum Action { case allow, deny }
    enum Target { case domain(String), ipAddress(String), ipRange(String) }
    let id: UUID; let name: String
    let action: Action; let target: Target
    let currentWorkingDirectory: String?       // optional CWD scope
    let enabled: Bool; let createdAt: Date
}
```

## 7. Bootstrap markers (`/leash` shared volume)

Plain files exchanged between target container and manager (see [`design/BOOT.md`](design/BOOT.md)).

| File | Mode | Producer | Consumer | Format |
|---|---|---|---|---|
| `/leash/leash-entry-linux-{amd64,arm64}` | 0755 | runner (extracts from embed) | target | binary |
| `/leash/leash-entry.ready` | 0644 | runner | leash-entry inside target | empty marker |
| `/leash/bootstrap.ready` | 0644 | leash-entry inside target | leashd | JSON `{ pid, hostname, timestamp }` |
| `/leash/cgroup-path` | 0644 | leash-entry inside target | leashd | one-line cgroup path (`/sys/fs/cgroup/...`) |
| `/leash/ca-cert.pem` | 0644 | leashd | target (added to trust store) | PEM cert |
| `/leash-private/ca-key.pem` | 0600 | leashd | leashd only (manager-private) | PEM RSA-2048 key |

## 8. Telemetry payloads

**Statsig** (`internal/telemetry/statsig`, see [`docs/TELEMETRY.md`](TELEMETRY.md)):
- `leash.start` — `{ os, arch, mode, version, has_subcommand, flag_<name>: bool, workspace_id (SHA-256 of cwd), session_id }`
- `leash.session` — `{ duration_s, policy_updates, policy_update_errors, workspace_id, session_id }`

**OpenTelemetry** (`internal/telemetry/otel`, MCP-focused):
- Counters: `mcp.requests_total`, `mcp.errors_total`
- Histogram: `mcp.request.duration` (ms)
- Spans: per MCP method (`mcp.tools/call:<tool_name>`) with attrs `mcp.server`, `mcp.method`, `mcp.tool`, `http.status_code`, `outcome`
- Optional W3C TraceContext propagation via `LEASH_OTEL_PROPAGATE_HTTP_HEADERS`

## 9. Cedar error detail

Returned by validate/persist/add when parsing fails. Surfaced inline in the Monaco editor.
```go
type ErrorDetail struct {
    Summary    string
    Message    string
    File       string
    Line, Column int
    Snippet    string
    Suggestion string
    Code       string // "unsupported_principal", "mcp_allow_noop", "resource_mismatch", ...
}
```
