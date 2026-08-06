# API Contracts — leash-core

All endpoints are exposed by the daemon (`leashd` in Linux containers, `darwind` on macOS native) on the address controlled by `--listen` / `LEASH_LISTEN` (default `:18080`). Both bind the same routes; macOS does not run the local MITM proxy.

The Next.js Control UI is embedded into the Go binary at `internal/ui/dist` and served by `SPAHandler` (`internal/ui/handler.go`) at `/`. Everything not under a registered API path falls through to the SPA.

Two contracts here are not endpoints. [§ CLI build contract](#cli-build-contract--leash-version---json) covers `leash version --json`, the document a provisioner reads from an *installed binary* before it drives anything else; [§ Node readiness](#node-readiness--leash-doctor---json) covers `leash doctor --json`, which answers the next question — whether the machine that binary is installed on can actually enforce.

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

## CLI build contract — `leash version --json`

Not an endpoint: this is the document an installed binary emits on stdout, for provisioners (`walk install leash`, CI images) that must decide whether the leash they just installed is one they can drive. `leash version` with no flag prints the historical human lines instead.

**The document is the contract. There is no package to import.** leash publishes no Go module for this on purpose — the rule below is three lines in any language, and a published package would bind this module (already tagged `v1.1.7`) to a permanent v1 Go API. Decode the JSON into a type of your own.

```jsonc
{
  "version": "v0.2.0",              // -X main.version, or "dev" on a plain `go build`
  "commit": "c686025-dirty",        // abbreviated hex hash, optionally "-dirty"; or "dev"; or "unknown"
  "builtAt": "2026-07-21T10:11:12Z",// RFC 3339 UTC, or "unknown"
  "enforcing": true,                // does THIS BUILD carry an enforcement path
  "contractVersion": 1,             // current CLI surface
  "minCompatibleContract": 0,       // oldest caller contract still served
  "capabilities": [                 // surface elements a provisioner can drive
    "policy", "inject-service", "runtime", "user", "require-lsm", "version-json"
  ],
  "os": "linux", "arch": "amd64"    // GOOS / GOARCH
}
```

Field names are camelCase and additive-only: renaming or removing one is a contract break, adding one is not.

Value domains a caller must accept rather than reject:

- `version` — a release tag, a `git describe` string (which may end `-dirty`), or the literal `dev`.
- `commit` — an abbreviated hex hash, optionally suffixed `-dirty`; or the literal `dev`; or the literal `unknown`. All three are legitimate builds.
- `builtAt` — RFC 3339 UTC, or the literal `unknown`.

`dev` and `unknown` are documented sentinels, not errors: `unknown` is the ldflag default in `cmd/leash`, and `dev` is both `main.version`'s default and what the build paths substitute for `commit` when `git rev-parse` fails.

**The `-dirty` marker is best-effort and not guaranteed on any given path.** Today only the Makefile `build` target appends it; `scripts/release.sh`, `scripts/install-leash.sh`, `build/publish-docker.sh` and `.goreleaser.yaml` stamp the bare hash. Its presence means the tree was modified; **its absence is not proof of a clean tree** and must not be treated as a provenance guarantee.

**Compatibility rule.** The contract covers the flags a provisioner drives (`--policy`, `--inject-service`, `--runtime`, `--user`, `--require-lsm`) plus the shape of this document. A caller written against contract `C` proceeds iff:

```
minCompatibleContract <= C <= contractVersion
```

| Situation | Verdict | Meaning |
|---|---|---|
| `minCompatibleContract <= C <= contractVersion` | `compatible` | Drive it. |
| `C > contractVersion` | `leash-too-old` | Leash predates the surface the caller needs — upgrade leash. |
| `C < minCompatibleContract` | `leash-too-new` | Leash dropped the surface the caller was written against — upgrade the caller. |
| `version --json` absent / non-zero exit / unparseable | contract `0` | A leash from before this feature; not an install error. |

The rule is the two-sided range above, and `contractVersion >= C` alone is **not** it: that test is necessary but not sufficient, because it also admits a leash whose `contractVersion` is above `C` *and* whose `minCompatibleContract` has since risen past `C` — the leash that dropped `C`'s surface. Both bounds must be checked.

**Implementing it.** Run the *installed* binary, decode its stdout, compare. Language-agnostic:

```
doc = json_decode(run(leash_path, "version", "--json").stdout)   # non-zero exit or unparseable → contract 0
require(doc is an object and has "version" and "contractVersion") # else → contract 0
ok = doc.minCompatibleContract <= C <= doc.contractVersion        # C = the contract you were written against
```

The same thing in Go, with a struct of your own — no leash import:

```go
type leashDoc struct {
	Version               string   `json:"version"`
	ContractVersion       *int     `json:"contractVersion"` // pointer: absent must not read as 0
	MinCompatibleContract int      `json:"minCompatibleContract"`
	Capabilities          []string `json:"capabilities"`
}

const myContract = 1 // the contract this provisioner was written against

out, err := exec.Command(leashPath, "version", "--json").Output()
if err != nil {
	return errContractZero // not an install failure; see the probe hazard below
}
var doc leashDoc
if err := json.Unmarshal(out, &doc); err != nil || doc.Version == "" || doc.ContractVersion == nil {
	return errContractZero // `null`, `{}` and any non-document land here, not in a false "compatible"
}
if myContract < doc.MinCompatibleContract || myContract > *doc.ContractVersion {
	return fmt.Errorf("incompatible leash: contract %d outside [%d,%d]",
		myContract, doc.MinCompatibleContract, *doc.ContractVersion)
}
```

Two traps that snippet avoids. Decoding straight into value types makes `null`, `{}` and any unrelated JSON object succeed with a zero range `[0,0]`, which a contract-0 caller reads as *compatible* — so require the fields that make it this document before trusting the numbers. And never compare leash against constants compiled into the caller: that compares the caller to itself and can only pass. The installed binary's stdout is the only thing that can disagree with you.

`capabilities` is there because the integer over-refuses. Raising `minCompatibleContract` for one removal turns away every caller below the new floor, including those that never used the removed flag; a caller that drives only `--policy` can test for `"policy"` in the array instead of consulting the range at all. Adding a name is additive (no bump); removing one is a break (bump, and raise the floor). A pre-`capabilities` document decodes with the field empty — fall back to the range. The empty string is never a capability.

`enforcing` reports whether **this binary carries an enforcement path**, derived from the build's `GOOS`: `true` on linux (the eBPF LSM programs plus the intercepting MITM proxy) and `true` on darwin (the darwin runtime builds and drives the same MITM proxy — `internal/darwind/runtime_darwin.go`, `NewMITMProxy` / `applyPolicyToProxy` — alongside the separately installed Endpoint Security / Network Extension components it coordinates with). Any other target reports `false`. It describes the binary, not the host's runtime capability, which is `leash doctor`'s job.

**Probing an unknown leash has a hazard.** On a build that predates this feature, `version` is not a subcommand: the argument falls through to the workload CLI, which configures telemetry and can begin runtime provisioning. `leash version --json` is a side-effect-free probe only from contract 1 onward. Establish contract 0 some other way where possible — `leash --version` has been in the argument switch of every build and only prints three lines — or probe with `LEASH_DISABLE_TELEMETRY=1` in a disposable directory.

Full rationale, the bump rules, and which build path stamps what: [`DEVELOPMENT.md § Reporting the version at run time`](DEVELOPMENT.md#reporting-the-version-at-run-time).

## Node readiness — `leash doctor --json`

Also not an endpoint. `leash version --json` describes the *binary*; this describes the *machine*, per runtime, so a provisioner (`walk install leash`, a CI image build) can decide whether the node it just prepared can enforce before it hands an agent to it. `leash doctor` with no flag prints the same facts as human text.

```jsonc
{
  "verdict": "degraded",            // best state any runtime reaches: ready | degraded | unavailable
  "native": {                       // leashd as a host process in a systemd scope
    "status": "degraded",           //   ready | degraded | unavailable
    "ready": false,                 //   status == "ready"; never true for degraded
    "lsm_bpf": "inactive",          //   active | inactive | unknown — the active-LSM list read
    "lsm_bpf_attachable": "unknown",//   attachable | unattachable | unknown — observed, never inferred
    "caps": ["bpf", "net_admin"],   //   effective caps observed, never inferred; [] when unreadable
    "issues": ["…"]                 //   one actionable sentence + remedy per blocker
  },
  "container": {                    // docker/podman
    "status": "degraded",
    "ready": false,
    "engine": "docker",             //   null when no supported engine is on PATH
    "issues": ["…"]
  },
  "unchecked": [                    // prerequisites doctor did NOT verify (never silently omitted)
    { "name": "bpf_lsm_attachable", "reason": "…" }
  ],
  "default_runtime": "native"       // the runtime a bare `leash run` selects on this build
}
```

Field names are snake_case here (they were fixed by issue #23 before the camelCase `version --json` document existed) and additive-only. `caps`, `issues` and `unchecked` are always arrays, never `null`, however the report was produced; `engine` is the only field that can be `null`.

**`lsm_bpf_attachable` is a second, observed signal beside `lsm_bpf`, not a replacement for it.** Reading `bpf` out of `/sys/kernel/security/lsm` is cheap, and on its own it is a guess: a kernel can list `bpf` and still refuse leash's programs — the verifier can reject `bpf_d_path`, BTF can be absent, ring buffer creation can fail, or a program can exceed the instruction limit (leash's own hard-link guard hit that ceiling in issue #29). So doctor loads leash's *real* LSM programs, lets the kernel verify them, attaches one, and detaches it immediately (issue #52).

- `attachable` — the programs verified, attached and were detached again.
- `unattachable` — the kernel was asked and said no, and `issues` carries the kernel's own text plus the remedy for the step that failed (a **verifier** rejection means the kernel cannot run these programs at all; an **attach** rejection means the programs are fine and the kernel is not accepting BPF LSM attachments).
- `unknown` — nothing was observed. `unchecked` then carries `bpf_lsm_attachable` with the reason: `--quick` was passed, the process lacks CAP_BPF (loading a BPF LSM program needs root or `CAP_BPF`), the platform is not Linux, or the probe did not settle.

**The two signals are conjunctive: attachability only ever narrows the Layer 1 verdict, never widens it.** Both must be good for Layer 1 to count as available:

| `lsm_bpf` | `lsm_bpf_attachable` | Layer 1 |
|---|---|---|
| `inactive` / `unknown` | anything, **including `attachable`** | unavailable |
| `active` | `attachable` | available |
| `active` | `unattachable` | unavailable (the case the probe exists for) |
| `active` | `unknown` | falls back to the list: available |

`attachable` on a host whose list has no `bpf` does **not** mean Layer 1 works, and doctor does not report it that way. A `BPF_PROG_TYPE_LSM` program loads and attaches perfectly well on a `CONFIG_BPF_LSM=y` kernel that was not booted with `bpf` in `lsm=` — the attach succeeds, and the hook is never invoked, because the bpf LSM is not registered in the active stack. The `issues` text says so explicitly when the combination occurs, so the two fields never have to be reconciled by the reader.

`--quick` skips it. The opt-out is the flag rather than an opt-in, so the honest answer is the default one; the report always declares what a `--quick` run did not check. The probe leaves nothing attached and does not disturb a leash already enforcing on the host.

**The three states.** Two were not enough. A host whose container engine works but whose kernel has no active `bpf` LSM *will* start a workload — leash enforces the fail-closed egress proxy (Layer 2) while filesystem, exec and socket policy (Layer 1) is off. `ready` would be a false assurance and `unavailable` would hide a machine that still runs agents:

| `status` | leash will | Layer 1 (eBPF LSM) | Layer 2 (fail-closed proxy) |
|---|---|---|---|
| `ready` | run | enforced | enforced |
| `degraded` | run | **not enforced, or not verifiable** | enforced |
| `unavailable` | not run | — | — |

`ready` never widens to include `degraded`: it is the field a provisioner gates on.

**Exit codes.** The verdict is in the document *and* in the exit status, and they always agree.

| Code | Meaning | Remedy shape |
|---|---|---|
| `0` | a runtime enforces with both layers | none |
| `1` | no runtime can run a workload at all | install or repair a runtime |
| `2` | usage error — **including `--help`** | fix the invocation |
| `3` | a runtime runs, but Layer 1 is unavailable (proxy-only) | the runtime is fine, the kernel is not |
| `4` | doctor could not render or write its own report | not a verdict; retry / check the pipe |

Exit `0` is the answer to "can this machine enforce?", so `leash doctor && …` fails closed on `3`. `--help` deliberately exits `2`, not `0`: a provisioner gating on the status must not get a free pass from `leash doctor -help`.

**A `degraded` verdict is not always about the kernel.** Four conditions produce it, and the `issues` text says which:

- `bpf` is absent from `/sys/kernel/security/lsm` (`lsm_bpf: "inactive"`), or that list could not be read or was empty (`"unknown"`). This holds whatever the attach probe observed — see the conjunctive table above.
- The list says `bpf` is there and leash's LSM programs were loaded and refused anyway (`lsm_bpf: "active"`, `lsm_bpf_attachable: "unattachable"`) — the case the probe exists for.
- The host is not Linux. Containers then run against a VM kernel doctor never probed — Docker Desktop's LinuxKit kernel, for one, does not carry `bpf`. An unprobed kernel is never `ready`.
- `DOCKER_HOST` is set. The engine's containers run on a remote daemon's kernel, not the one doctor read, so the Layer 1 claim is withheld rather than borrowed. No remote topology is modelled; `unchecked` gains a `container_kernel` entry.

**`default_runtime` is not the verdict.** `verdict` is the best state *any* runtime reaches, but `leash run` with neither `--runtime` nor `LEASH_RUNTIME` selects exactly one runtime and never falls back. On this build that is `native`, so a Linux host with no systemd and a working docker reports `verdict: ready` while a bare `leash run` fails. Compare `default_runtime` against that runtime's `status` (`native` → `native.status`, `docker`/`podman` → `container.status`); the human output prints the same warning in prose.

**What doctor does not check** is in the document, not just in this page: `unchecked` always names `bpf_d_path_ringbuf` and `netns_iptables`, plus `bpf_lsm_attachable` whenever the attach probe did not settle it (`--quick`, insufficient privilege, non-Linux, timeout), `capabilities` when `/proc/self/status` was unreadable and `container_kernel` in the two cases above. A `ready` verdict must be read as exactly that list of things unverified.

Two caveats a script should know. Doctor writes its whole report in one `Write`, so a closed stdout (`leash doctor --json | head -1`) is reported as exit `4` — except that Go raises `SIGPIPE` on fd 1, so the process is more likely to die of the signal (`141` from a shell) than to reach that code; doctor does not trap signals to paper over this. And an engine probe that hangs is bounded by a 5 s timeout on `<engine> info`, after which the daemon is reported unreachable — the CLI is killed, but a grandchild the client itself spawned is not process-group-killed and may outlive it.

Decode it the way `version --json` is decoded: with a struct of your own. Go consumers inside this repo can decode into `doctor.Report` (the marshal/unmarshal pair round-trips exactly, and `verdict`/`ready` are recomputed from the statuses rather than trusted from the document), but the package is `internal/` and exports no importable type.

## Notable header & error conventions

- All API responses set `Content-Type: application/json` unless noted.
- Errors carry `{ "error": { "message": "...", "detail"?: { "line": int, "column": int, "code": string, "suggestion": string } } }` (Cedar parse errors populate `detail`).
- `validate` always returns `200` — issues live inside the body so the editor can render them as markers.
- `complete` always returns `200` with `items` (empty on malformed input, comment context, or zero hints).
- No CSRF/auth today — the listener defaults to `127.0.0.1:18080`. Operators that change `--listen` to a non-loopback address are responsible for fronting it with auth.
