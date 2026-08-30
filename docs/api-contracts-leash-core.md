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
| `GET` | `/health/darwin` | macOS enforcement facts only the daemon can see | `200` + JSON (always) |

`/health/darwin` is served by the `--darwin` runtime (`internal/darwind`) and read by `leash doctor` from outside the process. It reports observations, never verdicts — the daemon says what it has been told, doctor decides what it means, so a daemon and a doctor from different builds still agree on the facts.

```jsonc
{
  "components": ["leash.es", "leash.netfilter", "leash.proxy"],  // clients currently holding a websocket
  "full_disk_access": "granted",        // granted | denied | unknown — as LeashES last reported it
  "full_disk_access_at": "2026-08-19T09:12:44Z"  // omitted when nothing has been reported
}
```

Both fields answer questions nothing outside the daemon can. **`components`** is stronger than extension activation: an extension that is activated but absent here receives no PID or rule broadcasts, so it holds no policy and enforces nothing (#62). **`full_disk_access`** exists because macOS exposes no API for reading another process's TCC grant — `es_new_client` returns `ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED` without Full Disk Access, so only LeashES knows.

LeashES reports it two ways, and both are needed:

- **In every `client.hello`**, as the `full-disk-access` capability, added once `es_new_client` has succeeded. The hello is re-sent on each reconnect, so this survives a daemon restart.
- **As an event at startup** (`es.full_disk_access.ready`, or `es.full_disk_access.missing` immediately before it exits).

The event alone was not enough, and the gap was measured on the validation VM: it fires once per extension *process* launch, so a daemon started after the extensions — the normal case, since macOS launches extensions at boot — saw **zero** FDA events across 139 `leash.es` reconnects, and `leash doctor` could never confirm the grant. The daemon therefore prefers a connected `leash.es` client advertising the capability (live evidence that cannot outlive the process it describes) and falls back to the last recorded event, which still covers the very first connection, the denial case, and extensions too old to advertise. `unknown` remains a real state for those older builds.

It always answers `200`, including before anything is known: "the daemon is up and has heard nothing" is itself the answer doctor needs, and a `503` would be indistinguishable from the daemon being down — a completely different remedy. `components` is always an array, never `null`.

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
  "sourceRevision": "c686025aa1b2c3-dirty", // complete -X main.commit value for provenance checks
  "builtAt": "2026-07-21T10:11:12Z",// RFC 3339 UTC, or "unknown"
  "enforcing": true,                // does THIS BUILD carry an enforcement path
  "contractVersion": 1,             // current CLI surface
  "minCompatibleContract": 0,       // oldest caller contract still served
  "capabilities": [                 // surface elements a provisioner can drive
    "policy", "inject-service", "runtime", "user", "require-lsm", "machine-output", "version-json", "resolver-contract-json", "idmap-volume"
  ],
  "os": "linux", "arch": "amd64"    // GOOS / GOARCH
}
```

Field names are camelCase and additive-only: renaming or removing one is a contract break, adding one is not.

Value domains a caller must accept rather than reject:

- `version` — a release tag, a `git describe` string (which may end `-dirty`), or the literal `dev`.
- `commit` — an abbreviated hex hash, optionally suffixed `-dirty`; or the literal `dev`; or the literal `unknown`. All three are legitimate builds.
- `sourceRevision` — the complete linked commit value, optionally suffixed `-dirty`; or the same `dev` / `unknown` sentinels. Release tooling compares this field exactly with the manager image revision label.
- `builtAt` — RFC 3339 UTC, or the literal `unknown`.

`dev` and `unknown` are documented sentinels, not errors: `unknown` is the ldflag default in `cmd/leash`, and `dev` is both `main.version`'s default and what the build paths substitute for `commit` when `git rev-parse` fails.

**The `-dirty` marker is best-effort and not guaranteed on any given path.** Today only the Makefile `build` target appends it; `scripts/release.sh`, `scripts/install-leash.sh`, `build/publish-docker.sh` and `.goreleaser.yaml` stamp the bare hash. Its presence means the tree was modified; **its absence is not proof of a clean tree** and must not be treated as a provenance guarantee.

**Compatibility rule.** The contract covers the flags a provisioner drives (`--policy`, `--inject-service`, `--runtime`, `--user`, `--require-lsm`, `--machine-output`, `--idmap-volume`) plus the shape of this document. A caller written against contract `C` proceeds iff:

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

### Resolver ownership — `leash resolvers` JSON

An orchestrator that generates network policy before launching Leash probes
`leash version --json`, requires the `resolver-contract-json` capability, and
then queries the exact runtime it will launch:

```sh
leash resolvers --runtime native --json
leash resolvers --runtime docker --json   # podman is identical
```

The command is side-effect free: it does not launch a workload, inspect an
image, require credentials, or read host resolver configuration. Runtime is
mandatory, as is `--json`; help and diagnostics are written only to stderr.

Native Leash owns the workload resolver configuration:

```json
{
  "schemaVersion": 1,
  "runtime": "native",
  "strategy": "leash-managed",
  "resolvers": ["1.1.1.1", "8.8.8.8"],
  "discovery": "use the complete resolver list reported by Leash"
}
```

`resolvers` is the complete, non-empty set Leash uses for the native workload's
private `resolv.conf` and DNS egress allow-list. Addresses are canonical IP
literals, deduplicated and sorted. An orchestrator should authorize exactly
these addresses on port 53. If native Layer 2 cannot be established, Leash's
existing fail-closed policy remains authoritative; the contract does not claim
that host resolvers were installed.

This `native` strategy describes the Linux network-namespace launcher. A
non-Linux build rejects `--runtime native` instead of reporting the Linux list;
its independently managed native backend must not be inferred from this schema.

Container engines own their workload resolver configuration:

```json
{
  "schemaVersion": 1,
  "runtime": "docker",
  "strategy": "runtime-managed",
  "resolvers": [],
  "discovery": "inspect the target runtime's effective /etc/resolv.conf"
}
```

An empty array is not an empty allow-list. `strategy: "runtime-managed"` is an
explicit delegation: inspect the target image and selected network using the
same engine and settings the workload will receive. Never copy the native
resolver list into a Docker/Podman policy.

`schemaVersion` versions this document independently of the broad CLI contract.
Unknown schema versions or strategies must fail closed. Invalid runtime,
malformed/empty/over-limit native resolver state, encoding failure, or output
failure returns non-zero. No validation or usage failure writes a partial
success document to stdout.

### Machine-output fd ownership — `leash --machine-output`

An orchestrator that needs the governed command's stdout as a machine-readable result first probes `leash version --json` and requires the `machine-output` capability. It then invokes either supported launcher shape normally, adding the flag before the workload separator:

```sh
leash --machine-output --runtime native -- agent --json
leash --machine-output --runtime docker -- agent --json
leash --machine-output --runtime podman -- agent --json
```

`--machine-output` is an fd-ownership contract, not an output format. It implies `--no-interactive` but leaves stdin open and directly attached. The governed workload inherits Leash's stdin, stdout, and stderr directly: workload fd 1 is Leash fd 1 byte-for-byte, and workload fd 2 remains Leash fd 2. Leash does not parse, buffer, recognize, normalize, or re-encode either workload stream, so arbitrary binary bytes and a final unterminated result are valid. Numeric workload exit codes still propagate exactly after best-effort cleanup; signal handling retains the runner's existing semantics.

Every Leash-owned policy, UI, bootstrap, image, port-forward, prompt, and lifecycle message is written to fd 2 in this mode. Docker and Podman command progress is also Leash-owned and goes to fd 2; native launcher diagnostics follow the same rule. With the flag absent, historical interactive behavior remains unchanged, including TTY allocation and operational-output destinations.

The capability is additive under contract version 1. A caller that requires pure stdout must require the literal `machine-output` capability rather than infer support from `contractVersion == 1`; older contract-1 builds do not carry this flag.

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
    "lsm_bpf_attachable": "unknown",//   attachable | unattachable | unknown — observed, never inferred Values: `attachable` (verified, attached, and `bpf` is in the active LSM stack), `inert` (verified and attached, but `bpf` is absent from the active stack so the hooks are never invoked and nothing is enforced), `unattachable` (the kernel refused), `unknown` (could not be established).
    "caps": ["bpf", "net_admin"],   //   effective caps observed, never inferred; [] when unreadable
    "issues": ["…"]                 //   one actionable sentence + remedy per blocker
  },
  "container": {                    // docker/podman
    "status": "degraded",
    "ready": false,
    "engine": "docker",             //   null when no supported engine is on PATH
    "issues": ["…"]
  },
  "darwin": {                       // macOS enforcement — `leash --darwin` (ES + NE extensions)
    "checked": false,               //   false off macOS: the probes never ran (≠ "macOS is broken")
    "status": "unavailable",        //   ready | degraded | unavailable
    "ready": false,
    "es_extension": "unknown",      //   active | disabled | missing | unknown — systemextensionsctl
    "filter_extension": "unknown",  //   the NE content filter
    "proxy_extension": "unknown",   //   the NETransparentProxyProvider that feeds the MITM proxy
    "full_disk_access": "unknown",  //   granted | denied | unknown — as LeashES reported it
    "daemon_up": false,             //   the `leash --darwin` daemon answered /healthz
    "daemon": "127.0.0.1:18080",    //   where doctor looked for it
    "components": [],               //   extensions actually connected to that daemon
    "leash_cli": "/Applications/Leash.app/Contents/Resources/leashcli",
    "issues": ["…"]
  },
  "unchecked": [                    // prerequisites doctor did NOT verify (never silently omitted)
    { "name": "bpf_lsm_attachable", "reason": "…" }
  ],
  "default_runtime": "native"       // the runtime a bare `leash run` selects on this build
}
```

Field names are snake_case here (they were fixed by issue #23 before the camelCase `version --json` document existed) and additive-only. `caps`, `issues`, `components` and `unchecked` are always arrays, never `null`, however the report was produced; `engine` is the only field that can be `null`.

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

### The `darwin` section (issue #61)

`native` and `container` grade the Linux runtimes; `darwin` grades macOS enforcement, which is a different mechanism wearing the same word. `--runtime native` on Linux means leashd plus eBPF LSM programs; the macOS path is `leash --darwin`, which enforces through three system extensions and a daemon they talk to. It is always present in the document — on Linux with `checked: false` and a single "this host is not macOS" issue, which is why it never drags the verdict down there.

**Two signals per extension, and neither substitutes for the other.**

| Signal | Source | Says |
|---|---|---|
| activation | `systemextensionsctl list` | the user approved it, so macOS will let the code run |
| connection | the daemon's `/health/darwin` `components` | it is running **and** receiving PID/rule broadcasts |

Neither is authoritative alone, but they fail in opposite directions, so doctor combines them:

| activation | connected | verdict |
|---|---|---|
| `active` | yes | running and holding rules |
| `active` | no | activated but enforcing nothing — a fault |
| `active` | *unknown* (daemon down) | no separate fault; the daemon's own issue says why |
| `unknown` | yes | running — the websocket is proof, so the unreadable table does not matter |
| `unknown` | *unknown* | unverified: an issue, never a blocker |
| `missing` / `disabled` | — | macOS is not running it — a fault |

The two `unknown` rows are the ones that matter. `systemextensionsctl` exits `EX_NOPERM` without admin rights, and grading that as a definite negative would report a perfectly healthy Mac as unable to enforce; a connected extension is running whatever the table says, so the *stronger* signal wins rather than the more pessimistic one. When neither signal is available the state is reported unverified — an issue and an `unchecked` entry (`macos_extension_activation`), but never a blocker, because doctor established nothing is wrong, only that it could not tell.

**Presence and absence are not equally trustworthy, and the code treats them differently.** A name in `components` is positive evidence: a client claimed it. Absence only means "not connected" if *every* client in the list could be identified — so two things suppress the negative conclusion:

- the daemon is down or did not serve `/health/darwin`, so the list is silence rather than evidence;
- the list contains `unknown`, i.e. a client connected without a `component` in its `client.hello`. Extensions built before that field existed (through Leash.app `1.1.0/20251027.1`) do exactly this, and treating their anonymity as absence reported a Mac with both extensions genuinely connected as `unavailable`, telling the operator to re-activate two working extensions.

In both cases doctor reports the gap as its own degradation (`unchecked` gains `macos_extension_connectivity`, whose reason names *which* gap) rather than blaming any extension. A positively named component still counts, so a new-build extension beside an old one remains provably connected.

**Full Disk Access has no external probe.** macOS exposes no API for reading another process's TCC grant, and the tempting substitutes answer a different question (probing a TCC-gated path tells you about whoever ran doctor). The signal is LeashES's own report to the daemon, relayed through `/health/darwin` — see that endpoint above for why `unknown` is common. **`unknown` never reaches `ready`.** Without FDA, LeashES observes no file events at all while looking perfectly healthy from the outside, so an unverified grant is treated the way an unread capability set is on Linux: reported as absent, never assumed. `unchecked` gains `macos_full_disk_access`.

**What makes a Mac `unavailable`** — enforcement cannot work at all, and there is no macOS equivalent of Linux's proxy-only fallback:

- the ES extension is definitively not activated, or is activated but not connected to the daemon (no file/exec policy, and nothing else gates them),
- Full Disk Access was reported **denied**,
- the companion `leashcli` binary is missing (`--leash-cli-path` overrides where doctor looks).

All blockers are reported together, not one at a time.

**What makes it `degraded`** — it enforces, but not everything:

- the content filter or transparent-proxy extension is not activated or not connected (socket policy / HTTPS inspection off),
- the daemon is unreachable, so the extensions are blind (they hold no rules),
- the daemon answered but predates `/health/darwin`, so connectivity and FDA could not be read,
- FDA was never reported,
- an extension's activation state could not be read and it is not connected either, so it is unverified rather than known-bad,
- a connected client did not identify itself, so no extension's connectivity can be confirmed.

**Four things doctor does not read directly**, all declared in `unchecked`: `macos_ne_configuration` (the `NEFilterManager` / `NETransparentProxyManager` installed-and-enabled state — inferred from activation plus connection, which is the stronger signal), `macos_extension_activation` (when `systemextensionsctl` could not be consulted), `macos_extension_connectivity` (when the daemon could not be asked) and `macos_full_disk_access` (when nothing was reported). SIP/AMFI are out of scope: a production signed build does not need relaxed security.

**Two flags exist for the macOS seams**, both accepted on every platform so a script need not branch on `GOOS`: `--leash-cli-path PATH` (default `/Applications/Leash.app/Contents/Resources/leashcli`) and `--darwin-daemon ADDR` (default `$LEASH_LISTEN`, else `127.0.0.1:18080`; a bare port or `:18080` is completed to loopback). Both have a legitimate non-default value during development, and reporting the app-bundle path as missing would be true but useless.

**Exit codes.** The verdict is in the document *and* in the exit status, and they always agree.

| Code | Meaning | Remedy shape |
|---|---|---|
| `0` | a runtime enforces with both layers | none |
| `1` | no runtime can run a workload at all | install or repair a runtime |
| `2` | usage error — **including `--help`** | fix the invocation |
| `3` | a runtime runs, but not every layer enforces (Linux: Layer 1 off, proxy-only; macOS: see the `darwin` section) | the runtime is fine, the kernel or the extension stack is not |
| `4` | doctor could not render or write its own report | not a verdict; retry / check the pipe |

Exit `0` is the answer to "can this machine enforce?", so `leash doctor && …` fails closed on `3`. `--help` deliberately exits `2`, not `0`: a provisioner gating on the status must not get a free pass from `leash doctor -help`.

**A `degraded` verdict is not always about the kernel.** These conditions produce it, and the `issues` text says which (the macOS ones are listed under the `darwin` section above):

- `bpf` is absent from `/sys/kernel/security/lsm` (`lsm_bpf: "inactive"`), or that list could not be read or was empty (`"unknown"`). This holds whatever the attach probe observed — see the conjunctive table above.
- The list says `bpf` is there and leash's LSM programs were loaded and refused anyway (`lsm_bpf: "active"`, `lsm_bpf_attachable: "unattachable"`) — the case the probe exists for.
- The host is not Linux. Containers then run against a VM kernel doctor never probed — Docker Desktop's LinuxKit kernel, for one, does not carry `bpf`. An unprobed kernel is never `ready`.
- `DOCKER_HOST` is set. The engine's containers run on a remote daemon's kernel, not the one doctor read, so the Layer 1 claim is withheld rather than borrowed. No remote topology is modelled; `unchecked` gains a `container_kernel` entry.

**`default_runtime` is not the verdict.** `verdict` is the best state *any* runtime reaches, but `leash run` with neither `--runtime` nor `LEASH_RUNTIME` selects exactly one runtime and never falls back. On this build that is `native`, so a Linux host with no systemd and a working docker reports `verdict: ready` while a bare `leash run` fails. Compare `default_runtime` against that runtime's `status` (`native` → `native.status`, `docker`/`podman` → `container.status`, `darwin` → `darwin.status`); the human output prints the same warning in prose. This matters most on macOS today: the default is `native`, which is `unavailable` there, so a Mac that enforces reports `verdict: ready` while a bare `leash run` stops with guidance — dispatching macOS to `--darwin` by default is tracked separately (sixtoad/leash#2).

**What doctor does not check** is in the document, not just in this page: `unchecked` always names `bpf_d_path_ringbuf` and `netns_iptables`, plus `bpf_lsm_attachable` whenever the attach probe did not settle it (`--quick`, insufficient privilege, non-Linux, timeout), `capabilities` when `/proc/self/status` was unreadable, `container_kernel` in the two cases above, and the `macos_*` entries on a Mac. A `ready` verdict must be read as exactly that list of things unverified.

Two caveats a script should know. Doctor writes its whole report in one `Write`, so a closed stdout (`leash doctor --json | head -1`) is reported as exit `4` — except that Go raises `SIGPIPE` on fd 1, so the process is more likely to die of the signal (`141` from a shell) than to reach that code; doctor does not trap signals to paper over this. And an engine probe that hangs is bounded by a 5 s timeout on `<engine> info`, after which the daemon is reported unreachable — the CLI is killed, but a grandchild the client itself spawned is not process-group-killed and may outlive it.

Decode it the way `version --json` is decoded: with a struct of your own. Go consumers inside this repo can decode into `doctor.Report` (the marshal/unmarshal pair round-trips exactly, and `verdict`/`ready` are recomputed from the statuses rather than trusted from the document), but the package is `internal/` and exports no importable type.

## Notable header & error conventions

- All API responses set `Content-Type: application/json` unless noted.
- Errors carry `{ "error": { "message": "...", "detail"?: { "line": int, "column": int, "code": string, "suggestion": string } } }` (Cedar parse errors populate `detail`).
- `validate` always returns `200` — issues live inside the body so the editor can render them as markers.
- `complete` always returns `200` with `items` (empty on malformed input, comment context, or zero hints).
- No CSRF/auth today — the listener defaults to `127.0.0.1:18080`. Operators that change `--listen` to a non-loopback address are responsible for fronting it with auth.
