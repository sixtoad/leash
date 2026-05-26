# Source Tree Analysis

Generated 2026-05-26 by `/bmad-document-project` (exhaustive scan).

Repository: [`github.com/strongdm/leash`](https://github.com/strongdm/leash) — monorepo with three documented parts plus three ancillary directories.

```
leash/
├── cmd/                       # Go binary entry points
│   ├── leash/main.go          # Multiplexer: runner | --daemon → leashd | --darwin → darwind
│   └── leash-entry/main.go    # Target-container bootstrap (CA install, exec target cmd)
│
├── internal/                  # All daemon, runner, enforcement, and shared code
│   ├── leashd/                # Linux/in-container daemon (HTTP/WS API, policy CRUD)
│   ├── darwind/               # macOS-native "daemon" (peer of leashd, talks to mac-leash)
│   ├── runner/                # Host-side orchestrator: docker run target + manager
│   ├── entrypoint/            # Embeds compressed leash-entry binaries (linux/amd64, arm64)
│   │
│   ├── lsm/                   # eBPF LSM kernel enforcement
│   │   ├── bpf/               # *.bpf.c source for file_open, exec, connect hooks
│   │   ├── manager.go         # LSMManager — attach/detach, policy push to BPF maps
│   │   ├── file_open.go       # OpenLsm module + OpenPolicyRule
│   │   ├── proc_exec.go       # ExecLsm + arg-blacklist denies
│   │   ├── net_connect.go     # ConnectLsm + DNS→IP expansion
│   │   └── common.go          # PolicySet, PolicyRule, MCPPolicyRule, SharedLogger
│   │
│   ├── cedar/                 # Cedar source parsing + compile errors
│   │   ├── compile.go         # CompileFile/CompileString → *Compilation
│   │   └── autocomplete/      # Engine behind POST /api/policies/complete (see docs/design/AUTOCOMPLETE.md)
│   │
│   ├── transpiler/            # Cedar AST → Leash IR (see internal/transpiler/README.md)
│   │   ├── cedar_to_leash.go  # TranspilePolicySet — action handlers (FileOpen, ProcessExec, NetworkConnect, HttpRewrite, McpCall)
│   │   ├── linter.go          # Capability checks, mcp_allow_noop warnings
│   │   └── policy_lines.go    # Cedar source ↔ UI line model
│   │
│   ├── policy/                # Hot-reload manager + file watcher + persistence
│   │   ├── policy.go          # Manager — layered file/runtime rules, atomic apply
│   │   ├── default_*.go       # Default Cedar policy bootstrap
│   │   └── suggest/           # Generator backing GET /suggest (event-log → policy proposal)
│   │
│   ├── proxy/                 # Transparent MITM HTTP/HTTPS proxy (see docs/design/PROXY.md)
│   │   ├── proxy.go           # MITMProxy, SO_MARK loop-prevention dialer, SO_ORIGINAL_DST extraction
│   │   ├── ca.go              # CertificateAuthority — public/private split (see docs/design/SECURITY-MODEL.md)
│   │   ├── rewriter.go        # HeaderRewriter — Cedar HttpRewrite → response-time injection
│   │   └── mcp_observer.go    # JSON-RPC + SSE parsing, McpCall enforcement, hint sources
│   │
│   ├── httpserver/            # Tiny http.Server factory (frontend.go: NewWebServer)
│   ├── websocket/             # WebSocketHub — /api endpoint, NDJSON event stream, ring buffer
│   │
│   ├── macsync/               # Go side of macOS app sync (manager.go + translator.go)
│   ├── messages/              # Cross-process envelopes (mac.pid.sync, mac.rule.sync, etc.)
│   ├── configstore/           # ~/.config/leash/config.toml + per-project .leash.toml overlay
│   ├── openflag/              # OPEN env-var flag parsing (browser auto-open)
│   ├── assets/                # Embedded shell scripts (iptables, nftables, leash prompt)
│   ├── log2cedar/             # LSM event log → Cedar policy suggestion (Generator)
│   │
│   ├── telemetry/
│   │   ├── otel/              # OpenTelemetry meter/tracer + MCPInstruments
│   │   └── statsig/           # Minimal Statsig client (see docs/TELEMETRY.md)
│   │
│   └── ui/                    # Embedded Next.js SPA via //go:embed dist/**
│       ├── embed.go           # embed.FS over dist/
│       ├── handler.go         # SPAHandler with client-side routing fallback + title injection
│       └── dist/              # Built by `make build-ui` → consumed by leashd & darwind
│
├── controlui/                 # Front-end source (Part: controlui-web)
│   ├── Makefile               # Scaffold/dev targets (bootstrap, dev, build, lint)
│   └── web/                   # Next.js 16 + React 19 + TS app
│       ├── src/
│       │   ├── app/           # App Router — single page.tsx + layout.tsx (SPA, output: "export")
│       │   ├── components/
│       │   │   ├── ui/        # shadcn/Radix primitives
│       │   │   ├── policy/    # CedarEditor + Collapsible + Monaco language
│       │   │   ├── actions/   # ActionsStream — event table
│       │   │   ├── graph/     # InstancesFlow — ReactFlow diagram
│       │   │   ├── nav/       # Header, DataSourceControls
│       │   │   └── single/    # SingleHeader (enforce/permit-all), PromptBanner
│       │   └── lib/
│       │       ├── policy/    # api.ts (all daemon calls), use-policy-query.ts, contexts
│       │       ├── mock/      # SimulationProvider — dev-mode fake events
│       │       └── single/    # SingleContext local store
│       ├── public/            # logo.svg + stock Next assets
│       ├── package.json       # pnpm + Next 16 + React 19 + Tailwind v4
│       ├── vitest.config.ts   # jsdom + Testing Library
│       └── eslint.config.mjs
│
├── mac-leash/                 # macOS native (Part: mac-leash) — Xcode workspace
│   ├── Leash.xcodeproj/
│   ├── Leash/                 # Status-bar SwiftUI app
│   │   ├── LeashApp.swift     # App entry — instantiates 2 SystemExtensionControllers
│   │   ├── MainStatusView.swift + MainStatusView+Sections.swift   # ES + NF + WebInterface boxes
│   │   ├── SystemExtensionController.swift (+Internals)           # Activation state machine
│   │   ├── SparkleUpdater.swift                                   # SUStandardUpdater wrapper
│   │   └── ExperimentalSettingsView.swift                         # Sys-wide enforcement, flow delay
│   ├── LeashCLI/              # /Applications/Leash.app/.../leashcli — thin posix_spawnp wrapper
│   │   └── main.swift
│   ├── LeashES/               # EndpointSecurity extension — exec/open monitoring
│   │   ├── main.swift
│   │   ├── LeashMonitor.swift (+Handlers)        # ES client, ES_EVENT subscriptions
│   │   └── LeashCommunicationService.swift (+Handlers)  # Rule cache, daemon WS messages
│   ├── LeashNetworkFilter/    # NetworkExtension content-filter — per-flow + SNI
│   │   ├── main.swift
│   │   └── FilterDataProvider.swift
│   │      + FlowHandling, PendingFlows, PIDMetadata, RuleEvaluation (~27KB), State
│   └── Shared/                # Cross-target Swift sources
│       ├── DaemonSync.swift (+Extensions)         # WebSocket client to ws://127.0.0.1:18080/api
│       ├── PolicyModels.swift                     # LeashPolicyEvent/Decision/Rule
│       ├── NetworkRule.swift                      # allow|deny × domain|ip|cidr
│       ├── LeashIdentifiers.swift                 # team ID W5HSYBBJGA, bundle IDs
│       └── LeashNotifications.swift               # FDA distributed notifications
│
├── e2e/                       # End-to-end Go tests (folded into leash-core)
│   ├── boot_test.go           # Bootstrap happy path, stale marker, timeout, private-dir
│   ├── complete_test.go       # /api/policies/complete subtests (incl. concurrent + 200-line)
│   ├── integration/           # Container-based policy enforcement variants
│   └── mcpserver/             # Test MCP JSON-RPC/SSE stub
│
├── npm/leash/                 # @strongdm/leash distribution wrapper
│   ├── bin/                   # node-launchable shim
│   └── package.json           # Node ≥18, darwin+linux × x64+arm64
│
├── build/                     # Release tooling
│   ├── versionator.py         # vX.Y.Z from git tag, else dev-<sha>[-dirty]
│   ├── docker_tags.py         # Channel-aware tag computation
│   ├── publish-docker.sh      # Buildx multi-arch → public.ecr.aws
│   ├── coder-cli-releases.py  # Watchdog for upstream agent CLIs
│   ├── gen-images-json.sh
│   ├── lsm-generate.sh        # Linux-host BPF generation
│   ├── npm/                   # collect_vendor_from_dist.py + build_npm_package.py
│   └── .hooks/                # git pre-commit (large-binary guard)
│
├── docs/                      # ⇒ THIS DIRECTORY (project_knowledge)
│   ├── design/                # ARCHITECTURE.md, CEDAR.md, PROXY.md, BOOT.md, SECURITY-MODEL.md, AUTOCOMPLETE.md
│   ├── todo/                  # SECRETS-INJECTION.md
│   ├── CONFIG.md, CUSTOM-DOCKER-IMAGES.md, DEVELOPMENT.md, MACOS.md, RELEASE.md, TELEMETRY.md
│   └── (generated by bmad-document-project: index.md, project-overview.md, architecture-*.md, …)
│
├── .github/workflows/         # tests.yml, release.yml, coder-cli-releases-watchdog.yml
│
├── Makefile                   # default → build-ui → docker-leash → build (see "Critical Targets" below)
├── Dockerfile.leash           # Multi-stage: build-base → build → runtime-base → final
├── Dockerfile.coder           # AI-agent image (claude, codex, gemini, qwen, opencode + context7-mcp)
├── .goreleaser.yaml           # linux/darwin × amd64/arm64, CGO_ENABLED=0
├── go.mod / go.sum            # Module: github.com/strongdm/leash (Go 1.23+; CI uses 1.25.x)
├── test_e2e.sh                # Wrapper invoked by make test-e2e
├── README.md, LICENSE (Apache-2.0), CONTRIBUTORS.md, DISCLAIMER.txt
└── _bmad/, .agents/, .claude/, _bmad-output/   # excluded from this analysis (BMad scaffolding)
```

## Critical Folders by Part

### leash-core (backend Go)

| Folder | Role | Entry-point file |
|---|---|---|
| `cmd/leash/` | Binary multiplexer | `main.go` |
| `cmd/leash-entry/` | Target-container bootstrapper | `main.go` |
| `internal/leashd/` | Daemon: HTTP API + WS hub + lifecycle | `runtime.go` (`Main`) |
| `internal/darwind/` | macOS daemon alternative | `runtime_darwin.go` (`Main`) |
| `internal/runner/` | Docker/Podman orchestrator | `runner.go` (`Main`) |
| `internal/lsm/` | eBPF LSM enforcement | `manager.go` + `bpf/*.bpf.c` |
| `internal/policy/` | Layered policy manager | `policy.go` |
| `internal/proxy/` | MITM HTTP/HTTPS proxy | `proxy.go` |
| `internal/transpiler/` | Cedar → IR | `cedar_to_leash.go` |
| `internal/cedar/autocomplete/` | Editor completion engine | (see [docs/design/AUTOCOMPLETE.md](design/AUTOCOMPLETE.md)) |
| `e2e/` | Boot + completion + integration tests | `boot_test.go`, `complete_test.go` |

### controlui-web (Next.js)

| Folder | Role |
|---|---|
| `controlui/web/src/app/` | App Router (single `page.tsx` SPA) |
| `controlui/web/src/components/policy/` | CedarEditor (Monaco) + completion + validation |
| `controlui/web/src/components/actions/` | Events table (live + simulated) |
| `controlui/web/src/components/graph/` | xyflow instance diagram |
| `controlui/web/src/lib/policy/` | All daemon HTTP calls (see [api-contracts-leash-core.md](api-contracts-leash-core.md)) |
| `controlui/web/src/lib/mock/` | Dev-mode `SimulationProvider` |

### mac-leash (Swift)

| Folder | Role |
|---|---|
| `mac-leash/Leash/` | SwiftUI status-bar app |
| `mac-leash/LeashES/` | EndpointSecurity sysext (exec/open) |
| `mac-leash/LeashNetworkFilter/` | NetworkExtension content-filter (per-flow + TLS SNI) |
| `mac-leash/Shared/` | `DaemonSync` (WebSocket to `ws://127.0.0.1:18080/api`) + policy/rule models |
| `mac-leash/LeashCLI/` | Thin `posix_spawnp` wrapper bundled inside `Leash.app` |

## Multi-Part Boundaries

Three distinct interface surfaces wire the parts together (full detail in [integration-architecture.md](integration-architecture.md)):

1. **Go ↔ Web** — `leashd`/`darwind` serve `internal/ui/dist` (embedded Next build) on `:18080`; web speaks HTTP+WS at `/api/*`.
2. **Web ↔ Cedar editor backend** — `POST /api/policies/complete` (`internal/cedar/autocomplete`) sources hints from policy.Manager, MITM observer, and the WebSocketHub event ring.
3. **Go ↔ Swift** — Same `:18080` WebSocket; `Shared/DaemonSync.swift` ↔ `internal/macsync/manager.go`. Envelopes defined in `internal/messages/messages.go` (`mac.pid.sync`, `mac.rule.sync`, `mac.policy.event`, `mac.policy.decision`, `mac.network_rule.update`).
