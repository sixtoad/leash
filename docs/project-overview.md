# Project Overview — Leash

> **Source of truth for end-users:** the top-level [`README.md`](../README.md). This document is the developer-facing summary that complements it and links into the rest of the generated docs.

## What it is

[Leash](https://leash.strongdm.ai/) wraps AI coding agents (`claude`, `codex`, `gemini`, `qwen`, `opencode`) in a governance shell. On Linux it runs the agent inside a container and pairs it with a privileged "leash manager" container that enforces [Cedar](https://docs.cedarpolicy.com/) policies via eBPF LSM hooks (file/exec/connect) plus an in-namespace MITM HTTP/HTTPS proxy. On macOS it skips containers altogether and uses Apple's EndpointSecurity + NetworkExtension system extensions for the same policy surface.

Policy authoring uses Cedar end-to-end; Leash IR (the format actually pushed into BPF maps and proxy tables) is generated in memory and never persisted.

## Repository shape

Monorepo at [`github.com/strongdm/leash`](https://github.com/strongdm/leash). Three substantive parts plus three small ancillary directories:

| Part | Type | Where it lives | What it produces |
|---|---|---|---|
| **leash-core** | backend (Go) | `cmd/`, `internal/` | `leash` CLI binary; multiplexes runner / `--daemon` / `--darwin` |
| **controlui-web** | web (Next.js + React) | `controlui/web/` | Static SPA → embedded into the Go binary at `internal/ui/dist` |
| **mac-leash** | desktop (Swift + Xcode) | `mac-leash/` | `Leash.app` (status-bar) + 2 system extensions + `leashcli` |
| _npm-leash_ | distribution wrapper | `npm/leash/` | `@strongdm/leash` npm package |
| _build-scripts_ | release tooling | `build/` | Goreleaser hooks, docker/npm publishing |
| _e2e_ | tests | `e2e/` | End-to-end Go test suite |

## Tech stack

### leash-core (Go)
- Go 1.23+ (CI uses 1.25.x); module `github.com/strongdm/leash`.
- `github.com/cedar-policy/cedar-go` (policy engine), `github.com/cilium/ebpf` (LSM), `github.com/gorilla/websocket` (UI/mac envelope transport).
- OpenTelemetry SDK + `stdouttrace` exporter (MCP-focused instrumentation).
- `github.com/charmbracelet/{bubbletea,lipgloss}` (terminal UI for `--open` and verbose mode).
- `github.com/pelletier/go-toml/v2` (config), `github.com/klauspost/compress` (embed compression).

### controlui-web (TypeScript)
- Next.js 16 (App Router, `output: "export"`), React 19.2, TypeScript 5.
- Tailwind v4 + shadcn/ui on top of `@radix-ui/*`.
- `@monaco-editor/react` (Cedar editor), `@tanstack/react-query` v5 (server state), `@xyflow/react` / `reactflow` (graph).
- pnpm 10 (corepack-pinned), Vitest + Testing Library + jsdom.

### mac-leash (Swift)
- Swift 5 / Xcode project.
- EndpointSecurity.framework (exec/file events), NetworkExtension.framework (content-filter provider with TLS SNI), SwiftUI status-bar host app, Sparkle for auto-update.
- Team ID: `W5HSYBBJGA`. Bundle IDs: `com.strongdm.leash.{LeashES,LeashNetworkFilter}`.

## How parts compose at runtime

```
              ┌──────────────────────────────────────┐
              │  controlui-web (SPA in Go binary)    │
              └───────────────┬──────────────────────┘
                              │   HTTP + WS  /api/*
                              ▼
              ┌──────────────────────────────────────┐
              │  leashd (Linux, in container) OR     │
              │  darwind (macOS, on host)            │
              │  • Cedar engine + IR transpiler      │
              │  • policy.Manager (file + runtime)   │
              │  • WebSocketHub                      │
              │  • macsync (mac envelopes)           │
              └────┬───────────────────────┬─────────┘
       BPF maps   │                       │  WebSocket
       Ringbufs   │                       │  envelopes
                  ▼                       ▼
        ┌─────────────────┐   ┌──────────────────────┐
        │ governed cgroup │   │ mac-leash app + ES + │
        │ (target ctr)    │   │ NetworkFilter sysext │
        └─────────────────┘   └──────────────────────┘
```

End-to-end detail in [`architecture-leash-core.md`](architecture-leash-core.md), [`architecture-controlui-web.md`](architecture-controlui-web.md), [`architecture-mac-leash.md`](architecture-mac-leash.md), and [`integration-architecture.md`](integration-architecture.md).

## Operating modes

| Mode | What happens | When |
|---|---|---|
| **Record** | All operations allowed; everything logged. | Initial deployment / behaviour discovery. |
| **Shadow** | Policies evaluated; nothing denied; events carry `would_deny: true`. | Pre-cutover validation. |
| **Enforce** | Policies enforced at the kernel and/or sysext layer. | Production. |

Toggled live via `POST /api/policies/permit-all` / `POST /api/policies/enforce-apply`. The `default_policy` BPF map is updated atomically — no daemon restart.

## Deep dives

| Topic | Doc |
|---|---|
| Why eBPF LSM (vs seccomp / Landlock / AppArmor / SELinux) | [`design/ARCHITECTURE.md`](design/ARCHITECTURE.md) |
| Cedar reference + IR mapping | [`design/CEDAR.md`](design/CEDAR.md) |
| MITM proxy capabilities | [`design/PROXY.md`](design/PROXY.md) |
| Bootstrap lifecycle | [`design/BOOT.md`](design/BOOT.md) |
| Trust boundaries + CA private/public split | [`design/SECURITY-MODEL.md`](design/SECURITY-MODEL.md) |
| Cedar editor autocomplete round-trip | [`design/AUTOCOMPLETE.md`](design/AUTOCOMPLETE.md) |
| Config schema + project overlay | [`CONFIG.md`](CONFIG.md) |
| macOS native path | [`MACOS.md`](MACOS.md) |
| Telemetry payloads + opt-out | [`TELEMETRY.md`](TELEMETRY.md) |
| Custom target Docker images | [`CUSTOM-DOCKER-IMAGES.md`](CUSTOM-DOCKER-IMAGES.md) |
| Release pipeline (Goreleaser + npm) | [`RELEASE.md`](RELEASE.md) |
| Future: secrets injection at the proxy | [`todo/SECRETS-INJECTION.md`](todo/SECRETS-INJECTION.md) |

## Where to start a contribution

| You want to… | Start at |
|---|---|
| Change Cedar action semantics | `internal/transpiler/cedar_to_leash.go` + `design/CEDAR.md` |
| Add an LSM hook | `internal/lsm/bpf/*.bpf.c` + `internal/lsm/manager.go` |
| Add a daemon endpoint | `internal/leashd/http_api.go` + `api-contracts-leash-core.md` |
| Change UI behaviour | `controlui/web/src/components/` + `architecture-controlui-web.md` |
| Wire a new MCP capability | `internal/proxy/mcp_observer.go` + `internal/cedar/autocomplete/` |
| Change runner flag set | `internal/runner/` + `architecture-leash-core.md § Runner` |
| Touch the macOS path | `mac-leash/` + `internal/darwind/` + `architecture-mac-leash.md` |
| Modify release pipeline | `.github/workflows/release.yml` + `build/` + `RELEASE.md` |

## License & contributors

Apache-2.0 (`LICENSE`). See `CONTRIBUTORS.md` and `DISCLAIMER.txt`.
