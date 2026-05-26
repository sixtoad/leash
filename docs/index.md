# Leash — Documentation Index

> **Primary entry point for AI-assisted development.** Generated 2026-05-26 by `bmad-document-project`. Project context: see [`project-overview.md`](project-overview.md).

## Project Snapshot

- **Type:** monorepo with 3 documented parts (backend Go core, Next.js web, Swift macOS native) + 3 ancillary directories
- **Primary languages:** Go 1.23+, TypeScript 5, Swift 5
- **Repo:** [`github.com/strongdm/leash`](https://github.com/strongdm/leash)
- **License:** Apache-2.0

### Quick reference per part

| Part | Tech stack | Root path |
|---|---|---|
| **leash-core** (backend) | Go · Cedar policy engine · eBPF/LSM via `cilium/ebpf` · MITM HTTP proxy · gorilla/websocket · OpenTelemetry · bubbletea TUI | `cmd/`, `internal/` |
| **controlui-web** (web) | Next.js 16 · React 19 · TypeScript · Tailwind v4 · shadcn/Radix · Monaco · TanStack Query · xyflow · Vitest | `controlui/web/` |
| **mac-leash** (desktop) | Swift · Xcode · EndpointSecurity · NetworkExtension · Sparkle · SwiftUI status-bar app | `mac-leash/` |

Plus: `npm/leash/` (npm wrapper), `build/` (release tooling), `e2e/` (end-to-end Go tests).

## Generated Documentation (this scan)

### Overview & navigation

- [Project Overview](project-overview.md) — what leash is, repo shape, tech stack, where to start a contribution
- [Source Tree Analysis](source-tree-analysis.md) — annotated directory map with package roles

### Per-part architecture

- [Architecture — leash-core](architecture-leash-core.md) — Go binary multiplexer, package map, Cedar→IR pipeline, runtime wiring
- [Architecture — controlui-web](architecture-controlui-web.md) — Next.js routing, state, daemon API consumption, Monaco editor, build pipeline
- [Architecture — mac-leash](architecture-mac-leash.md) — Xcode targets, status-bar app, ES + NetworkExtension internals, DaemonSync surface

### Cross-cutting

- [Integration Architecture](integration-architecture.md) — controlui-web ↔ leash-core ↔ mac-leash boundaries; bootstrap; envelope catalog
- [API Contracts — leash-core](api-contracts-leash-core.md) — every HTTP endpoint + WebSocket message + mac envelope
- [Data Models — leash-core](data-models-leash-core.md) — Cedar IR, BPF maps, WebSocket events, config schema, macOS rule models
- [Component Inventory — controlui-web](component-inventory-controlui-web.md) — every shadcn primitive + feature component + hook + lib module

### Operational guides

- [Development Guide](development-guide.md) — prerequisites, fast iteration loops per part, env vars worth knowing, versioning
- [Deployment Guide](deployment-guide.md) — release pipeline, CI workflows, Docker layout, npm packaging, macOS distribution

## Existing Documentation (cross-referenced, not regenerated)

### Design corpus (`docs/design/`)

These are the authoritative deep-dives; the generated architecture docs above link out to them rather than duplicate.

- [`design/ARCHITECTURE.md`](design/ARCHITECTURE.md) — Why eBPF LSM (vs seccomp/Landlock/AppArmor/SELinux); two-layer enforcement; Cedar integration; MCP; modes; perf
- [`design/CEDAR.md`](design/CEDAR.md) — Full Cedar policy reference; supported actions/resources; IR mapping; MCP semantics
- [`design/PROXY.md`](design/PROXY.md) — MITM proxy capabilities and notes
- [`design/BOOT.md`](design/BOOT.md) — Bootstrap-Oriented OrchesTration sequence (target ↔ manager handshake)
- [`design/SECURITY-MODEL.md`](design/SECURITY-MODEL.md) — Trust boundaries, deny-by-default, public/private CA split
- [`design/AUTOCOMPLETE.md`](design/AUTOCOMPLETE.md) — Cedar editor autocomplete round-trip (Monaco ↔ daemon ↔ engine)

### Operator-facing docs

- [`README.md`](../README.md) — User-facing overview, install, quick start
- [`CONFIG.md`](CONFIG.md) — `~/.config/leash/config.toml` + per-project `.leash.toml` schema
- [`CUSTOM-DOCKER-IMAGES.md`](CUSTOM-DOCKER-IMAGES.md) — Extending the target image
- [`DEVELOPMENT.md`](DEVELOPMENT.md) — Minimal dev setup
- [`MACOS.md`](MACOS.md) — macOS native install, activation, troubleshooting
- [`RELEASE.md`](RELEASE.md) — Cut-release runbook (Goreleaser + Docker + npm)
- [`TELEMETRY.md`](TELEMETRY.md) — Statsig events emitted; opt-out
- [`todo/SECRETS-INJECTION.md`](todo/SECRETS-INJECTION.md) — Future: secrets injection at the proxy boundary

### Package-local READMEs

- [`internal/transpiler/README.md`](../internal/transpiler/README.md) — Cedar → IR transpilation details
- [`controlui/web/README.md`](../controlui/web/README.md) — Stock Next dev-server snippet
- [`npm/leash/README.md`](../npm/leash/README.md) — npm consumer notes

### CI/CD configuration

- [`.github/workflows/tests.yml`](../.github/workflows/tests.yml) — `make test-deps test-go test-web` on every push/PR
- [`.github/workflows/release.yml`](../.github/workflows/release.yml) — verify → release → stage-npm → publish-npm
- [`.github/workflows/coder-cli-releases-watchdog.yml`](../.github/workflows/coder-cli-releases-watchdog.yml) — Upstream agent CLI watchdog

## Getting Started

### For new contributors

1. Read [`project-overview.md`](project-overview.md) end-to-end.
2. Skim [`source-tree-analysis.md`](source-tree-analysis.md) to learn where things live.
3. Read whichever architecture doc matches the part you'll touch.
4. Reach for [`development-guide.md`](development-guide.md) for the build/test loop.
5. Reach for [`api-contracts-leash-core.md`](api-contracts-leash-core.md) or [`data-models-leash-core.md`](data-models-leash-core.md) when designing changes that cross the daemon boundary.

### For AI-assisted PRD/architecture work

When generating a brownfield PRD or architecture for new functionality, point your workflow at this index file (`docs/index.md`). The architecture, integration, API, and data-model docs are designed to be consumed wholesale by a planning agent — they're terse and cross-referenced.

| Feature area | Primary docs to include |
|---|---|
| Cedar / policy changes | `design/CEDAR.md`, `architecture-leash-core.md`, `api-contracts-leash-core.md`, `data-models-leash-core.md` |
| LSM / kernel changes | `design/ARCHITECTURE.md`, `design/SECURITY-MODEL.md`, `architecture-leash-core.md` |
| Daemon API additions | `api-contracts-leash-core.md`, `architecture-leash-core.md`, `integration-architecture.md` |
| UI features | `architecture-controlui-web.md`, `component-inventory-controlui-web.md`, `api-contracts-leash-core.md` |
| macOS native changes | `architecture-mac-leash.md`, `integration-architecture.md`, `MACOS.md` |
| Release / packaging | `deployment-guide.md`, `RELEASE.md`, `CUSTOM-DOCKER-IMAGES.md` |

## Notes on freshness

This index was generated by the `bmad-document-project` exhaustive scan on 2026-05-26 from a clean tree at:

- HEAD: `fd8e0c1` `feat(configstore): support local .leash.toml override file`
- Branch: `main`

The state file at [`project-scan-report.json`](project-scan-report.json) records what was scanned, what was found, and what was written. Re-run `/bmad-document-project` to refresh; the workflow detects the existing index and offers to rescan or deep-dive.
