# Development Guide

This expands [`DEVELOPMENT.md`](DEVELOPMENT.md) with the everyday workflows for each part. The short version: `make` from the repo root does the right thing for most tasks.

## Prerequisites

| Tool | Why | Notes |
|---|---|---|
| **Go 1.23+** | leash-core | CI uses 1.25.3; pin via `go.mod`. |
| **Docker** (or Podman, OrbStack) | Building images, running containers | Override with `DOCKER=podman make ...`. Required even for local UI builds if `pnpm` is absent (falls back to `node:22-bookworm` container). |
| **clang + llvm + libbpf-dev** | eBPF generation on Linux hosts | Not needed on macOS — `lsm-generate` runs in a `golang:1.25.3-bookworm` container. |
| **pnpm 10** (via corepack) | Building/running the UI | `corepack enable` from any Node 18+ install. CI pins `pnpm@10.18.0`. |
| **Xcode 15+** | mac-leash | macOS 14+; requires Apple developer team ID `W5HSYBBJGA` to sign locally with the same bundle IDs. |

## Repo entry points

```bash
make help                # auto-generated target list
make                     # default: build-ui → docker-leash → build
make build               # just the Go binary into ./bin/leash
make build-ui            # rebuild controlui/web → internal/ui/dist (pnpm or docker fallback)
make dev-ui              # cd controlui && make dev   (Next dev server on :3000, ws → 127.0.0.1:18000)
make dev                 # build then run ./bin/leash with DEV_COMMAND (default: codex shell)
                         # flags: V=1|VERBOSE=1 → --verbose; T=1|TRACE=1 → TRACE=1 env
make test                # test-unit + test-e2e + test-ui
make test-go             # `go test ./...` (alias: test-unit)
make test-web            # vitest in controlui/web
make test-e2e            # ./test_e2e.sh (heavy — builds images first)
make lsm-generate        # eBPF Go bindings (in Docker on non-Linux)
make clean               # clean-go + clean-ui + clean-docker
```

`make precommit` installs the local git hooks under `build/.hooks/` (pre-commit guards against committing large binaries).

## leash-core (Go)

### Fast iteration loop

```bash
# In one terminal:
make dev-ui            # Next dev server on :3000, expects daemon WS at :18000
# In another:
make dev V=1           # build + run leash with the default agent command
```

`make dev` runs the binary against the workspace's default agent (`codex shell` unless `DEV_COMMAND` is overridden). For a fast non-Docker iteration:

```bash
go run ./cmd/leash --darwin help                  # macOS native subcommand listing
go run ./cmd/leash --version
LEASH_DISABLE_TELEMETRY=1 go test ./internal/...  # unit tests, skip telemetry sends
```

### Common pitfalls

- **`internal/lsm/*_bpf*.go` are generated.** Don't edit; run `make lsm-generate`. They're cleaned by `make clean-go`.
- **`internal/entrypoint/bundled_linux_*_gen.go` are generated.** Run `make generate-entrypoint-if-missing` (or just `make build` which does it).
- **`internal/ui/dist/` is generated.** Don't commit. Built by `make build-ui`.
- **Don't `go build ./cmd/leash` without the entry-point gen** — runner will fail to extract leash-entry at runtime.

### Adding a new endpoint

1. Add handler + route in `internal/leashd/http_api.go` (or `darwind` if macOS-only).
2. Update [`api-contracts-leash-core.md`](api-contracts-leash-core.md).
3. Add the corresponding client call in `controlui/web/src/lib/policy/api.ts` and a React Query hook in `use-policy-query.ts`.

### Adding a new LSM action

1. Define the Cedar Action and the IR operation mapping in [`design/CEDAR.md`](design/CEDAR.md) (update the table).
2. Implement the BPF program (`internal/lsm/bpf/lsm_<op>.bpf.c`) and Go module (`internal/lsm/<op>.go`).
3. Wire it into `LSMManager.UpdateRuntimeRules` in `internal/lsm/manager.go`.
4. Extend `internal/transpiler/cedar_to_leash.go` with the action dispatcher.
5. Run `make lsm-generate && make build`.
6. Add an end-to-end test in `e2e/integration/`.

## controlui-web (Next.js)

### Local dev

```bash
cd controlui/web
pnpm install                # uses pnpm-lock.yaml; corepack-pinned
pnpm dev                    # next dev on :3000
pnpm test                   # vitest run
pnpm lint                   # eslint (uses eslint.config.mjs)
```

For the dev server to actually receive events you need a daemon running. Either:
- `make dev-ui` from the repo root (Next on :3000, expects `ws://127.0.0.1:18000`), and run `./bin/leash --daemon ...` in another terminal; or
- Use the simulation mode in `src/lib/mock/sim.tsx` — toggle "Sim" in the UI's DataSourceControls.

### Build & embed cycle

`pnpm build` emits the static export to `controlui/web/.next/`; the helper `scripts/build-if-changed.mjs` copies it to `internal/ui/dist/` only when the input hash changed (`/cache/controlui.buildhash`). The Go side picks it up via `//go:embed dist/**` (`internal/ui/embed.go`).

When updating UI assets:

```bash
make build-ui              # rebuilds dist + writes to internal/ui/dist
make build                 # repackages leash binary with the new dist
```

### Style + structure

- Server-state goes through React Query — see [`architecture-controlui-web.md § State`](architecture-controlui-web.md#3-state-architecture).
- All daemon calls must go through `src/lib/policy/api.ts` (centralised error parsing + base URL).
- shadcn primitives live in `src/components/ui/`; add via `npx shadcn@canary add <component>` or via `controlui/Makefile`'s `make ui-add-base`.
- Tailwind v4 — config in `postcss.config.mjs`; no `tailwind.config.*` file.

## mac-leash (Swift)

```bash
open mac-leash/Leash.xcodeproj
```

Build & run from Xcode against a local team that controls bundle IDs `com.strongdm.leash.*`. For local builds without the StrongDM team, override via env at compile time:

```bash
export LEASH_BUNDLE_IDENTIFIER=com.you.leash.dev
export LEASH_TEAM_IDENTIFIER=XXXXXXXXXX
xcodebuild -project mac-leash/Leash.xcodeproj -scheme Leash
```

System extension activation requires user approval in **System Settings → General → Login Items & Extensions**. `LeashES` additionally needs Full Disk Access (Privacy & Security pane).

Test against a running daemon:

```bash
./bin/leash --darwin -serve :18080    # in one terminal
open mac-leash/Leash.xcodeproj         # build & run Leash.app from Xcode
```

The WebSocket transport defaults to `ws://127.0.0.1:18080/api`; override via `LEASH_WS_URL` for testing against a remote daemon.

## End-to-end tests

```bash
make test-e2e              # delegates to ./test_e2e.sh after make test-deps
```

`test-deps` first runs `make build-ui`, `make generate-entrypoint-if-missing`, and `make lsm-generate` so the binary is ready. The test suite (`e2e/`):

- `boot_test.go` — bootstrap happy path, stale-marker handling, timeout, private-dir isolation.
- `complete_test.go` — `/api/policies/complete` subtests including concurrent and 200-line input.
- `integration/integration_test.go` — containerized policy enforcement across deny/allow scenarios (gracefully degrades to "lite mode" if cgroup namespace isn't available).
- `mcpserver/` — JSON-RPC + SSE test stub used by integration tests.

To run a single test:

```bash
go test ./e2e -run TestBootstrapTimeout -v
```

## Formatting & hygiene

- Go: `make fmt` (installs `goimports` if missing; runs over all tracked `*.go` excluding `.scratch/`).
- Web: `pnpm lint`, no auto-formatter committed.
- Swift: rely on Xcode formatter.
- Pre-commit: `make precommit` enables the hooks in `build/.hooks/` which currently guard against committing large binary files.

## Environment variables worth knowing

| Variable | Effect |
|---|---|
| `LEASH_TARGET_IMAGE` | Override default target container image |
| `LEASH_IMAGE` | Override leash manager container image |
| `LEASH_POLICY_FILE` / `LEASH_POLICY` | Cedar policy file path |
| `LEASH_LISTEN` | Control UI bind (`:18080` default; blank disables) |
| `LEASH_BOOTSTRAP_TIMEOUT` | Bootstrap wait (default `2m`) |
| `LEASH_PRIVATE_DIR` | Manager-private mount root (`/leash-private` in container) |
| `LEASH_DIR` | Public mount root (`/leash` in container) |
| `LEASH_PROXY_PORT` | MITM proxy port (`18000` in container) |
| `LEASH_ENTRY_BIN` | Fallback leash-entry binary path (skip embedded blobs) |
| `LEASH_DISABLE_TELEMETRY` | Any non-empty value disables Statsig |
| `LEASH_OTEL_METRICS`, `LEASH_OTEL_TRACES`, `LEASH_OTEL_ENDPOINT`, `LEASH_OTEL_HEADERS`, `LEASH_OTEL_PROPAGATE_HTTP_HEADERS` | OpenTelemetry config |
| `LEASH_BUNDLE_IDENTIFIER`, `LEASH_TEAM_IDENTIFIER` | mac-leash bundle/team overrides |
| `LEASH_WS_URL` | mac-leash WebSocket override (default `ws://127.0.0.1:18080/api`) |
| `DOCKER` | Container runtime override (`docker`/`podman`) |
| `VERBOSE`, `V`, `TRACE`, `T` | `make dev` flag forwarding |

Per-tool API keys (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, `DASHSCOPE_API_KEY`) are auto-forwarded by the runner when present in the host shell.

## Versioning

`build/versionator.py` computes:

```bash
./build/versionator.py bin     # "1.2.3" (drops the v) for binary builds
./build/versionator.py tag     # "v1.2.3" or "dev-ab12cd3[-dirty]"
./build/versionator.py minor   # numeric minor
```

The Makefile, release scripts, and Docker builds all delegate to this script. Local builds embed `dev-<shortSHA>[-dirty]` automatically.
