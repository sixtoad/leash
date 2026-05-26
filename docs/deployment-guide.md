# Deployment Guide

Two pipelines ship leash: container images + standalone binaries (via Goreleaser) and the `@strongdm/leash` npm package. Plus the macOS app distributed through Homebrew/Sparkle. Detailed release runbook lives in [`RELEASE.md`](RELEASE.md); this doc is the operational map across the whole release surface.

> **Adjacent docs:** [`RELEASE.md`](RELEASE.md) (cut-release runbook) · [`CUSTOM-DOCKER-IMAGES.md`](CUSTOM-DOCKER-IMAGES.md) (extending the target image) · [`CONFIG.md`](CONFIG.md) (runtime config volume) · [`MACOS.md`](MACOS.md) (macOS install).

## 1. Artifacts

| Artifact | Channel | Built by |
|---|---|---|
| `leash` binary (linux/darwin × amd64/arm64) | GitHub Releases `leash_<v>_<os>_<arch>.tar.gz` | Goreleaser (`.goreleaser.yaml`) |
| `leash` manager Docker image | `public.ecr.aws/s5i7k8t3/strongdm/leash:{vX.Y.Z,latest}` | `build/publish-docker.sh` via Dockerfile.leash |
| `coder` target image (default agent runtime) | `public.ecr.aws/s5i7k8t3/strongdm/coder:{vX.Y.Z,latest}` | same script via Dockerfile.coder |
| `@strongdm/leash` npm package | npmjs.com, `latest` and `alpha` dist-tags | `build/npm/build_npm_package.py` |
| `Leash.app` (macOS) | Homebrew cask `strongdm/tap/leash-app` | Out-of-tree; uses Sparkle for in-app updates |

The npm wrapper and the macOS app both ultimately re-distribute the Goreleaser tarballs.

## 2. CI workflows

### `.github/workflows/tests.yml`

Triggers: every push to `main`, every PR, and `workflow_call`. On `ubuntu-latest` with a 45-minute timeout:

1. Install `clang`, `llvm`, `libbpf-dev`, `pkg-config`.
2. Enable corepack + pin `pnpm@10.18.0`.
3. Set up Go from `go.mod` (currently 1.23 floor; CI fetches latest patch).
4. Restore Go build cache by `go.sum` hash.
5. `make test-deps test-go test-web` — UI build, entrypoint gen, LSM gen, Go tests, Vitest.

### `.github/workflows/release.yml`

Triggers on tags `v*.*.*`. Four sequential jobs:

```
push tag vX.Y.Z
   └─ verify       (preflight: build + test + Docker staging push)
       └─ release  (Goreleaser cross-build + Docker promote)
           └─ stage-npm   (build .tgz from goreleaser dist)
               └─ publish-npm  (trusted publishing via OIDC)
```

**verify** — ubuntu-latest. Logs into ECR Public (OIDC role `AWS_ECR_RELEASE_ROLE_ARN`), runs `make lsm-generate && make build-ui && make build`, then `make test-go && make test-web`. Uploads `internal/lsm`, `internal/ui/dist`, `bin/` as a workflow artifact. Builds + pushes staging Docker images tagged `verify-<run_id>` via `./build/publish-docker.sh` (QEMU + Buildx for linux/amd64 + linux/arm64).

**release** — depends on `verify`. Sets up Go 1.25.2 (note: Dockerfile uses 1.25.3; CI uses 1.25.2 for the local build), QEMU, Buildx. Downloads verify artifacts (so it doesn't re-run lsm-generate / ui-build). Runs Goreleaser via `goreleaser/goreleaser-action@v5` (pinned `v2.12.5`) with `release --clean`. Uploads `dist/` as a workflow artifact. Then re-tags staging Docker images as `vX.Y.Z` and `latest` via `./build/publish-docker.sh "$GORELEASER_CURRENT_TAG"`.

**stage-npm** — pulls the `goreleaser-dist` artifact, installs Node 22 + `uv`, runs `ruff check + format --check` on `build/npm`, then:

```bash
uv run build/npm/collect_vendor_from_dist.py --dist dist --out dist/npm/vendor --force
uv run build/npm/build_npm_package.py --version "$NPM_VERSION" \
    --vendor dist/npm/vendor --stage dist/npm/stage --out dist/npm --force
```

Tarball naming is deterministic: `strongdm-leash-<semver>.tgz`. Uploaded as `npm-package` artifact.

**publish-npm** — only on tag refs. Downloads the staged tarball, computes dist-tag (`alpha` if version contains `-alpha.`, else `latest`), publishes with `--provenance --access public`. Uses trusted publishing — no `NPM_TOKEN` long-lived secret. (Trusted publisher setup steps in [`RELEASE.md § Trusted Publisher Setup`](RELEASE.md#trusted-publisher-setup).)

If any step fails, the workflow halts and no release is published. Fix → re-push the same tag.

## 3. Container image layout (`Dockerfile.leash`)

Multi-stage:

```
build-base   (golang:1.25.3-bookworm + Node 20 + clang/llvm/libbpf-dev + pnpm)
   ↓
build        (compiles UI inside, runs go generate, builds /out/leash and /out/leash-entry)
   ↓
runtime-base (debian:bookworm + bash, busybox, libbpf1, iptables, tcpdump, tini, vim, …)
   ↓
final        (copies the two binaries from build into /usr/local/bin/)
final-prebuilt (variant that skips UI build, assumes internal/ui/dist already populated)
leash-test-{alpine,debian,rocky}  (lightweight targets used by integration tests)
```

ENTRYPOINT is `/usr/bin/tini -- /usr/local/bin/leash --daemon`. Env defaults:

```
LEASH_LOG_DIR=/log
LEASH_CFG_DIR=/cfg
LEASH_LOG=/log/events.log
LEASH_POLICY=/cfg/leash.cedar
LEASH_PROXY_PORT=18000
```

`make docker-leash` builds `final`; `make docker-leash-prebuilt` builds `final-prebuilt` (used by the release pipeline after Goreleaser produces the dist). Both publish under channel tags computed by `build/docker_tags.py`.

## 4. Target image (`Dockerfile.coder`)

`debian:testing-slim` + Node 22 + the supported AI agent CLIs:

- `@anthropic-ai/claude-code`
- `@openai/codex`
- `@google/gemini-cli`
- `@qwen-code/qwen-code`
- `opencode-ai`
- `@upstash/context7-mcp` (MCP server)

Operators wanting their own target image should follow [`CUSTOM-DOCKER-IMAGES.md`](CUSTOM-DOCKER-IMAGES.md): start from `public.ecr.aws/s5i7k8t3/strongdm/leash:latest` as the leash-entry source, base on any debian/alpine/rocky-flavoured image with `update-ca-certificates`, copy `/usr/local/bin/leash-entry` into `/bin/leash-entry`, set it as `ENTRYPOINT`.

## 5. Goreleaser config (`.goreleaser.yaml`)

```yaml
project_name: leash
before.hooks:
  - go mod download
  - make lsm-generate
  - go generate ./internal/entrypoint/...
builds:
  - id: leash
    main: ./cmd/leash
    binary: leash
    goos:   [linux, darwin]
    goarch: [amd64, arm64]
    env:    [CGO_ENABLED=0]
    flags:  [-trimpath]
    ldflags:
      - -X main.version={{ .Version }}
      - -X main.commit={{ .ShortCommit }}
      - -X main.buildDate={{ .Date }}
archives:
  - id: leash
    name_template: '{{ .ProjectName }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}'
    formats: [tar.gz]
release:
  replace_existing_draft: true
  prerelease: false
checksum.disable: true
```

`CGO_ENABLED=0` for the released binary means **the eBPF programs are loaded at runtime via libbpf**, not compiled into the binary. The actual BPF C source compiles during `make lsm-generate` and the resulting `*_bpf*.o` blobs are embedded as Go strings by `bpf2go`.

## 6. npm packaging (`build/npm/`)

Two Python scripts (linted by ruff):

- `collect_vendor_from_dist.py` — pulls the goreleaser-built tarballs into `dist/npm/vendor`, organized per OS/arch.
- `build_npm_package.py` — composes the npm tarball:
  - Copies `npm/leash/{package.json, bin/, README.md, LICENSE}` into `dist/npm/stage/`.
  - Adds the vendored binaries under `vendor/`.
  - Stamps the semver into `package.json`.
  - Emits `strongdm-leash-<semver>.tgz` ready for `npm publish`.

`npm/leash/package.json` declares `bin.leash = bin/leash.js`. The shim script resolves the right vendored binary at install time based on `process.platform`/`process.arch`.

`engines.node >= 18`; supported `os: [darwin, linux]` × `cpu: [x64, arm64]`.

Dist-tag policy:
- `vX.Y.Z` → `--tag latest`.
- `vX.Y.Z-alpha.N` → `--tag alpha`.

Consumers install via:

```bash
npm install -g @strongdm/leash         # stable
npm install -g @strongdm/leash@alpha   # prerelease
```

Manual fallback (if trusted publishing breaks): documented step-by-step in [`RELEASE.md § Manual Fallback`](RELEASE.md#manual-fallback).

## 7. macOS distribution

Outside the GitHub Actions pipeline:

- **Homebrew cask** — `brew tap strongdm/tap && brew install --cask leash-app`. Installs `Leash.app` into `/Applications`.
- **Sparkle in-app updates** — `Leash/SparkleUpdater.swift` reads `SUFeedURL` from Info.plist (AWS S3 appcast). Background update check ~10s after launch.
- **System extensions** — bundled inside `Leash.app/Contents/Library/SystemExtensions/`. Activation requires user approval in System Settings (see [`MACOS.md`](MACOS.md)).
- **Notarisation / signing** — handled by the macOS release pipeline (out of repo).

## 8. Runtime configuration on a deployed host

| Artifact | Location |
|---|---|
| Per-user config | `$XDG_CONFIG_HOME/leash/config.toml` (or `~/.config/leash/config.toml`) |
| Per-project overlay | `<cwd>/.leash.toml` (commit `fd8e0c1`) |
| Cedar policy file | `--policy` flag, `LEASH_POLICY_FILE` env, or `/cfg/leash.cedar` inside the manager container |
| Shared volume (public) | `/leash` (mode 0755, bind-mounted into both containers) |
| Manager-private volume | `/leash-private` (mode 0700, manager container only) |
| Event log | `LEASH_LOG=/log/events.log` (configurable) |

For the trust-boundary details around the public/private split, see [`design/SECURITY-MODEL.md`](design/SECURITY-MODEL.md).

## 9. ECR-public URL summary

| Image | Tags |
|---|---|
| `public.ecr.aws/s5i7k8t3/strongdm/leash` | `vX.Y.Z`, `latest`, `verify-<run_id>` (staging) |
| `public.ecr.aws/s5i7k8t3/strongdm/coder` | `vX.Y.Z`, `latest`, `verify-<run_id>` (staging) |

Both manifests are multi-arch (linux/amd64 + linux/arm64). Pulls are anonymous.

## 10. Troubleshooting a failed release

1. **Verify job failed:** likely a unit/UI test regression — fix locally, push to main, then re-tag.
2. **Goreleaser failed:** check `lsm-generate` ran in verify (it should, since it's listed in `before.hooks`). The lsm artifacts may be stale.
3. **Docker push failed:** AWS OIDC role missing or expired; check `AWS_ECR_RELEASE_ROLE_ARN`.
4. **stage-npm ruff failed:** lint-fix the python scripts under `build/npm/` and re-tag.
5. **publish-npm provenance failed:** trusted publisher likely unconfigured for the scope; fall back to the manual `npm publish` path in [`RELEASE.md`](RELEASE.md).
