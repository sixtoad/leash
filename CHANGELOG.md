# Changelog

All notable changes to the `walk-integration` (downstream) build of leash.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/). The
container-free **native runtime** is developed on the upstream-eligible slice
`feat/runtime-native-poc` and merged here; walk adds the native-by-default and
Claude Code handling on top.

## [Unreleased]

### Added — build & compatibility document
- **`leash version --json`** (also `--output json`): the build metadata as a
  machine-readable document — `version`, `commit`, `builtAt`, `enforcing`,
  `contractVersion`, `minCompatibleContract`, `capabilities`, `os`, `arch` — so
  a provisioner (`walk install leash`, a CI image) can verify an installed leash
  before driving it. On a plain `go build` with no ldflags, `version` is the
  literal `dev` and `commit`/`builtAt` are the literal `unknown`: documented
  sentinels, not errors.
- **A checkable compatibility contract, in an importable package.** The
  contract type and helpers live in
  [`pkg/leashversion`](pkg/leashversion) — outside `internal/`, so a consumer in
  another Go module (walk is `github.com/sixto/walk`) can actually import them;
  Go's internal rule would have forbidden it from `internal/version`, which
  remains leash's own CLI/rendering layer. The document carries both bounds of
  the CLI surface leash serves: a caller written against contract `C` proceeds
  iff `minCompatibleContract <= C <= contractVersion`. A leash with no
  `version --json` at all is contract `0`. `leashversion.Parse` decodes the
  installed binary's stdout and `Info.SupportsCaller` / `CheckCaller` return the
  verdict (`compatible` / `leash-too-old` / `leash-too-new`), so callers neither
  hand-roll the comparison nor accidentally check their own compiled-in
  constants. Documented in
  [`docs/api-contracts-leash-core.md`](docs/api-contracts-leash-core.md) and
  [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md).
- **`capabilities`**, an additive string array naming the CLI surface a
  provisioner drives (`policy`, `inject-service`, `runtime`, `user`,
  `require-lsm`, `version-json`). The integer over-refuses — raising
  `minCompatibleContract` for one removal turns away every older caller,
  including those that never used the removed flag — so `Info.HasCapability`
  lets a caller ask about the surface it actually needs. Adding a name is
  non-breaking and does not bump `contractVersion`.
- **`leash version --help` / `-h`**: usage on stdout, exit 0. Contradictory or
  empty format specs are rejected with a diagnostic instead of silently
  resolving by last-one-wins — including a flag *repeated* with contradictory
  values (`--output json --output text` in either order, `--json --json=false`),
  which `flag.FlagSet.Visit` cannot see because it reports a repeated flag once,
  with the last value.

### Changed
- **`enforcing` is derived per platform** rather than a compile-time `true`. It
  reports whether *this binary* carries an enforcement path: `true` on linux
  (eBPF LSM programs + MITM proxy) and `true` on darwin, whose runtime
  constructs and drives the same MITM proxy (`internal/darwind`,
  `NewMITMProxy` / `applyPolicyToProxy`) alongside the separately installed
  Endpoint Security / Network Extension components. Any other target reports
  `false`.
- **Every build path that stamps a commit now appends the `-dirty` marker** when
  the tree is modified: `scripts/release.sh`, `scripts/install-leash.sh` and
  `build/publish-docker.sh` join the Makefile `build` target, so the provenance
  guarantee the document states is one the build system actually implements.
  (`.goreleaser.yaml` needs no marker: `goreleaser release` refuses to build
  from a modified tree at all.) The checks now use
  `git diff-index --quiet HEAD --` rather than `git status --porcelain`, so they
  count tracked files only — the same semantics as the adjacent
  `git describe --dirty`, which stops `version` and `commit` disagreeing about
  one tree over an untracked file — and they fail **closed**: a git that errors
  is stamped `-dirty` with a warning instead of being read as pristine. The
  marker is appended only when the commit lookup succeeded, so the `dev`
  fallback never becomes `dev-dirty`.
- **`make build` now stamps `-X main.version`** (`git describe --tags --always
  --dirty`, or `dev`). Locally built binaries previously always reported
  `version: dev` regardless of the checkout.
- **`leash version` is now a subcommand.** It previously fell through to the
  workload CLI, where it would have been treated as a command to run in the
  box; `leash version [--json|--output json|text] [--help]` now handles it, and
  anything else after `version` is rejected rather than passed through.
- `leash --version` human output is **unchanged for every value the repo's build
  paths emit** — 7-hex hashes, `hash-dirty`, full 40-char SHAs, and the `dev` /
  `unknown` sentinels — verified byte-for-byte against the pre-change rendering.
  It is *deliberately different* for values those paths do not produce: only the
  hash component is abbreviated now, so a `git describe` string renders as
  `v1.2.3-4-gabc1234` instead of the fragment `v1.2.3-`, and a short
  `abc-dirty` renders as `abc` instead of `abc-dir`. The old output named a
  build that does not exist; that is the point of the change, not a regression.

## [native-v0.1.0] — 2026-07-04

First distributed build. Container-free native enforcement on Linux, made the
default, with turnkey Claude Code sandboxing. Verified end-to-end on-device.

### Added — native runtime (Linux, container-free)
- **`--runtime native`**: run the workload directly on the host — no container —
  in a delegated systemd cgroup-v2 scope, with `leashd` in **host mode**
  (`--daemon --host`, re-execing the same binary). **Native is the default** on
  walk (OS-detected); no Docker fallback.
- **Layer 1 (eBPF LSM)**: file-open / exec / network-connect enforced on the
  cgroup, uid-independent. Requires the `bpf` LSM active in the kernel.
- **Layer 2 (MITM proxy)** via **netns egress**: the workload runs in a dedicated
  network namespace with a veth pair + host NAT (`MASQUERADE` + IP forwarding) +
  a private-mount-ns `resolv.conf`, entered with `nsenter --net` (preserves
  `/sys/fs/{cgroup,bpf}` — `ip netns exec` would remount `/sys`). HTTPS is
  REDIRECTed to the proxy, decrypted, policy-checked, forwarded out.
- **Workload runs as the invoking user** (`$SUDO_USER` via `runuser`), not root —
  leash/leashd keep root only for enforcement. Lets root-averse agents (e.g.
  Claude Code with `--dangerously-skip-permissions`) run boxed.
- **CA trust for the workload**: leash publishes its MITM CA to a world-readable
  `/tmp` copy and points the workload at it (`NODE_EXTRA_CA_CERTS`), additive to
  system roots.
- **LSM-only fallback**: if netns egress can't be set up, the run degrades to
  host-netns LSM-only (Layer 1 keeps enforcing; no L7 proxy) instead of trapping
  the workload in a netns with no route out. Gated by `nativeLayer2Enabled` /
  `layer2Active`.
- **Fail-closed readiness**: the workload is not launched until all LSM programs
  settle (attached or failed) — fixed a regression where a `defer`-fired settle
  only ran at shutdown.
- **leashd logs to a file** (`/tmp/leash-native-leashd-<netns>.log`) instead of
  the workload's TTY, so an interactive agent's UI isn't corrupted.
- Real **Control UI** embedded (Next.js static export in `internal/ui/dist`).

### Added — Claude Code handling (walk)
- `scripts/leash-claude.sh`: turnkey — generates a workspace-confinement policy
  and runs Claude sandboxed (runs as you, workspace + `~/.claude` only, network
  restricted to Anthropic).
- `docs/CLAUDE-CODE-LEASHED.md`: full recipe — prerequisites, the non-obvious
  policy entries (`~/.claude.json` is the login file; `/tmp` for the CA), the
  **Datadog telemetry** finding (Claude ships logs to `*.datadoghq.com`; blocked
  by the network allow-list), architecture, and troubleshooting.

### Added — distribution
- `scripts/install-leash.sh`: build from source onto a PATH dir.
- `scripts/release.sh` + `scripts/leash-install.sh`: cross-build
  linux/darwin × amd64/arm64, publish a GitHub Release on the fork, and
  `curl | bash` install the matching prebuilt binary.

### Changed — architecture (upstream-clean)
- Onion/ports-and-adapters refactor: upstream files carry minimal generic seams;
  native logic lives in adapters (`launcher_native.go`, `host_ready.go`). The
  runner routes every backend decision through a `launcher` interface — **zero**
  `if native` branches outside the composition root — so the native slice merges
  into walk cleanly.

### Known limitations
- **macOS**: the Go binary enforces only on Linux. On mac it's the CLI for a
  separately-installed `Leash.app` (ES + Network Extension), invoked via
  `leash --darwin`. Walk's macOS Claude handling is not yet written/verified.
- The `nft` control-plane-isolation rule fails to parse the cgroup path (upstream
  [strongdm/leash#83](https://github.com/strongdm/leash/issues/83)); its fallback
  is harmless inside the netns.
- `Leash UI: http://localhost:18080/` is printed even under Layer 2, where the UI
  is actually at the netns IP.
- Non-Node tools don't pick up `NODE_EXTRA_CA_CERTS`; appending leash's CA to the
  system bundle is pending.
