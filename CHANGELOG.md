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
  `contractVersion`, `minCompatibleContract`, `os`, `arch` — so a provisioner
  (`walk install leash`, a CI image) can verify an installed leash before
  driving it. `version` and `builtAt` are the literal `unknown` on a plain
  `go build`: a documented sentinel, not an error.
- **A checkable compatibility contract.** The document carries both bounds of
  the CLI surface leash serves: a caller written against contract `C` proceeds
  iff `minCompatibleContract <= C <= contractVersion`. A leash with no
  `version --json` at all is contract `0`. `version.Info.SupportsCaller` /
  `CheckCaller` implement the rule (`compatible` / `leash-too-old` /
  `leash-too-new`) so callers do not hand-roll it. Documented in
  [`docs/api-contracts-leash-core.md`](docs/api-contracts-leash-core.md) and
  [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md).
- **`leash version --help` / `-h`**: usage on stdout, exit 0. Contradictory or
  empty format specs (`--json --output text` in either order, `--output=`) are
  rejected with a diagnostic instead of silently resolving by last-one-wins.

### Changed
- **`enforcing` is derived per platform** rather than a compile-time `true`: it
  reports whether *this build* ships the in-binary enforcement path (eBPF LSM +
  MITM proxy), so the darwin binary — whose enforcement lives in the separately
  installed Endpoint Security / Network Extension components — no longer
  advertises the Linux path.
- **`scripts/release.sh` and `scripts/install-leash.sh` stamp the `-dirty`
  marker** on `main.commit` when built from a modified tree, matching the
  Makefile and making true the provenance guarantee the document states: a
  binary cut from a dirty tree cannot report the pristine commit.
- `leash --version` human output is unchanged (byte-for-byte). Only the hash
  component is abbreviated now, so a `git describe` value or a short
  `hash-dirty` string is no longer cut into a fragment naming a different build.

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
