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
- **A checkable compatibility contract, published as a rule rather than as a
  package.** The document carries both bounds of the CLI surface leash serves: a
  caller written against contract `C` proceeds iff
  `minCompatibleContract <= C <= contractVersion`. A leash with no
  `version --json` at all is contract `0`. The rule, the value domains, the
  contract-0 handling and a decode-the-installed-binary snippet (with a struct
  the *consumer* owns — leash exports no Go type for this) are in
  [`docs/api-contracts-leash-core.md`](docs/api-contracts-leash-core.md), with
  the bump policy in [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md). The
  implementation stays in `internal/version`: the emitted JSON is the contract,
  the Go type is not, so leash can refactor it without shipping a `/v2`.
  Decoding is fail-closed — `null`, `{}` and any object missing `version` /
  `contractVersion` are rejected rather than yielding a zero contract range that
  a contract-0 caller would read as compatible.
- **`capabilities`**, an additive string array naming the CLI surface a
  provisioner drives (`policy`, `inject-service`, `runtime`, `user`,
  `require-lsm`, `version-json`). The integer over-refuses — raising
  `minCompatibleContract` for one removal turns away every older caller,
  including those that never used the removed flag — so a caller can test the
  array for the one surface element it actually drives instead. Adding a name is
  non-breaking and does not bump `contractVersion`.
- **`leash version --help` / `-h`**: usage on stdout, exit 0. Contradictory or
  empty format specs are rejected with a diagnostic instead of silently
  resolving by last-one-wins — including a flag *repeated* with contradictory
  values (`--output json --output text` in either order, `--json --json=false`),
  which `flag.FlagSet.Visit` cannot see because it reports a repeated flag once,
  with the last value.

### Added — node readiness self-check
- **`leash doctor` / `leash doctor --json`**: one command answering the question
  a provisioner (`walk install leash`, a CI image) had been guessing at with its
  own coarse probes — *can this machine actually enforce?* — per runtime. It
  delegates to the same classifiers a real run uses (`ProbeBPFLSM`,
  `NativeRuntimeAdvice`, `HostHasSystemd`, `DetectContainerEngine`), so a
  `ready` from doctor and a successful `leash run` cannot drift apart. The JSON
  shape, the three states and the exit codes are documented in
  [`docs/api-contracts-leash-core.md`](docs/api-contracts-leash-core.md).
- **A third state, `degraded`, because two states lied.** A host whose engine
  works but whose kernel has no active `bpf` LSM starts workloads with Layer 1
  (filesystem/exec/socket policy) silently off and only the fail-closed proxy
  running. That is neither `ready` nor "cannot run", so it has its own state and
  its own exit code (`3`), with the consequence named in `issues`. `ready` is
  never widened to include it — and, symmetrically, a Linux host that is
  degraded only by its kernel is no longer reported as unable to run at all.
- **An unprobed kernel is never `ready`.** Off Linux, containers run against a
  VM kernel doctor did not read (Docker Desktop's LinuxKit kernel has no `bpf`
  LSM), and with `DOCKER_HOST` set they run on a remote daemon's kernel — which
  is exactly why `preflightHostKernel` already refuses to draw a conclusion
  there. Both report `degraded` with a `container_kernel` entry in `unchecked`
  rather than borrowing this host's verdict. No remote topology is modelled.
- **Capabilities are observed, never inferred.** An unreadable or unparseable
  `/proc/self/status` yields *unknown, and therefore not ready* — never "root,
  so it must hold CAP_BPF", which is wrong in precisely the environments that
  would consult it (darwin; a container with a masked `/proc`).
- **Prerequisites doctor does not check are named in the output**, not silently
  omitted: `bpf_lsm_attachable` (the check is list-based, not an attach probe —
  issue #52), `bpf_d_path_ringbuf`, `netns_iptables`, plus `capabilities` and
  `container_kernel` when they apply.
- **`default_runtime` is in the document.** The verdict is the best state any
  runtime reaches, but a bare `leash run` selects one runtime (`native` here)
  and never falls back, so a host where only the *other* runtime works would
  read as unqualified good news. The document names the default and the human
  output warns when it is not the runtime the verdict is about.

### Fixed — remedy text that could break the host
- **`leash doctor` could tell an operator to set `lsm=,bpf`** — a leading-comma
  kernel command line that *replaces* the host's LSM stack, silently disabling
  AppArmor/SELinux or leaving the machine unbootable. Two separate paths reached
  it: a read error on `/sys/kernel/security/lsm` swallowed into a nil list, and
  — reproduced on the development host — a readable but **empty or
  whitespace-only** list, which `strings.Split` turns into `[]string{""}` with
  no error at all. The state is now `unknown` whenever the list is unusable, and
  `bpfLSMAdvice` itself refuses to emit an `lsm=` example it cannot build from a
  real list, so the run path (`preflightHostKernel`) is covered too.
- **Engine stderr is sanitized before it reaches the report.** `docker info`
  output is pasted verbatim into an issue; ANSI escapes and carriage returns in
  it could repaint the readiness report a reader is consulting precisely because
  they do not trust the machine.
- **`doctor.Report` decodes as well as encodes.** It was marshal-only: a Go
  consumer's `json.Unmarshal` failed, and one that ignored the error held a zero
  `Report` — which re-encodes as `verdict: unavailable, ready: false` from a
  document that said `ready`. Round-tripping is now identity, with the derived
  fields recomputed from the statuses rather than trusted from the document.

### Changed
- **`enforcing` is derived per platform** rather than a compile-time `true`. It
  reports whether *this binary* carries an enforcement path: `true` on linux
  (eBPF LSM programs + MITM proxy) and `true` on darwin, whose runtime
  constructs and drives the same MITM proxy (`internal/darwind`,
  `NewMITMProxy` / `applyPolicyToProxy`) alongside the separately installed
  Endpoint Security / Network Extension components. Any other target reports
  `false`.
- **The `-dirty` marker is documented as best-effort, not as a guarantee.** The
  docs previously claimed every build path appends it when the tree is modified;
  they no longer do, and no build path changed. Only the Makefile `build` target
  stamps the marker; `scripts/release.sh`, `scripts/install-leash.sh`,
  `build/publish-docker.sh` and `.goreleaser.yaml` stamp the bare hash. Its
  presence means the tree was modified — **its absence is not proof of a clean
  tree**, and a consumer must not treat it as provenance. The documented value
  domain of `commit` also now names the literal `dev`, which several paths emit
  when `git rev-parse` fails, so a caller validating against the published set
  no longer rejects a legitimate build.
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
