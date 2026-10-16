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

### Added — doctor probes BPF-LSM attachability instead of guessing
- **`lsm_bpf_attachable` in `leash doctor --json`**: doctor now loads leash's
  *real* LSM programs, lets the kernel's verifier judge them, attaches one and
  detaches it immediately — `attachable` / `unattachable` / `unknown`. Reading
  `bpf` out of `/sys/kernel/security/lsm` is a proxy for that question, and a
  kernel can list `bpf` and still refuse the programs: the verifier can reject
  `bpf_d_path`, BTF can be absent, ring buffer creation can fail, or a program
  can exceed the instruction limit (leash's own hard-link guard hit that ceiling
  in issue #29). Such a host used to report `lsm_bpf: active` and `ready`; it now
  reports `degraded` and names the kernel's reason (issue #52).
- **Attachability narrows the Layer 1 verdict; it never widens it.** The two
  signals are conjunctive: `bpf` must be in the active LSM list *and* the
  programs must attach. An `inactive` list is decisive whatever the probe saw,
  because `attachable` does not mean what it looks like there — a
  `BPF_PROG_TYPE_LSM` program loads and attaches perfectly well on a
  `CONFIG_BPF_LSM=y` kernel that was not booted with `bpf` in `lsm=`, and the
  hook is then never invoked, so the successful attach enforces nothing. Where
  that combination occurs the `issues` text says it out loud rather than leaving
  a reader to reconcile `lsm_bpf: inactive` with
  `lsm_bpf_attachable: attachable`.
- **The probe uses the shipped programs, not a stand-in.** It goes through the
  same `loadLsmOpen` → `ebpf.NewCollection` → `link.AttachLSM` path a real run
  takes, including the optional-hook handling, so what doctor tests cannot drift
  from what leash runs. A toy program that verifies while the real ones do not is
  the exact failure this replaces.
- **A verifier rejection and an attach rejection are told apart**, because the
  remedies do not overlap: the first means this kernel cannot run leash's
  programs at all (BTF, `bpf_d_path`, the instruction limit), the second means
  the programs are fine and the kernel is not accepting BPF LSM attachments.
- **`EPERM`/`EACCES` is `unknown`, never `unattachable`.** That is a statement
  about doctor's own privileges, not about the kernel; an unprivileged run can no
  more condemn a host than bless one, and the verdict falls back to the list read
  exactly as before.
- **`--quick` opts out; there is no `--deep` to opt in.** The honest answer is
  the default answer. A skipped or unsettled probe leaves `bpf_lsm_attachable` in
  `unchecked` with the reason named (`--quick`, or insufficient privilege).
- **It leaves nothing behind.** Independent collection, every descriptor and link
  released on every path including panic, bounded in time, and fail-soft: any
  outcome that is not a clean verdict degrades to `unknown` rather than erroring,
  hanging, or taking the report down with it. Running it while leash is enforcing
  does not touch the live programs.

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
  omitted: `bpf_lsm_attachable` (now answered by the attachability probe above,
  and still declared whenever that probe did not settle it),
  `bpf_d_path_ringbuf`, `netns_iptables`, plus `capabilities` and
  `container_kernel` when they apply.
- **`default_runtime` is in the document.** The verdict is the best state any
  runtime reaches, but a bare `leash run` selects one runtime (`native` here)
  and never falls back, so a host where only the *other* runtime works would
  read as unqualified good news. The document names the default and the human
  output warns when it is not the runtime the verdict is about.

### Changed — fail closed by default when the eBPF LSM can't attach (#117)
- **Behavior change.** When the eBPF LSM (Layer 1) cannot attach — kernel
  without an active `bpf` LSM, rootless podman, or no scopable cgroup — leash
  now **refuses to run the workload** instead of warning and continuing
  proxy-only. This applies to the client preflight, native readiness, and
  leashd (container and host mode).
- **New opt-out: `--allow-proxy-only`** (env `LEASH_ALLOW_PROXY_ONLY=1`, also a
  leashd flag) restores the old degrade: warn and continue with only the
  fail-closed L7 proxy; filesystem/exec/socket policies are then not enforced.
- **`--require-lsm` / `LEASH_REQUIRE_LSM` stay accepted** (and the
  `require-lsm` capability stays advertised) but are now redundant. A falsy
  `LEASH_REQUIRE_LSM` does not opt out. Flags beat env vars; asking for both
  fail-closed and proxy-only at the same level is an error.
- **New capability `allow-proxy-only`** in `leash version --json`; its presence
  means this build fails closed by default.
- **`contractVersion` is now `2`** (contract 2 = fail-closed-by-default posture
  plus `--allow-proxy-only`). `minCompatibleContract` stays `0`: nothing was
  removed, so callers written against contract 0 or 1 (e.g. Walk's
  `walkLeashContract=1`) remain compatible.
- **Effective enforcement level is machine-readable.** The enforcement-ready
  marker (still gated on by existence) is now a JSON document
  `{"enforcement":"lsm"|"proxy-only"|"none","layer1":…,"layer2":…,"requireLSM":…,"allowProxyOnly":…}`,
  leashd logs an `enforcement.level` event, and the client prints
  `leash: enforcement=<level> layer1=<state> layer2=<state>` on the diagnostic
  stream (always under `--machine-output`, always when not `lsm`).
- The client now always tells leashd its resolved posture
  (`LEASH_REQUIRE_LSM=1` or `LEASH_ALLOW_PROXY_ONLY=1` in the container,
  `--require-lsm` or `--allow-proxy-only` for native leashd), and native
  readiness now honors `LEASH_REQUIRE_LSM` (it previously read only the flag).
- **`--allow-proxy-only` never releases an unenforced workload.** When the L7
  proxy is also off (native `--lsm-only`: rootless, or egress setup failed),
  there is nothing to degrade to, so an LSM attach failure stays fatal and
  native readiness refuses. leashd also refuses to publish the ready marker for
  a level the posture forbids — `none`, or anything but `lsm` under
  fail-closed, including when no LSM program attached at all.
- **The client cross-checks leashd's reported level** against its own posture
  and refuses to release on a mismatch, and rejects posture overrides that
  would make the two diverge: `-e LEASH_REQUIRE_LSM` / `-e
  LEASH_ALLOW_PROXY_ONLY` and posture flags inside `LEASH_EXTRA_ARGS`.
- The enforcement-ready marker is written atomically (temp file + rename).
- **Layer 1 is reported active only when the kernel confirms it.** On a kernel
  with `CONFIG_BPF_LSM=y` but `bpf` not in `/sys/kernel/security/lsm` (Ubuntu
  24.04's default) the LSM programs attach and are never invoked; leashd now
  also requires `bpf` in the active list (an unreadable list counts as not
  active), so that case fails closed by default and reports `proxy-only` with
  a `reason` under `--allow-proxy-only`. The client's own preflight can only
  narrow the reported level, and a native refusal now echoes leashd's FATAL
  reason instead of only pointing at the log.

### Fixed — HTTP/2 clients bypassed header rewrite and MCP enforcement (#57)
- **Full HTTP/2 MITM.** The proxy used to offer `h2, http/1.1` to every client
  and tunnel any h2 connection opaquely, so header-rewrite rules, MCP
  `tools/call` policy and MCP observability never saw requests from h2 clients
  (curl, browsers, gRPC, most SDKs). Only the connect allow/deny applied. Now,
  when a request-level feature applies to the SNI host (a rewrite rule for the
  host, any MCP policy, or MCP observability not `off`), the proxy terminates
  h2. Each stream gets the same handling as an HTTP/1.1 request (MCP sniff and
  enforcement, header rewrite, `http.request`/`mcp.*` logging), then goes
  upstream over h2, or HTTP/1.1 when the origin lacks h2. Bodies stream both
  ways (SSE, gRPC, large uploads); trailers, flow control and concurrent
  streams are kept. An MCP denial answers only its own stream. Each stream's
  `:authority` goes through the same verified-authority check as HTTP/1.1
  (#149): a mismatch gets `421` before any rewrite, so coalesced h2
  connections cannot carry requests past the connect policy. Rewrite and MCP
  policy use the verified host. Upstream connections dial the destination the
  connect policy permitted (#154: the original IP, with SNI preserved, when
  only an IP rule permitted it). The pool is per client connection, so it is
  never shared across connections with different permitted destinations. Hosts with no
  request-level feature keep the opaque h2 tunnel. Same code on Linux and macOS
  (darwind runs this proxy behind the transparent-proxy extension).
- **`LEASH_PROXY_H2=inspect|downgrade`** (default `inspect`). `downgrade` is an
  escape hatch: inspected hosts are offered only `http/1.1`, so connections take
  the HTTP/1.1 path. An h2-only client (gRPC) to a host with a rewrite rule or
  MCP policy is refused at the handshake rather than tunneled past the rule.
  See [`docs/CONFIG.md`](docs/CONFIG.md#proxy-http2-handling-leash_proxy_h2).
- Each ALPN decision for a client that offered h2 is logged as
  `event=http.alpn` with `alpn_offered`, `alpn_advertised`, `alpn_negotiated`,
  `alpn_mode` (`inspect`/`tunnel`/`downgrade`/`refuse`) and `reasons`.

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
- **Behavior change — egress is denied when a policy has no `NetworkConnect`
  rules (#118).** The kernel connect LSM is now always created and attached.
  Previously a policy with file/exec rules but no network rules never attached
  it, so every outbound IPv4 connection that was not redirected through the
  proxy (anything other than TCP 80/443, including raw TCP and UDP) was
  allowed. The kernel default now mirrors the proxy's default: **deny**, unless
  the policy explicitly permits network access
  (`permit (principal, action == Action::"NetworkConnect", resource) when { resource in [ Host::"*" ] };`)
  or sets an explicit default. As with policies that already had connect rules,
  this also denies DNS and loopback from the target unless the resolver /
  address is permitted. Policies that relied on the old implicit allow must add
  explicit `NetworkConnect` permits.
- **Connect policy reloads that drop to zero kernel rules now take effect.**
  The rule count was only written when there were rules, so removing the last
  connect rule (or a reload whose hostnames all failed to resolve) left the
  previously loaded kernel rules live — the kernel kept allowing an IP the
  proxy already denied. The count is now always written.
- **Known limitation: IPv6 egress is not enforced by the connect LSM.** Both
  hooks (`socket_connect`, `socket_sendmsg`) allow every non-`AF_INET` socket,
  so IPv6 connections from the target are not denied by the kernel layer,
  with or without connect rules.
- **Behavior change — file opens and execs are denied when a policy has no
  file / exec rules.** The kernel file-open LSM (which also carries the
  directory-mutation and link hooks) and the exec LSM are now always created
  and attached, like the connect LSM (#118; this is #139). Previously a policy with no
  `FileOpen*` rules (or no `ProcessExec` rules) never attached that program, so
  the whole category was unenforced, while removing the last rule from an
  already-attached program denied it. The kernel default is now Cedar's:
  **deny**, unless the policy permits the root path
  (`permit (principal, action == Action::"ProcessExec", resource) when { resource in [ Dir::"/" ] };`,
  likewise for the `FileOpen*` actions). Each category is decided only from its
  own rules. The workload's own start (launcher shell, leash helpers, dynamic
  loader and libraries, `/proc`) runs under policy, so a policy must permit what
  the workload needs in every category, as policies with file rules already
  had to. The built-in bootstrap policy (no policy file) permits `Dir::"/"` for
  both and is unaffected.
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
