# Changelog

All notable changes to the `sixtoad/leash` fork, released as `native-vX.Y.Z`
(`scripts/release.sh`, docs/RELEASE.md). Format loosely follows
[Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added
- **MCP policies can read the call's arguments** (#113). `Action::"McpCall"`
  requests carry `context.args` (the top-level string, integer and boolean
  arguments, strictly typed and bounded) and `context.argNames`, so a strict
  policy can pin an MCP endpoint to one repository and a retrieval-only tool
  list (the Walk code-indexer capability; shape in `docs/design/CEDAR.md`).
  The authz socket accepts flat records in the context for the same query.
  Advertised as the `mcp-call-args` capability.

### Changed
- **MCP enforcement is fail-closed on ambiguous requests** (#113). While MCP
  policies are active the proxy parses request bodies case-sensitively,
  decides every `tools/call` of a JSON-RPC batch, and denies a JSON request
  it cannot decide unambiguously (invalid JSON, a duplicated key, a malformed
  `tools/call`, a body over 64 MiB) instead of forwarding it unchecked.
  Previously a batch, a body over the 1 MiB sniff limit or an unparseable
  body passed without an MCP decision.

## [native-v0.5.0] — 2026-10-29

Minor release on top of `native-v0.4.1` (PRs #228, #238, #239). It adds one
optional capability, `pin-network-host`; `contractVersion` stays 3 and
`minCompatibleContract` 0, so existing callers are unaffected.

### Added
- **`--pin-network-host` keeps exact-host policies working across DNS
  changes on Linux Docker** (#239). An exact-host rule resolves its addresses
  when the policy loads, so a permitted host whose address later rotated (a
  package registry behind a CDN) failed the kernel connect check. The new
  repeatable flag resolves up to 32 exact hostnames to a bounded IPv4
  snapshot inside the target container before enforcement starts and pins
  them in Docker's shared hosts file, so the manager and both libc and Go
  clients use the same addresses. Policy authority is unchanged, and the pin
  lasts for the container's lifetime (no DNS failover). Native and Podman
  runs reject the flag; wildcards, ports, address literals, a shadowed
  `/etc/hosts`, `container:<id>` networking and an NSS `hosts:` rule not
  starting with `files` are refused. The selected snapshot is reported as
  `event=runner.network-hosts status=pinned`. Advertised as the
  `pin-network-host` capability; callers must check it before passing the
  flag. Default invocations pin nothing.

### Security
- **Symlink creation is policy-checked on Linux** (#226). The new
  `lsm_symlink` program on `security_path_symlink` decides a new symlink's
  name with the directory-mutation table, like mkdir and mknod, before the
  link exists, and writes a `file.symlink` record for every decision. A
  workload can no longer plant a symlink in a directory it has no write
  authority over. macOS already checked `AUTH_CREATE` of a symlink against
  the same table; its events now name the operation `symlink`.

### Fixed
- **The upstream coder-CLI releases watchdog no longer runs in forks**
  (#238).

## [native-v0.4.1] — 2026-10-19

Patch release on top of `native-v0.4.0` (PRs #221–#236), driven by a Layer 2
fail-open in the native runtime on hosts whose `/bin/sh` is bash. No change
to the CLI contract: `contractVersion` stays 3, `minCompatibleContract` 0,
and the `capabilities` list is unchanged.

### Security
- **Layer 2 no longer fails open when `/bin/sh` is bash** (#232, part of
  #208/#209). `apply-nftables.sh` passed the redirect ports as `{80,443}`,
  which bash (`/bin/sh` on Fedora, RHEL, Arch) brace-expands, so nft rejected
  the HTTP/HTTPS redirect rule and the script only warned. The native runtime
  runs the script with the host's `/bin/sh`: it reported `layer2=active`
  while HTTPS went straight to the origin, forbidden MCP `tools/call`s
  succeeded and header rewrites did not apply (the eBPF connect policy still
  held). The port set is now one quoted word, and the HTTP/HTTPS redirect and
  QUIC drop are required rules in both the nftables and iptables scripts: if
  one cannot be applied the script exits with `FATAL`, leashd falls back to
  iptables or refuses to start. Container runs (dash in the manager image)
  were not affected.
- **The native workload keeps no capability it could regain** (#223, #203).
  `--harden-exec` dropped the bounding set after `runuser` had already left
  root, without `CAP_SETPCAP`, so the drop failed silently and the workload
  ran with `CapBnd=000001ffffffffff`. See **Changed**.
- **A denied create no longer leaves a file behind** (#224, #204).
  `open(O_CREAT)`, `touch`, `mknod`, `mkfifo` and unix-socket binds create a
  name through `security_path_mknod` before `file_open` can refuse the open;
  the new `lsm_mknod` program decides that name with the directory-mutation
  table (writable-directory authority, deny precedence, a `file.create` audit
  record), on overlay rootfs, bind mounts and plain filesystems alike. macOS
  `AUTH_CREATE` of a regular file now checks the same table as well.

### Fixed
- **SELinux hosts: `podman exec` / `docker exec` into a governed container
  works** (#231, part of #208). The procfs canonicalizer now recognises the
  OCI runtime's SELinux `attr/exec` and `attr/keycreate` writes (crun and
  runc), which were denied as unprefixed paths, so no run got past "locate a
  usable shell". They still go through the ordinary `/proc/` policy.
- **A `kill -9` of the leash client no longer strands its containers**
  (#222, #201). A detached watcher bound to the client by a lifeline pipe
  removes the run's target and sidecar containers (sidecar first, no stop
  timeout) and its temp work dir; containers carry owner labels so the next
  container run also reaps runs whose owner is provably gone (never runs from
  another machine or PID namespace, never kept runs).
- **Enforcer client race** (#221, #220): a result the daemon sends just
  before ending the session is no longer lost to a random `select`, so a
  failed attach reports the worker's reason and a successful `Detach` no
  longer returns an error.
- **SELinux build containers** (#233, #173): `make lsm-generate-docker` and
  `make docker-ui` run their throwaway build containers with
  `--security-opt label=disable` (`BUILD_CONTAINER_SECURITY_OPTS`), instead
  of failing on unlabelled bind mounts or relabelling the checkout.
- **eBPF objects are always built with clang 18** (#230, #227). Every
  generation path (`make lsm-generate`, `lsm-generate-docker`,
  `Dockerfile.leash`, `make docker-base`, release) checks the pinned major
  and refuses any other; clang 14 objects failed the 6.8 verifier in
  `lsm_rename_*`.
- Test-only: a data race in `TestPolicyReloadKeepsPreviousOnBadUpdate`
  (#229, #225) and a leaked test lock behind the 10-minute darwin CI hang
  (#235, #234).

### Added
- **`--selinux` / `LEASH_SELINUX` = `auto` | `relabel` | `disable`** (#236,
  fixes #175, #208, #209) for the agent's project and config mounts on
  SELinux-enforcing hosts. `auto` (default) changes nothing unless SELinux is
  enforcing and the engine labels containers; then a project or config mount
  that is not a container type refuses the run before any container starts,
  naming each path and the choices. `relabel` adds `:z` (shared
  `container_file_t`; never `:Z`; refuses `/`, top-level system directories
  and home directories). `disable` runs only the target container with
  `label=disable`; leash's LSM and proxy are unaffected. Explicit `-v`
  volumes keep their own flags. Verified on Fedora 44 with rootful and
  rootless podman and rootful Docker.
- **docs/SELINUX.md**: the label decision for every mount, the verified
  matrix, and the enforcer-daemon and build-container notes. ROOTLESS.md
  drops its "not verified on SELinux" caveat.

### Changed
- **Capability drop in the native runtime** (#223, #203). `--harden-exec
  --user <name>` now empties the bounding set and clears the ambient set
  while still root, then drops to the user itself (setgroups / setresgid /
  setresuid, with `runuser -u`'s `HOME`/`SHELL`/`USER`/`LOGNAME`), clears the
  inheritable/permitted/effective sets, sets `no_new_privs` and the seccomp
  filter, verifies, and refuses to run the workload if any capability is
  left. Inside the box `CapBnd`, `CapAmb`, `CapInh`, `CapPrm`, `CapEff` are
  all `0` and `NoNewPrivs` is `1`; setuid binaries gain nothing and
  file-capability binaries (iputils `ping`) cannot be executed. It stays
  PID 1 of the box (reaps orphans, forwards TERM/HUP/USR1/USR2).
- **`runuser` (and its PAM session) is no longer used to launch the native
  workload** (#223). `--allow-namespaces` keeps the previous `runuser` launch
  so nested rootless containers can still use `newuidmap`, and the
  `--inject-service` plugin launch still uses `runuser`. Container mode is
  unchanged (docs/design/SECURITY-MODEL.md § Workload capabilities).
- **Unix-socket binds, `mknod` and `mkfifo` are policy-checked creates**
  (#224): a policy without write authority over the directory now refuses
  them, as it already did `mkdir` and `O_CREAT` opens.
- On an SELinux-enforcing host, `--selinux auto` refuses a container run
  whose project or config mount is not labelled for containers, where it
  previously started and failed inside the container (#236).

## [native-v0.4.0] — 2026-10-18

Everything merged since `native-v0.3.15` (PRs #129–#216). The headline: one
Cedar engine decides every request and the kernel enforces tables compiled
from the same policy, strict Cedar is the default dialect, and enforcement
fails closed everywhere. Upgrade notes are under **Breaking**.

### Breaking
- **Strict Cedar is the default policy dialect** (#216). An unmarked policy
  file is plain Cedar: forbid overrides permit, default deny (MCP included),
  `File::"/p"` is exactly one path, `action == Action::"FileOpen"` is
  rejected. Convert a legacy policy with `leash policy migrate <file> --write`
  or keep its old meaning with `@leash_semantics("legacy")`; `leash policy
  lint` flags unmarked files that look written for the legacy dialect.
  `contractVersion` 3, capability `cedar-strict-default`.
- **Fail closed, always** (#137, #214). A run is refused when the eBPF LSM
  cannot attach (or `bpf` is not an active LSM, or the workload has no
  scopable cgroup); `--allow-proxy-only` / `LEASH_ALLOW_PROXY_ONLY` are gone
  and `--require-lsm` is a no-op. `contractVersion` 2.
- **Default deny in every kernel category** (#129, #140). The connect,
  file-open and exec LSMs are always attached; a policy with no rules for a
  category denies it (egress, opens and execs need explicit permits).
- **A policy that does not load stops the run** (#163), and a bad reload
  keeps the previous policy; policy changes apply transactionally across the
  kernel, the enforcer daemon and the proxy and fail closed (deny-all, stop
  the workload) if a rollback fails (#197).
- **Permits Leash cannot enforce as written are rejected** (#164, #183): a
  principal constraint or a condition on a file, exec or connect permit fails
  the load instead of being enforced unconditionally.
- **The workload is killed when leashd or the leash sidecar exits** mid-run
  (#200).
- **macOS refuses to start without its ES and NE extensions** (#211).

### Security
- **TCP and connected-UDP connects were not enforced by the kernel**: the
  connect hook read the sockaddr as user memory (#145, #147); the connect map
  and event ABI are now pinned field by field (#78, #192).
- **IPv6 and IPv4-mapped egress** is enforced by the connect LSM (#182,
  #185).
- **Packet, raw IP and SCTP sockets** are refused at creation unless the
  policy restricts no destination (#188, #202; capability `raw-socket-gate`).
- **Writes through the container overlay rootfs** bypassed the file policy
  (#186, #205); the hard-link guard's path reconstruction bounds were lifted
  (#206).
- **Policy load failures failed open** (the workload ran with the previous or
  no policy) (#162, #163).
- **Credential leak through Host/SNI mismatch**: request decisions (and
  header rewrites) are bound to the connection's verified host (#149, #153);
  the proxy dials only a destination the TLS connect policy permitted (#154,
  #168); wildcard hosts need a label boundary (`*.example.com` no longer
  matches `evilexample.com`) and names compare case-insensitively (#159).
- **HTTP/2 clients bypassed header rewrite and MCP enforcement** (#57, #146,
  #148).
- **macOS**: the ES and NE extensions enforce exactly the Linux kernel tables
  (open mode, nested permits, ports, connect default; #215); the daemon's
  control plane is closed to other clients and the LAN (#212); the policy
  file is kept out of `/tmp` and unsafe paths are refused (#12, #213).

### Added
- **Cedar decision engine** (#142: #150, #151, #152). Every userspace check
  (proxy connect, MCP tools/call, plugin questions) is `cedar.Authorize` over
  one strict policy set; the eBPF and macOS tables are compiled from the same
  set by a compiler that accepts only constructs it can enforce exactly, and
  parity tests prove the two agree. Deterministic rule precedence (#138).
- **Plugin authorization socket**: `--inject-service ... authz=<Ns>` gives an
  injected plugin a private Cedar authorization socket (protocol v1,
  `pkg/authz`; capability `authz-socket`).
- **Rootless podman with kernel enforcement** through the leash enforcer
  daemon (`leash daemon install|status|uninstall`; #189, #190; capability
  `rootless-daemon`).
- **Full HTTP/2 MITM** for inspected hosts (#57, #148).
- **Container resource limits**: `--cpus`, `--memory`, `--pids-limit`
  (#116, #167; capability `container-resource-limits`).
- **macOS parity** with the Linux kernel tables (#215), and the darwin
  hardening above.
- `leash policy migrate` and `leash policy lint` (#216).
- **`leash manager inspect --json`** reports the manager image a container
  run would use (same `--leash-image` / `LEASH_IMAGE` / embedded-default
  precedence), read from the local engine: ref, digest, version, revision,
  manager-contract range, the image leash's `contractVersion` range and
  capabilities, and whether this CLI would accept it (capability
  `manager-inspect`). The manager image gains the OCI labels
  `io.leash.manager.cli.contract.version`,
  `io.leash.manager.cli.contract.min-compatible`,
  `io.leash.manager.capabilities` and `io.leash.manager.policy-limits`
  (reported as `policyLimits`); the `final` build stage now also sets the
  manager-contract labels, which were empty in images built from it.

### Fixed
- Rootless podman with `userns = "keep-id"` (#121, #184); Dir rules cover the
  directory itself end to end (#119, #130); trailing-slash line-format rules
  (#126, #166); cgroup v2 paths for control-plane rules (#123, #131);
  `--inject-service` helpers reaped on every teardown (#128, #132); container
  commands run in a non-login shell, preserving the image `PATH` (#120,
  #134); target bootstrap failures surfaced before the sidecar netns error
  (#81, #136); native leashd and boxes reaped on every teardown, including
  boxes left by dead runs (#143, #156, #158, #198); the CA certificate and
  key share one lifetime so `LEASH_SHARE_DIR` can be reused (#165, #199);
  the CA is installed without `cp` and its trust verified before bootstrap
  (#169, #181); local images are not pre-pulled and real pull failures are
  reported (#170, #179).
- CI on GitHub Actions: lint, Linux and darwin tests, kernel verifier load,
  mac-leash build (#195); root and race fixes in tests (#144, #157, #180,
  #194, #210).

### Detailed notes
The entries below accumulated on the development branch since
`native-v0.1.0` (the `native-v0.2.x`/`native-v0.3.x` tags were not itemized
in this file); the summary above is what is new since `native-v0.3.15`.

#### Breaking — unmarked policy files are strict Cedar
- A policy file without a `@leash_semantics` marker is now read as **strict
  Cedar**: any matching `forbid` denies (a longer `permit` no longer beats a
  shorter `forbid`), otherwise a matching `permit` allows, otherwise deny —
  MCP calls included (they were allowed unless forbidden). `File::"/p"` is
  exactly the path `/p` (it was a byte prefix; the prefix is
  `FilePrefix::"/p"`), `action == Action::"FileOpen"` is rejected (write
  `action in Action::"FileOpen"`), and `unless` is an exception (legacy read
  it as `when`). Before, an unmarked file was read in the legacy dialect and
  only `@leash_semantics("cedar")` made it strict.
- **Migrate** a legacy policy with `leash policy migrate <file> --write`
  (same decisions, plain strict Cedar, no marker needed), or keep its old
  meaning by marking it `@leash_semantics("legacy")`. `@leash_semantics("cedar")`
  stays accepted as an explicit strict marker.
- New `leash policy lint [--json] <file>`: reports what would fail the load
  and warns (`legacy_semantics_suspected`, also in the Control UI's
  validation) when an unmarked file decides differently than its legacy
  reading, naming an example request. A load error on an unmarked file
  carries the migrate / mark-legacy hint.
- Every built-in policy was migrated with `leash policy migrate` and is
  checked to decide like its legacy original: the bootstrap policy (now with
  an explicit MCP permit), the release-gate Walk policy
  (`e2e/testdata/walk33-combined.cedar`) and the CEDAR.md examples. The
  policy API and Control UI generate statements that read the same in both
  dialects; `log2cedar` and the policy suggestions emit strict Cedar.
- `contractVersion` is now `3` (contract 3 = strict Cedar by default),
  `minCompatibleContract` stays `0` (nothing was removed: the legacy dialect
  is one marker away), and `capabilities` gains `cedar-strict-default`.
  Provisioners that generate unmarked legacy-style policies (Walk) must emit
  strict Cedar or mark their output `@leash_semantics("legacy")` against a
  leash that advertises it.

#### Security — macOS enforces the Linux kernel tables
- The macOS extensions now enforce exactly the tables the eBPF LSM enforces,
  compiled from the Cedar policy by the same code (`lsm.MacTablesFor`) and
  sent as `mac.policy.tables`; the Swift matcher implements the kernel's
  lookups. Before, the translation lost the open mode (a read-only permit
  allowed writes, a write forbid blocked reads), ordered file rules before
  directory rules (a permit nested under a forbid was ignored), dropped
  connect ports (`Host::"10.0.0.2:443"` allowed every port), never passed the
  connect default (the content filter allowed everything unmatched) and
  matched any IP to the first domain rule it saw.
- Parity is tested: random strict policies decided by a Go model of the Swift
  matcher equal `cedar.Authorize` (2500 sets, ~800,000 decisions); the same
  vectors are replayed against the Swift code (`swift test --package-path
  mac-leash`, in CI).
- LeashES also decides file creation (`AUTH_CREATE`, `AUTH_TRUNCATE`,
  `AUTH_CLONE`, `AUTH_COPYFILE`, `AUTH_EXCHANGEDATA`) and the directory
  mutations (`AUTH_UNLINK`, `AUTH_RENAME`, `AUTH_LINK`, mkdir): new files used
  to be created anywhere.
- No policy, a refused policy, or a daemon gone for more than 30 s is a deny
  for leashed operations (ES and NE). `leash --darwin exec` runs a command
  only once ES, NE and the transparent proxy are connected, ES and NE applied
  the daemon's current tables and ES tracks leashcli (it no longer needs a
  terminal to be tracked, and leashcli no longer sleeps and hopes).
- Forked children are tracked (`NOTIFY_FORK`); processes left running after
  leashcli exits stay tracked; a restarted LeashES re-tracks running ones.
- Leash's own state (state directory, CA key, policy file) is denied to the
  workload whatever the policy says, and the daemon's listeners refuse
  connections from leashed processes (the content filter never sees
  loopback). Only the ES extension may report tracked PIDs.
- A policy that names a path macOS only reaches as `/private/...` fails to
  load on macOS instead of silently never matching.
- leashcli reports a command killed by a signal (an exec ES denied) as
  128 + signal instead of exit 0.

#### Changed — native macOS refuses to start without its extensions
- `leash --darwin exec` and the darwin daemon now **refuse to start** unless
  both the Endpoint Security and the Network Filter system extensions are
  activated. The previous default warned and ran the workload unenforced;
  `LEASH_REQUIRE_ENFORCEMENT` is removed because refusing is now the only
  behaviour. The check runs in the terminal first, so the refusal and the
  activation steps are printed instead of a daemon readiness timeout, and it
  runs before the daemon touches any directory, key or log.
- `systemextensionsctl list` rows are matched on the bundle-id column exactly
  (leash doctor included), so a sibling extension whose id starts with leash's
  cannot make leash look enforced.
- `--inject-service` (and its `authz=` socket) is refused in native macOS mode
  with an explanation: darwind serves no plugin authorization socket.
#### Security — macOS policy file out of /tmp (#12)
- The darwin daemon's default policy moves from `/tmp/tmp.leash.policy` (which
  any local user could create, or symlink, before leash first ran) to
  `policy.cedar` in the per-user state directory (mode `0700`, repaired if
  looser, refused if not owned by you). A missing file is created `0600` with
  `O_EXCL|O_NOFOLLOW`.
- Every policy path is checked before it is created or read and on each
  reload: regular file, no symlink, owned by you or root, not group/other
  writable, and no directory above it writable by others unless sticky. An
  unsafe path stops the daemon; an unsafe reload is refused and the previous
  policy stays active.
- `LEASH_POLICY` given to `leash --darwin exec` is now passed to the daemon it
  starts instead of being overridden.

#### Added — build & compatibility document
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

#### Added — doctor probes BPF-LSM attachability instead of guessing
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

#### Added — node readiness self-check
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

#### Changed — permits with conditions Leash cannot enforce no longer load (#164)
- **Behavior change for legacy policy files.** Legacy semantics ignored
  principal constraints and every condition other than a whole
  `resource in [...]` or `context.hostname ==`/`like` clause, and read
  `unless` as `when`. A permit carrying such a constraint was enforced
  without it, so it allowed more than written (for example
  `permit (...) when { context.tty == true }` granted unconditionally, and
  `permit (... resource in Dir::"/a/") unless { resource in Dir::"/a/secret/" }`
  granted `/a/secret/`). The load (leashd, the policy API, the runner's
  preflight, reloads) now fails instead, naming the policy, its line and the
  construct (`CEDAR_UNENFORCEABLE_CONDITION`); a reload leaves the previous
  policy active. A permit that grants no file, exec or connect rule (MCP
  permits, which were no-ops) is unaffected.
- **Forbids** without their unenforceable constraint are enforced more
  broadly, as before (stricter); the rewrite report now says so. A forbid
  that legacy semantics would have enforced on *fewer* requests than written
  is rejected too: one whose resources appear only in the ignored condition
  or in an `unless` (`forbid (principal, action, resource) unless { resource
  in [File::"/bin/rm"] }` forbade only `/bin/rm`), or an MCP forbid naming
  servers or tools inside such a condition.
- **Strict files:** an `McpCall` policy (userspace only) may test only
  `context.server`, the only context the MCP adapters supply; one reading
  other context keys, the principal, or entity attributes or tags could never
  apply as written and is rejected. Kernel-enforced actions already had to
  stay in the kernel subset. Plugin-action policies keep every condition:
  the authz socket evaluates them with the context the plugin sends.
- `leash policy migrate` refuses such a file with the same error, and
  `LintFromString` (policy API, Control UI) reports each one as
  `unenforceable_condition`. Fix: drop the constraint to grant
  unconditionally, narrow the resources, express an exception as a forbid,
  or mark the file strict (`@leash_semantics("cedar")`), where `unless {
  resource in [...] }` is enforced as written. Design:
  [`docs/design/AUTHZ-SERVICE.md`](docs/design/AUTHZ-SERVICE.md) §4.3.

#### Changed — fail closed when the eBPF LSM can't attach (#117)
- **Behavior change.** When the eBPF LSM (Layer 1) cannot attach — kernel
  without an active `bpf` LSM, rootless podman without the enforcer daemon,
  rootless Docker, or no scopable cgroup — leash now **refuses to run the
  workload** instead of warning and continuing with only the L7 proxy. There
  is no opt-out: leash never runs a workload with only the proxy enforcing.
  This applies to the client preflight, native readiness, and leashd
  (container and host mode, including the former no-cgroup degraded mode of
  #67).
- **`--require-lsm` / `LEASH_REQUIRE_LSM` stay accepted** (and the
  `require-lsm` capability stays advertised) as no-ops. A falsy
  `LEASH_REQUIRE_LSM` does not opt out.
- **`contractVersion` is now `2`** (contract 2 = the fail-closed posture).
  `minCompatibleContract` stays `0`: nothing was removed, so callers written
  against contract 0 or 1 (e.g. Walk's `walkLeashContract=1`) remain
  compatible.
- **Effective enforcement level is machine-readable.** The enforcement-ready
  marker (still gated on by existence) is now a JSON document
  `{"enforcement":"lsm"|"none","layer1":…,"layer2":…,"requireLSM":true}`,
  leashd logs an `enforcement.level` event, and the client prints
  `leash: enforcement=<level> layer1=<state> layer2=<state>` on the diagnostic
  stream (always under `--machine-output`, always when not `lsm`). A workload
  is only ever released at `lsm`; `none` appears only on the skip-enforcement
  path.
- The client always sets `LEASH_REQUIRE_LSM=1` in the leash container, so an
  older leashd image (which continued with only the proxy by default) stays
  fail-closed, and rejects a user `-e LEASH_REQUIRE_LSM` that could undo it.
- leashd refuses to publish the ready marker for anything but `lsm`,
  including when no LSM program attached at all.
- **The client cross-checks leashd's reported level** and refuses to release
  the workload at any level other than `lsm`.
- The enforcement-ready marker is written atomically (temp file + rename).
- **Layer 1 is reported active only when the kernel confirms it.** On a kernel
  with `CONFIG_BPF_LSM=y` but `bpf` not in `/sys/kernel/security/lsm` (Ubuntu
  24.04's default) the LSM programs attach and are never invoked; leashd now
  also requires `bpf` in the active list (an unreadable list counts as not
  active), so that case is refused with a `reason`. The client's own preflight
  can only narrow the reported level, and a native refusal now echoes leashd's
  FATAL reason instead of only pointing at the log.

#### Added — kernel enforcement for rootless podman: the leash enforcer daemon
- Rootless podman cannot load the eBPF LSM, so a rootless run used to fail
  closed. `sudo leash daemon
  install` now installs the **leash enforcer daemon**: a socket-activated
  systemd service, running as a dedicated user with only `CAP_BPF` and
  `CAP_PERFMON`, no network and a narrow syscall filter. Members of the new
  `leash` group can ask it, over `/run/leash/enforcerd.sock` (`root:leash`
  `0660`), to attach leash's eBPF LSM programs to their own containers'
  cgroups. It compiles the session's policy with the same pipeline as leashd
  (`cedar.CompileLayers` → `transpiler.CompileKernel`) and loads it with the
  same `lsm.LSMManager`, one worker process per session. A rootless podman
  run then reports `enforcement=lsm` (`layer1Via: "enforcer-daemon"`), and
  file, exec, mutation and connect denials are identical to a rootful run.
- Callers are authenticated by `SO_PEERCRED`: group membership, subordinate
  uids attributed to their owner, and no connection or request from inside a
  governed cgroup. Targets must be inside the caller's delegated
  `user@<uid>.service` subtree, owned by the caller and populated; overlaps
  are refused. Every request is audited to
  `/var/log/leash-enforcerd/audit.log`. Sessions detach when the client
  detaches, the cgroup empties or disappears (including after a leash crash),
  or the daemon stops. A client disconnect alone keeps enforcement attached.
- A rootless podman run without a usable daemon is refused before anything
  starts, with `sudo leash daemon install` / `leash daemon status` in the
  error. Rootless Docker is refused (not supported yet, #207).
- If the daemon session is lost mid-run, leashd exits (`kernel enforcement
  lost`) and the runner kills the workload container.
- `leash daemon install|uninstall|status [--json]`; new capability
  `rootless-daemon`. See [`docs/ROOTLESS.md`](docs/ROOTLESS.md) for the
  security model. **Walk follow-up:** `enforcement` is still `lsm`, so Walk
  needs no change to accept these runs; it may want to surface `layer1Via`
  and drop its `userns=host` override (#121).

#### Fixed — rootless podman with `userns = "keep-id"` (#121)
- With `userns = "keep-id"` in `containers.conf` (a common rootless podman
  setting) the target container gets its own user namespace. The leash
  container stayed in podman's default one, so it had no `CAP_NET_ADMIN` over
  the target's network namespace and crun refused to start it (`mount sysfs to
  sys: Operation not permitted`); the run failed before bootstrap. The podman
  leash container now joins the target's user namespace whenever the target has
  one of its own (`HostConfig.UsernsMode` other than empty/`host`), so keep-id,
  `auto` and explicit mappings work and stay the user's choice. Rootful podman,
  rootless podman's default namespace and Docker are unchanged.
- leash-entry, when it is not container root and has no sudo, now says which
  uid it runs as and what overrode leash's `--user 0`, instead of "must run as
  root or have sudo available".

#### Fixed — HTTP/2 clients bypassed header rewrite and MCP enforcement (#57)
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

#### Fixed — remedy text that could break the host
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

#### Changed
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
  with or without connect rules. (Since lifted: IPv6 and IPv4-mapped egress are
  enforced, #185.)
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
