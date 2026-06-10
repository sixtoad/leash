# Leash on micro-VMs (Apple Vz / OrbStack / Docker Desktop)

> **Status:** spec. No code lands with this commit — this document is the contract we agree to before implementing.
>
> **Branch:** `feat/microvm-vz`, stacked on `feat/remote-container-runtimes`.
>
> **Scope:** macOS only. Linux hosts use the existing container path with kernel-level eBPF and need no changes from this work.
>
> **Phasing:** Phase 1 (graceful mode) is in scope for this branch's eventual implementation PRs. Phase 2 (in-guest leash via Vz) is documented here as a forward reference but is NOT implemented under this spec.

## 1. Background

### 1.1 Where eBPF lives, where micro-VMs put it

Leash's enforcement model layers two surfaces:

- **Kernel** — eBPF LSM hooks (`file_open`, `bprm_check_security`, `socket_connect`) and a ringbuffer event stream. Attached to a Linux kernel by the **leash manager container**, scoped to the target's cgroup via `bpf_get_current_cgroup_id`. See [`docs/design/ARCHITECTURE.md`](ARCHITECTURE.md) for the full rationale.
- **Userspace** — a transparent MITM HTTP/HTTPS proxy that intercepts L7 traffic redirected to it by host iptables, terminates TLS with a per-host generated cert from a CA the target trusts, and enforces hostname / header / MCP-tool policies in userspace.

The kernel layer is in-band with the agent process: every syscall the agent issues passes through the same kernel's LSM hooks. The userspace layer is in the same network namespace.

A **micro-VM runtime** breaks the kernel-layer assumption. The agent now runs against the *guest* kernel; the host kernel sees only the VMM process. There is no LSM hook on the host that can observe a guest-side `open(2)`. eBPF programs the host attaches do not enter the guest. This is the central trade-off the spec resolves.

### 1.2 macOS-specific landscape

On macOS, the agent's container runtime can be any of:

| Runtime | Backing | Kernel agent sees | Container scope |
|---|---|---|---|
| Linux Docker daemon (remote / VM) | Linux kernel | Linux | per-container |
| **OrbStack** | Apple Vz VM (one shared) | Linux (inside the shared VM) | per-container, but all containers in one VM |
| **Docker Desktop** (Apple Silicon ≥ v4.x) | Apple Vz VM (one shared) | Linux (inside the shared VM) | per-container, but all containers in one VM |
| **Podman Desktop** (Apple Silicon) | Apple Vz VM (one shared) | Linux (inside the shared VM) | per-container, but all containers in one VM |
| **Lima** / **Colima** | Apple Vz or QEMU VM | Linux (inside the shared VM) | per-container, but all in one VM |
| `leash --darwin` (native) | macOS host | macOS (no Linux at all) | per-process scoped via EndpointSecurity + NetworkExtension |

Three of the runtimes above (OrbStack, Docker Desktop, Podman Desktop) follow the same pattern: a single shared Linux VM hosts all containers. From leash's perspective, that VM *is* the kernel — and eBPF LSM works *inside it* the same way it works on a Linux bare-metal host. **The host kernel that eBPF would run against is the VM's, not macOS's.**

This is the key insight that drives Phase 1: on a Vz-backed container runtime, leash's existing Linux-container architecture **mostly works as-is**, because both the target container and the leash manager container live in the same VM and share the VM's Linux kernel. The cgroup-scoping property holds. The MITM proxy still works because iptables redirection happens inside the VM's network namespace.

What changes is operational:

- The agent's container is bind-mounted from a Mac filesystem *through* the VM (typically virtio-fs or similar). File paths may need normalization.
- Image arch must match VM arch (`linux/arm64` on Apple Silicon).
- DNS, network policy, and resource limits are configured per-VM (one shared layer for all containers).
- Performance characteristics differ from native Linux (cold-boot, syscall overhead, virtio I/O).
- Some leash assumptions about cgroup paths, `--cgroupns=host`, or privileged operations may surface latent bugs that don't trigger on bare Linux.

A critical assumption holds throughout the above: the four Vz-backed runtimes follow a **shared-VM** model — one Linux VM, many containers (target + leash manager + anything else the operator has running) inside it. A distinctly different micro-VM model exists in the wider ecosystem: **per-container-per-VM**, exemplified by Kata Containers and Firecracker direct. That model has fundamentally different consequences for leash's enforcement architecture and is deliberately out of scope for this spec; see [§3.1](#31-kata-style-per-container-per-vm-micro-vms).

### 1.3 Why this work is worth doing

Today, the README endorses OrbStack as a supported runtime. In practice, no code in the runner explicitly probes for Vz-backed runtimes, no test covers OrbStack, and there are no documented runbooks for "what to expect when leash runs on Apple Silicon with Docker Desktop/OrbStack." We're operating on the assumption that everything just works. Phase 1 of this work makes that assumption explicit, instrumented, and supported.

## 2. Goals

### 2.1 Phase 1 — Graceful mode (in scope)

1. **Detect** when the target container runtime is a Vz-backed micro-VM (OrbStack, Docker Desktop, Podman, Lima/Colima) at runner startup.
2. **Document** which existing leash features remain enforceable (kernel + MITM still work *inside* the VM) and which features are operationally different (file mount path translation, image arch, DNS, resource limits).
3. **Surface clear messaging** at start of run: which runtime detected, which mode, which features are limited or differ from bare-Linux defaults.
4. **Add a CLI flag and env var** for explicit user override (`--microvm-target` / `LEASH_MICROVM_TARGET=<auto|vz|none>`).
5. **Test against OrbStack and Docker Desktop on Apple Silicon** as a CI matrix entry or a manual-run smoke test in `e2e/`.
6. **Document the architecture** in this file and via cross-references from `docs/MACOS.md` and `docs/design/ARCHITECTURE.md`.

### 2.2 Phase 2 — In-guest leash via Apple Vz (out of scope for this spec)

A future mode where leash spawns its own Linux VM via Apple Virtualization framework and runs the leash manager + target containers *entirely inside it* — bypassing the operator's installation of OrbStack or Docker Desktop. This delivers:

- Identical Cedar enforcement to bare-Linux on any Mac with Vz support.
- No dependency on third-party container runtimes.
- Per-session VM lifecycle (start when `leash` is invoked, tear down on exit).
- A third macOS mode alongside containerized (today) and `--darwin` native (today).

Phase 2 is sketched in [§7](#7-phase-2-preview--in-guest-leash-on-apple-vz) below. Implementation is **explicitly not part of this branch**.

## 3. Non-goals

### 3.1 Kata-style per-container-per-VM micro-VMs

**What "Kata-style" means.** The term loosely covers any model where every container gets its own dedicated micro-VM, sharing nothing with siblings or the host runtime. Two concrete representatives in the ecosystem today:

- [**Kata Containers**](https://katacontainers.io/) — an OCI runtime that drops in for `runc`. You enable it via `docker run --runtime=kata-runtime ...` or as the default in containerd / CRI-O. From the orchestrator's perspective it looks like a container; underneath, each container is a tiny VM with its own kernel (typically a stripped Clear Linux derivative), an in-guest agent (`kata-agent`), and your container's rootfs. The hypervisor underneath is pluggable: QEMU, Cloud Hypervisor, or Firecracker.
- [**Firecracker direct**](https://github.com/firecracker-microvm/firecracker) — AWS Lambda's underlying tech, invoked directly via its REST API rather than through Docker. Each function invocation gets a sub-second cold boot of a stripped-down Linux VM. Designed for extreme-scale hostile multi-tenancy.

**Why it's architecturally different from this spec's shared-VM model.** In OrbStack / Docker Desktop / Podman / Lima, *one* Linux VM hosts both the target container and the leash manager container; they share that VM's kernel. In Kata-style, target and manager would live in *separate* VMs with *separate* kernels — they cannot share anything except files explicitly bridged via virtio-fs or a host-mediated socket.

| Aspect | Shared-VM (this spec's target) | Kata-style (out of scope) |
|---|---|---|
| VMs in the path | 1 | N (one per container) |
| Target ↔ manager kernel | shared | separate |
| eBPF LSM cgroup scoping | meaningful (single kernel hierarchy) | meaningless (no shared cgroup hierarchy) |
| MITM via iptables REDIRECT | works (inside the VM's network namespace) | doesn't apply (target traffic is on a host-side tap device, not in a shared netns) |
| Bootstrap handshake (`/leash/bootstrap.ready`) | shared volume inside the VM | needs per-VM virtio-fs mount + synchronization |
| Cold-boot cost | amortized over VM lifetime | paid per container (~125 ms Firecracker, ~500 ms QEMU) |
| Target audience | developer desktop | hostile multi-tenant, serverless, secure CI |

**What concretely breaks if we naively layered leash on Kata today.** Four things, each non-trivial:

1. **eBPF LSM scoping is undefined.** Leash uses `bpf_get_current_cgroup_id` + an `allowed_cgroups` map to scope enforcement to a specific cgroup *in the kernel the BPF program is attached to*. In Kata, the manager's kernel doesn't have a cgroup that corresponds to the target's processes — they're in another kernel entirely. The map has nothing useful to put in it.
2. **MITM iptables REDIRECT doesn't apply.** Leash places an iptables REDIRECT in the shared network namespace of target + manager. In Kata, the target's network is a virtio-net device backed by a host-side tap; the host's iptables sees the tap, not the connections inside the guest, and the manager's iptables is in yet another netns.
3. **CA bootstrap requires per-VM choreography.** The current handshake — manager writes `/leash/ca-cert.pem`, target's `leash-entry` installs it — relies on a single shared filesystem. Kata's per-VM virtio-fs mount needs explicit pairing, and `leash-entry` needs to know which guest it's bootstrapping for.
4. **The control plane is now N+1 endpoints.** Today there is one HTTP/WS at `:18080`. With one VM per container, we would need either a fan-in aggregator on the host (probably a vsock multiplexer) or a registration protocol so the Control UI can locate each agent.

None of this is fundamentally unsolvable. It's a different architecture.

**Why this spec defers.** Three reasons, in order of weight:

1. **Audience mismatch.** Leash's stated user (per the README, the Mac setup guide, the Linux setup guide) is a developer running an AI agent on their own machine. Kata's design target is hostile multi-tenant — many users, none trusted by the operator. The capability gap (container vs. per-container VM) primarily matters when you don't trust your neighbors. Today's leash users *are* the neighbors.
2. **No expressed demand.** A survey of the strongdm/leash issue tracker, all 43 forks, the README'd-into projects (packnplay, safe-ai-factory), and the leash maintainer commits over the last six months turned up zero mentions of Kata, Firecracker direct, or per-container-per-VM in any issue, PR, design doc, or roadmap. Adding speculative architectural capacity has cost — code, tests, docs, maintenance surface — and that cost is real even for a use case nobody has asked for.
3. **Scope discipline.** Supporting per-container-per-VM means either moving enforcement *into* each guest (each VM boots with `leashd` inside it) or moving enforcement to a different layer entirely (host hypervisor introspection, syscall tracing, etc.). Either is a multi-month design effort. Bundling it into Phase 1 of a graceful-mode-on-Mac-Vz commit obscures both pieces of work and makes both harder to review.

**Forward path if we ever do support it.** A future spec would introduce a `BackendKataLike` runtime classifier covering any per-container-per-VM model (Kata, Firecracker direct, Cloud Hypervisor direct). The enforcement strategy would shift to **agent-in-guest**: each guest boots a slim image we ship containing `leashd`, and the host-side runner becomes pure orchestration (provision the VM image, mount source via virtio-fs, manage lifecycle, aggregate the control plane over vsock). MITM either moves into each guest (and the guest's egress is bridged through it) or moves to a host-side proxy reachable via `DOCKER_HOST`-style URL or vsock. Cedar continues to be the authoritative source; the transpiler outputs ship into each guest at boot. This is closer in spirit to how `leash --darwin` works today (per-process enforcement via a system extension) than to today's containerized model. It is not a small change.

### 3.2 Other non-goals

- **`--darwin` native mode is unchanged.** It already provides macOS-native enforcement via system extensions; this work does not replace or compete with it.
- **Linux hosts are not affected.** The graceful-mode detection is gated by `runtime.GOOS == "darwin"` and a non-empty Vz signature; on Linux it's a no-op.
- **We are not building a Docker / OrbStack / Podman client abstraction.** Leash continues to shell out to `docker` / `podman`. The detection layer is a thin probe of `docker info` (or `podman info`).
- **No image build changes.** We will document that the target image must be `linux/arm64`-compatible on Apple Silicon, but we do not change `Dockerfile.coder` or `Dockerfile.leash` in this work.

## 4. Detection contract (Phase 1)

### 4.1 What we probe

The runner queries `docker info --format '{{json .}}'` (or `podman info --format json` if the configured runtime is podman) once at startup. The probe runs **after** the operator's chosen runtime is selected by `DOCKER=podman` or default, and **before** any `docker run` is issued. The probe is cached for the run.

We extract:

| JSON field | Used for |
|---|---|
| `ServerVersion` / `Server.Name` | Identifying OrbStack vs Docker vs Podman |
| `OperatingSystem` | Detecting "OrbStack" / "Docker Desktop" suffixes |
| `KernelVersion` | Linux kernel version inside the VM (confirms Linux guest) |
| `Architecture` | `aarch64` / `x86_64` — informs image arch warnings |
| `OSType` | Should be `linux` for any Vz-backed runtime |
| `DefaultRuntime` | `runc` (typical) or alternative; informs Phase 2+ future Kata work |

### 4.2 Classification

`internal/runtime/microvm.go` defines:

```go
package runtime

type Backend int

const (
    BackendUnknown Backend = iota
    BackendLinuxNative              // Linux host, no VM in the path
    BackendDockerDesktopVz          // Docker Desktop on Apple Silicon (Vz-backed)
    BackendOrbstack                  // OrbStack (Vz-backed)
    BackendPodmanVz                  // Podman Desktop / podman machine on macOS (Vz-backed)
    BackendLimaColima                // Lima / Colima (Vz or QEMU)
    BackendRemoteLinux               // Remote Docker daemon over DOCKER_HOST (no Vz from our POV)
)

type Detection struct {
    Backend          Backend
    KernelVersion    string
    Architecture     string
    OSType           string
    ServerVersion    string
    OperatingSystem  string
    GuestIsLinux     bool   // true when the kernel reachable from leashd is Linux
    SharesGuestKernel bool  // true when target + manager share a single Linux kernel (the Vz VM's)
    Notes            []string
}

func Classify(info DockerInfo) Detection
```

### 4.3 Operator override

| Surface | Behaviour |
|---|---|
| `LEASH_MICROVM_TARGET=auto` (default) | Run the probe, use the result. |
| `LEASH_MICROVM_TARGET=vz` | Skip probe, force `BackendOrbstack` semantics. Useful for CI / determinism. |
| `LEASH_MICROVM_TARGET=none` | Skip probe, force `BackendLinuxNative` semantics. Useful for debugging. |
| `--microvm-target {auto,vz,none}` CLI flag | Same options, CLI form. |

The override is *advisory*: it bypasses the probe and forces a classification, but does not change any enforcement decision that depends on the actual runtime behaviour. If a user forces `vz` on a Linux host, the run will still attempt eBPF attach against the host kernel — the override only changes telemetry + messaging.

## 5. Enforcement-degradation matrix

This is the contract we surface to operators.

| Capability | Bare Linux | OrbStack / Docker-Desktop / Podman (Vz) | Notes |
|---|---|---|---|
| eBPF LSM `file_open` enforcement | ✅ | ✅ — attaches inside the VM | Both containers share the VM's Linux kernel. |
| eBPF LSM `bprm_check_security` | ✅ | ✅ | Same as above. |
| eBPF LSM `socket_connect` | ✅ | ✅ | Same as above. |
| MITM HTTP/HTTPS proxy | ✅ | ✅ — iptables redirect happens inside the VM's network namespace | Works unchanged. |
| MITM MCP observer (JSON-RPC, SSE) | ✅ | ✅ | Works unchanged. |
| HTTP/2 ALPN tunneling | ✅ | ✅ | Works unchanged (lands via `feat/remote-container-runtimes`'s sibling commit `164015b`). |
| Cgroup discovery (`/leash/cgroup-path`) | ✅ | ✅ if `--cgroupns=host` honored by the VM's docker (it is, on all three) | Validate in CI. |
| `--privileged` + `--cap-add NET_ADMIN` | ✅ | ✅ | Vz-backed runtimes pass through. |
| `LEASH_PRIVATE_DIR` mode 0700 enforced | ✅ | ✅ (path is inside the VM) | virtio-fs preserves modes. |
| Bind-mount of caller cwd | ✅ | ⚠ may differ | OrbStack: transparent. Docker Desktop: requires Settings → File Sharing entry. Podman: depends on machine config. |
| File path consistency host ↔ container | ✅ | ⚠ partial | On macOS, the host path is `/Volumes/...` or `/Users/...`. Inside the VM, it's the same path (re-projected by virtio-fs). Cedar policies that reference absolute paths must use the *guest-visible* path, not the macOS-visible one. |
| Image arch | n/a | ⚠ must be `linux/arm64` on Apple Silicon | Default `coder` image must be multi-arch (already is per `.goreleaser.yaml`); document. |
| Cold-boot latency | ms | seconds (first run after machine cold boot) | One-time cost. |
| Sustained syscall overhead | baseline | small overhead (Vz syscall path is fast on Apple Silicon) | Negligible for agent workloads. |

The four `⚠` rows are documentation + ergonomics work, not enforcement gaps.

## 6. Implementation plan (Phase 1)

This spec does not land code. The implementation plan is what the **next** commits on this branch will do.

### 6.1 Code changes (one commit per bullet, stacked further if needed)

1. **`internal/runtime/microvm.go`** — `Backend`, `Detection`, `Classify(DockerInfo) Detection` plus tests with fixture `docker info` outputs from OrbStack, Docker Desktop on Apple Silicon, Podman, and bare Linux. Pure function; no I/O.
2. **`internal/runtime/probe.go`** — `Probe(ctx, runtime string) (Detection, error)` shells out to `docker info --format '{{json .}}'` or `podman info --format json` and feeds `Classify`. Single-shot, cached per invocation.
3. **`internal/runner/runner.go`** — call `runtime.Probe` once during `Main`, store on `runner`. Emit a log line at info level: `runtime: backend=orbstack kernel=6.6.31-orbstack-..., arch=aarch64, shared_kernel=true`.
4. **`internal/runner/runner.go`** — wire `--microvm-target` flag + `LEASH_MICROVM_TARGET` env override.
5. **`internal/leashd/runtime.go`** — at activation time, log the detection result alongside other startup state for parity in logs / WebSocket events.
6. **`docs/MACOS.md`** — add a section linking to this design doc, summarizing "how to run leash on Mac via OrbStack / Docker Desktop / Podman / native" — the contents of [§5](#5-enforcement-degradation-matrix) condensed.
7. **`e2e/microvm_test.go`** — a test that skips unless `LEASH_MICROVM_TARGET=vz` (or runs on a host with OrbStack detected). When it runs, exercises the standard happy path (`leash --no-interactive -- echo ok`) and asserts the detection log line appears.

### 6.2 Commit shape

Each item above is a single commit on `feat/microvm-vz`. Order: 1 → 2 → 3 → 4 → 5 → 6 → 7. The branch ships as one logical change set when ready, against the eventual upstream RFC.

### 6.3 Test fixtures

Real `docker info` outputs collected before implementation begins, committed under `internal/runtime/testdata/`:

- `docker_info_orbstack.json`
- `docker_info_docker_desktop_apple_silicon.json`
- `docker_info_podman_macos.json`
- `docker_info_lima.json` (optional)
- `docker_info_linux_native.json`

These pin the classifier against drift in any single vendor's output format.

## 7. Phase 2 preview — In-guest leash on Apple Vz

This section exists for forward reference only. It is **not** scoped for the current branch and will be tracked under a future `feat/microvm-vz-inguest` branch (or similar).

### 7.1 The idea

`leash` on macOS gains a third mode (alongside containerized and `--darwin` native):

```
leash --microvm -- claude
```

Behaviour:

1. Lookup or spawn a per-session Linux VM via Apple's `Virtualization.framework` (likely orchestrated via a Swift helper in `mac-leash/` — we already ship one for `--darwin` mode).
2. Inside the VM, the existing leash stack runs unchanged: `leashd` + target container + eBPF LSM + MITM proxy.
3. The user's cwd is exposed inside the VM via virtio-fs (or its equivalent).
4. The Control UI is reverse-proxied from the VM to a host port.
5. On exit, the VM is suspended (warm start) or destroyed (cold start), per a config flag.

### 7.2 Why it matters

- No dependency on OrbStack / Docker Desktop / Podman being installed.
- Same Cedar enforcement as bare-Linux: kernel + MITM, all paths.
- Per-session VM = stronger isolation than a shared OrbStack VM.
- A natural home for Phase 1 of the `walk` wrapper's "persistent container" feature on Mac — each session's VM is the persistent unit.

### 7.3 What we'd need to design

- Swift helper to wrap Virtualization.framework (analogous to `LeashES` / `LeashNetworkFilter` in `mac-leash/`).
- VM image distribution (a slim guest Linux with leashd preinstalled).
- VM lifecycle (start, suspend, destroy) integrated into the runner.
- File path projection (Mac path ↔ guest path).
- Network model (NAT through host? bridge? socket forwarding?).
- Control UI reverse proxy.

Out of scope here. Will be its own spec.

## 8. Open questions

| # | Question | Default position |
|---|---|---|
| 1 | Should `Classify` fall back to "linux native" when Vz signals are absent on macOS, or should it error? | Fall back. Some users run native Linux Docker in a remote VM; the path should still work. |
| 2 | Do we need a separate "remote linux" classification for users running over `DOCKER_HOST=ssh://...`? | Yes — `BackendRemoteLinux` is in the enum. Behaviour identical to `BackendLinuxNative` for now; the distinction is for telemetry and future remote-runtime PRs (see `feat/remote-container-runtimes`). |
| 3 | Should the detection be re-probed on policy reload? | No. Runtime topology doesn't change mid-session. Single probe at startup is sufficient. |
| 4 | Where does the detection result get logged for operator visibility? | (a) stderr at info level once, (b) WebSocket `leash.runtime` event for the Control UI, (c) `state.toml`-like file in `LEASH_DIR` for diagnostics. Decision: (a) + (b) for Phase 1; (c) is a nice-to-have. |
| 5 | Should we add a `leash doctor` subcommand that prints the detection? | Out of scope for this branch — propose as a follow-on. Mirrors `walk doctor` in the wrapper. |
| 6 | What about Docker Desktop on **Intel Macs** (HyperKit, no Vz)? | Treat as `BackendDockerDesktopVz` for our purposes — same fundamentals (Linux VM, shared kernel), even though Vz isn't the underlying tech on Intel. Document. |
| 7 | Should `--cgroupns=host` failure on the VM be a hard error or a fallback? | Hard error today (leash already requires it). Phase 2 in-guest mode controls the kernel directly and can guarantee it. |
| 8 | Cedar policy authoring helper for "you're on Vz, here are the paths the guest sees"? | Possibly an `autocomplete` hint extension. Out of scope for this branch. |

## 9. Acceptance criteria (Phase 1)

The branch's implementation PR is mergeable when:

1. `Classify` correctly tags each of the four fixture `docker info` outputs.
2. The runner emits a `runtime:` log line on every invocation, naming the detected backend.
3. `LEASH_MICROVM_TARGET={auto,vz,none}` and `--microvm-target` override the probe.
4. `e2e/microvm_test.go` passes on a CI runner with OrbStack and on bare Linux (skips appropriately).
5. `docs/design/MICROVM.md` (this file) and `docs/MACOS.md` cross-link cleanly.
6. No behavior change on bare Linux relative to `main`.
7. No regression in the standard `leash --no-interactive -- echo ok` test path on Apple Silicon with OrbStack or Docker Desktop.

## 10. References

- [`docs/design/ARCHITECTURE.md`](ARCHITECTURE.md) — why eBPF LSM, why MITM, the two-layer enforcement model.
- [`docs/design/SECURITY-MODEL.md`](SECURITY-MODEL.md) — trust boundaries, CA public/private split.
- [`docs/MACOS.md`](../MACOS.md) — operator guide for `--darwin` native mode (to be cross-linked from this doc).
- [Apple Virtualization framework](https://developer.apple.com/documentation/virtualization) — Apple's Vz docs.
- [OrbStack documentation](https://docs.orbstack.dev/) — operator runbook for the most common Vz-backed runtime.
- [Docker Desktop Apple Silicon notes](https://docs.docker.com/desktop/install/mac-install/) — Docker's own Vz/VirtioFS migration story.
- [Linux kernel eBPF LSM](https://www.kernel.org/doc/html/latest/bpf/prog_lsm.html) — the LSM hook surface we're scoped to.
- [Lima](https://github.com/lima-vm/lima) / [Colima](https://github.com/abiosoft/colima) — alternate Vz-backed runtimes worth testing against if time permits.
