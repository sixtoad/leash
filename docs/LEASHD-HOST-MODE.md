# leashd host mode — spec

**Status: spec, held. No code.** The new leashd capability that
[`LAUNCHER-ABSTRACTION.md`](LAUNCHER-ABSTRACTION.md) named as the real blocker
for a native (container-free) backend. Companion to
[`RUNTIME-NATIVE-POC.md`](RUNTIME-NATIVE-POC.md).

## Goal

Run leashd as a **privileged host process** that enforces on a workload living
in a systemd scope + network namespace — instead of as a sibling privileged
**container** sharing the target container's namespaces. Same two layers, same
policy, no Docker.

## What leashd assumes today (the container contract)

leashd is `leash --daemon` (`Dockerfile.leash` ENTRYPOINT
`tini -- /usr/local/bin/leash --daemon`). Grounded in `internal/leashd/runtime.go`:

| Concern | Today | Source |
|---|---|---|
| **Cgroup to enforce on** | `--cgroup` / `LEASH_CGROUP_PATH`, required, validated as a cgroup-v2 dir (`cgroup.controllers` present); **discovered from a hint file** the target's leash-entry writes to the shared volume | `runtime.go:173`, `:259-270` |
| **eBPF LSM attach** | `lsm.NewLSMManager(cfg.CgroupPath, …)` → `LoadAndStart()` — **attaches scoped to that cgroup path** | `runtime.go:351`, `:459` |
| **Shared dir** (`LEASH_DIR`) | bootstrap marker + CA cert live here; a **bind-mounted volume** shared with the target container | `runtime.go:96`, `:396`, `:471` |
| **Private dir** (`LEASH_PRIVATE_DIR`) | required, `0700`, holds `ca-key.pem` | `runtime.go` preFlight |
| **Policy / log** | `LEASH_POLICY=/cfg/leash.cedar`, `LEASH_LOG=/log/events.log` (container paths) | `runtime.go:157-161` + Dockerfile env |
| **Bootstrap handshake** | `waitForBootstrap()` blocks until the **target's leash-entry** writes a marker, *then* activates the LSM | `runtime.go:430`, `:468` |
| **Network** | `applyNetworkRules(proxyPort, leashPort, cgroupPath)` — nftables/iptables REDIRECT to the proxy + control-plane isolation, **cgroup-matched, applied in the target's netns** (leashd runs with `--network container:<target>` + `NET_ADMIN`) | `runtime.go:647`, `:726` |

The container wiring that provides all this:
`--privileged --cap-add NET_ADMIN --cgroupns=host --network container:<target> -v /sys/fs/cgroup:ro`
(`launchLeashContainer` in `internal/runner/runner.go`).

## The one thing that does NOT change

**The eBPF LSM attach is already cgroup-path-based and backend-agnostic.** Give
leashd a valid cgroup-v2 path and it attaches `file_open`/`exec`/`connect`
scoped to it — it does not care whether that cgroup came from `docker run` or
`systemd-run --scope`. The proxy, policy engine, Cedar evaluation, Control UI,
and event log are likewise unchanged. **Host mode is not a rewrite of
enforcement — it's a rewrite of the *plumbing around* it.**

## What host mode changes (four things, in effort order)

### 1. Invocation & privilege (small)
Add a `--host` flag (or `LEASH_MODE=host`). Under it leashd:
- does **not** assume container paths/mounts;
- expects to run with `CAP_BPF`+`CAP_SYS_ADMIN` (LSM attach) and `CAP_NET_ADMIN`
  (netfilter) as a host process — via root, `setcap`, or a systemd unit. The
  **workload stays unprivileged** in the scope; privilege moves to leashd, not
  the agent.

### 2. Paths (trivial — already env/flag-driven)
`--cgroup`, `--policy`, `--log`, `LEASH_DIR`, `LEASH_PRIVATE_DIR` already come
from flags/env. Host mode just points them at **host** paths (e.g. a per-session
`/run/leash/<id>/` with `public/` + `private/` 0700). No code change beyond not
hard-defaulting to `/cfg`÷`/log`÷`/leash` when `--host` is set. The cgroup path
is the **scope's** cgroup — and in host mode it is **known at creation, so the
hint-file discovery is skipped entirely** (`resolveCgroupPath`'s reason to exist
goes away on this path).

### 3. Network namespace + netfilter (real work)
Today leashd shares the target's netns. In host mode the workload has its **own
named netns** (created by the launcher, see division of labor). leashd must:
- **operate in that netns** when it applies `applyNetworkRules` and binds the
  proxy — i.e. `setns` into the workload's net namespace (or run that stage via
  `nsenter --net=<ns>`), so the REDIRECT + control-plane-isolation rules land in
  the namespace the workload actually uses;
- keep the **cgroup match** coherent with that netns (the rules match the
  workload's cgroup for egress steering).
The rule *scripts* are unchanged; what changes is the **namespace they execute
in**. This is the bulk of host-mode work.

### 4. Bootstrap / readiness handshake (real work — a decision)
Today `waitForBootstrap()` waits for the **target container's leash-entry** to
write a marker, then activates the LSM (fail-closed: the workload is held until
enforcement is live). In native mode **there is no leash-entry in a container** —
the workload is a plain process in a scope. Two options:

- **A. Launcher writes the marker.** `nativeLauncher` creates the scope *paused*
  (or holds the workload on a gate), writes the bootstrap marker to `LEASH_DIR`,
  and leashd's existing `waitForBootstrap()` works unchanged. Smallest leashd
  change; keeps the exact fail-closed ordering.
- **B. Readiness fd.** Replace the marker with leashd signaling readiness on an
  fd/unix socket the launcher waits on before unpausing the workload. Cleaner,
  but changes the handshake contract.

**Recommendation: A first** (reuses the marker machinery and the proven ordering;
the launcher just plays the role leash-entry played), B as a later cleanup.

## Proposed interface

```
leash --daemon --host \
  --cgroup    /sys/fs/cgroup/.../leash-<id>.scope \   # the systemd scope's cgroup
  --netns     /run/netns/leash-<id> \                 # workload's named netns (NEW flag)
  --policy    /run/leash/<id>/leash.cedar \
  --log       /run/leash/<id>/events.log \
  --proxy-port 18000 \
  --listen    127.0.0.1:18080
# env: LEASH_DIR=/run/leash/<id>/public  LEASH_PRIVATE_DIR=/run/leash/<id>/private (0700)
```

`--netns` is the one genuinely new flag. `--host` flips off container-path
defaults and the hint-file cgroup discovery. Everything else is existing
flags/env pointed at host paths.

## Division of labor: nativeLauncher ⇄ leashd host mode

| Step | nativeLauncher (client) | leashd `--host` |
|---|---|---|
| Box | `systemd-run --scope --property=Delegate=yes`; `ip netns add leash-<id>` | — |
| Cgroup | reads the scope's cgroup path, passes `--cgroup` | validates it (existing check) |
| Dirs | creates `/run/leash/<id>/{public,private}` | reads them (existing env) |
| Workload | starts it **gated** in scope+netns (paused until ready) | — |
| Enforce | spawns leashd `--host --netns …` | attaches eBPF LSM (**unchanged**), enters netns, applies netfilter, starts proxy |
| Readiness | (option A) writes bootstrap marker; waits for CA cert | `waitForBootstrap()` then `LoadAndStart()` (**unchanged**) |
| Go | un-gates the workload once leashd is live | — |
| Teardown | `systemctl stop <scope>`, kill leashd, `ip netns del` | clean LSM/proxy on signal |

## Reuse map

- **Unchanged:** `lsm.*` (attach is cgroup-path-based), the MITM proxy, the Cedar
  policy engine, the Control UI/API, the event log, the netfilter *scripts*, the
  `waitForBootstrap` marker machinery (option A).
- **New:** `--host` + `--netns` flags; a netns-entry step around the network
  stage; host-path defaults; the launcher playing the leash-entry role.
- **Composes with:** the eBPF-LSM degrade + `--require-lsm` work on
  `feat/enforcement-preflight` (host mode should honor the same fatal-vs-degrade
  rule — note that branch's `NewLSMManager(cgroup, logger, requireLSM)` signature
  vs this branch's 2-arg form; reconcile when both land).

## Open decisions

1. **Handshake A vs B** — recommend A (marker) first.
2. **netns entry mechanism** — leashd `setns` itself for the network stage, vs.
   the launcher running leashd already inside the netns (`nsenter`). `setns` for
   just the network stage keeps the LSM attach (which is netns-agnostic) in the
   host ns; simpler isolation reasoning. Decide during 2.2.
3. **System vs user scope** — system scope (root leashd, host-visible cgroup) is
   required for real enforcement; the PoC's `--user` scope was a no-root demo
   convenience only.
4. **Privilege delivery** — root vs `setcap` vs a systemd system service for
   leashd. The agent stays unprivileged regardless.

## Build & test

- leashd's eBPF objects need the toolchain (clang/llvm/libbpf). Build via the
  **dockerized codegen** already used for #67: `make lsm-generate-docker` +
  rootful `sudo podman` (the dev box has no host clang). The Go side compiles
  without it.
- **Enforcement** additionally needs `bpf` in the active LSM list
  (`lsm=…,bpf` boot param + reboot) — the universal gate detected by
  `feat/enforcement-preflight`. The non-enforcing box lifecycle (scope + netns +
  exec + teardown) is testable **without** the reboot.

## Non-goals (here)

Remote/cross-host native (needs file copy, separate effort), Windows native
(kernel driver — see briefing §10.2), and the macOS native worlds (ES/NE —
`feat/enforcement-preflight`). This spec is Linux host mode only.
