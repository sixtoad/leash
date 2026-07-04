# `--runtime native` — proof of concept

> **Status — 2026-07-04:** This is the design/PoC-era doc. The native runtime is
> implemented and released (`native-v0.1.0`). Shipped beyond this PoC: netns
> **egress** / Layer 2, the **LSM-only** fallback (`layer2Active`), the workload
> **running as the invoking user** (`runuser`, not root), **CA trust**
> (`NODE_EXTRA_CA_CERTS`), and the **leashd log-file** redirect. Current truth:
> [CHANGELOG.md](../CHANGELOG.md) (what shipped) and
> [CLAUDE-CODE-LEASHED.md](CLAUDE-CODE-LEASHED.md) (how to run it).

**Status: PoC, held. Proves the box; does not yet enforce.** Not advertised
alongside docker/podman.

## The question

Can leash enforce **without a container** on Linux — the way the macOS app runs
natively — so there's no Docker dependency and the agent touches the real
working tree directly?

## The answer

Yes for the **box**. leash's two layers each need one kernel primitive, and both
exist without any container runtime:

| Layer | Needs | Container-free source |
|---|---|---|
| 1 — eBPF LSM (cgroup-scoped) | a cgroup to attach to | `systemd-run --scope --property=Delegate=yes` → a delegated cgroup-v2 scope |
| 2 — MITM proxy (fail-closed L7) | a netns to intercept in | `unshare --net` → a fresh network namespace |

Two commands build the whole box on a stock Linux host — no image, no daemon, no
Docker:

```sh
# Layer-1 attach point: a delegated cgroup-v2 scope; print where the eBPF LSM would attach.
systemd-run --user --scope --quiet --property=Delegate=yes \
  -- bash -c 'sed "s#^0::#/sys/fs/cgroup#" /proc/self/cgroup'

# Layer-2 intercept point: an isolated network namespace for the proxy.
unshare --user --map-root-user --net bash -c 'readlink /proc/self/ns/net'
```

Verified on the dev box (the cgroup path is exactly what leashd hands to
`link.AttachLSM`):

```
Layer 1 (eBPF LSM)   -> attach to cgroup:  /sys/fs/cgroup/.../leash-native-poc-NNNN.scope
Layer 2 (MITM proxy) -> intercept in netns: net:[40265…]
Container runtime used: NONE  (systemd-run + unshare only)
```

A local helper, `scratch-native-poc/build-box.sh` (untracked, dev-only), wraps
these with checks and the layer mapping.

The same argv is exercised in code by `nativeRuntime` and asserted live by
`TestNativeScopeLandsInCgroup_Integration` (skips where there's no user systemd
manager).

## What this PoC wires

`internal/runner/runtime_native.go` — `nativeRuntime`, a `Runtime` backend
resolved by `newRuntime("native")` (i.e. `--runtime native` flows through the #4
seam). `Cmd()` wraps the workload in a delegated scope; `Name()` is `native`.

## The honest finding: where the `Runtime` seam leaks

The `Runtime` interface is **container-CLI-shaped** — `Run`/`Output` take verbs
(`run`, `pull`, `inspect`, `ps`), `ExecWithInput` addresses a *container*. Native
mode has no daemon to drive and no container to address, so those methods return
a clear `not wired` error **naming the verb**. Because the launch path
(`launchTargetContainer` does `docker run <image>`; `launchLeashContainer` uses
`--privileged --network container:<target>`) calls them, `--runtime native`
fails *precisely at the call sites that assume a container* — which is the point:
it maps the work.

**Conclusion:** the seam cleanly accepts a non-`cliRuntime` backend (this type is
the proof), but a *production* native backend is not a CLI swap. It needs a
launcher abstraction wider than `Runtime`, because two things change above the
interface:

1. **leashd stops being a sibling container.** Today it's a second privileged
   container sharing the target's netns and mounting `/sys/fs/cgroup`. Native:
   leashd runs as a **privileged host process** (holding `CAP_BPF`/
   `CAP_SYS_ADMIN`) that attaches the eBPF LSM to the scope's cgroup and runs the
   proxy in the shared netns. The target stays unprivileged in the scope.
2. **There is no image rootfs.** The workload runs from the host filesystem, so
   the mount-namespace *isolation* a container gives is gone. The eBPF LSM still
   enforces `file_open` allow/deny *policy* on every open, so the security
   boundary holds — this is "leash on my real machine," arguably more on-spirit.

## To make it actually enforce (out of scope here)

- `bpf` in the active LSM list (`lsm=…,bpf` boot param) — already detected by the
  preflight on `feat/enforcement-preflight`. Native mode shares that gate.
- A compiled `leashd` able to run as a host process and take a `--cgroup` that is
  a systemd scope path (it already takes `--cgroup`; the wiring is the launcher).
- A native launch path (above `Runtime`) that creates the scope + netns, starts
  host-leashd, and runs the workload in the scope.

## Files

- `internal/runner/runtime_native.go` — the backend + the leak documented inline
- `internal/runner/runtime_native_test.go` — unit + live integration tests
- `internal/runner/runtime.go` — `newRuntime` resolves `native`
- `scratch-native-poc/build-box.sh` — runnable container-free box proof (local, untracked)
