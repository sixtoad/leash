# Launcher abstraction — the seam above `Runtime`

**Status: design sketch, held.** Companion to
[`RUNTIME-NATIVE-POC.md`](RUNTIME-NATIVE-POC.md). A compile-checked version of
every type below lives at `scratch-native-poc/launcher-sketch/` (local,
type-checks: both launchers satisfy one interface).

## Why a second seam

The native PoC proved the box is Docker-free but found that `Runtime` is the
*wrong level* for a native backend. `Runtime` is **container-CLI-shaped** —
`Run`/`Output` take verbs (`run`, `pull`), `ExecWithInput` addresses a
*container*. The things that actually differ between "container world" and
"native world" are not commands, they're **session-lifecycle** decisions:

- leashd is a **sibling container** (container) vs. a **privileged host process**
  (native);
- the cgroup is **discovered from a hint file** after the container runs
  (container) vs. **known at scope creation** (native);
- the workload has an **image rootfs** (container) vs. **runs from the host fs**
  (native).

None of that is expressible as "a different CLI." So the fix is a **second seam
at a higher level**: `Launcher` owns the lifecycle; `Runtime` demotes to "the
container launcher's CLI driver."

```
runner  ──drives──▶  Launcher   (session lifecycle: provision → enforce → ready → exec → teardown)
                       │
          ┌────────────┴─────────────┐
   containerLauncher{rt}         nativeLauncher{}
          │                          │
       Runtime (docker/podman CLI)   systemd-run / unshare / host-leashd
```

`Runtime` is unchanged and stays useful — it's just no longer top-level.

## The interface

```go
// Launcher owns the enforcement-session lifecycle. The runner drives these five
// phases in order and is identical across backends.
type Launcher interface {
	Name() string
	Provision(ctx, WorkloadSpec) (*Box, error)        // build box (cgroup+netns), stage workload
	StartEnforcement(ctx, *Box, EnforcementSpec) error // attach eBPF LSM + proxy
	WaitReady(ctx, *Box) error                          // fail-closed gate
	Exec(ctx, *Box, ExecSpec) (exitCode int, err error)
	Teardown(ctx, *Box) error
}

// Box abstracts "where the two layers attach" so the runner never branches on
// container-vs-native again.
type Box struct {
	Backend    string // "docker" | "podman" | "native"
	CgroupPath string // Layer-1 (eBPF LSM) attach point, host-visible
	NetnsPath  string // Layer-2 (proxy) intercept point
	Workload   string // container id/name OR systemd scope unit
	ShareDir   string
}
```

`WorkloadSpec` (Image is empty in native — no rootfs), `EnforcementSpec`
(carries `RequireLSM`, policy, ports — independent of how the box was made), and
`ExecSpec` round it out; see the sketch for fields.

**Fail-closed contract (unchanged):** `WaitReady` must not return nil until
enforcement is bootstrapped; on error the runner tears down without ever running
the workload. `RequireLSM=false` still degrades to proxy-only with a loud
warning (Layer 2 survives) — only "no boundary at all" is fatal. This is the
#66 spirit, now a property of the interface rather than scattered in the
container path.

## How the two worlds map onto the lifecycle

| Phase | `containerLauncher` (today, refactored) | `nativeLauncher` (new) |
|---|---|---|
| **Provision** | `docker run -d <image>` → cgroup + netns + **rootfs** | `systemd-run --scope --property=Delegate=yes` + `ip netns add` → cgroup + netns, **no rootfs** |
| **Get cgroup** | read **hint file** on shared vol (bootstrap writes it; unknown until the container runs) | **known at scope creation** — no hint file |
| **StartEnforcement** | `docker run --privileged --network container:<target>` leashd — a **sibling container** | fork **host leashd** (`CAP_BPF`) via `nsenter --net=<ns>`, `--cgroup <scope>` |
| **WaitReady** | poll bootstrap marker on shared vol | wait host-leashd readiness (fd/unix socket) |
| **Exec** | `docker exec [-it] <target>` | `nsenter --net=<ns>` + place into scope cgroup, then exec |
| **Teardown** | `docker stop/rm` both containers | `systemctl stop <unit>.scope`, kill leashd, `ip netns del` |
| **FS view** | image rootfs (mount-ns **isolation**) | host fs (**policy-only**; isolation traded away) |
| **leashd identity** | sibling privileged **container** | privileged **host process** |

The left column is *exactly* today's `startContainers` / `launchTargetContainer`
/ `resolveCgroupPath` / `launchLeashContainer` / `waitForBootstrap` / `exec*` /
`stopContainers`, reorganized — no behavior change.

## Migration path (safe, incremental)

1. **Extract `containerLauncher` — zero behavior change.** Define `Launcher`;
   move the existing container lifecycle bodies into `containerLauncher` methods
   that still call `r.rt()`. The runner becomes
   `provision → startEnforcement → waitReady → exec → teardown`. docker/podman
   behave identically; the full `internal/runner` suite stays green. Pure
   refactor — reviewable on its own.
2. **Add `nativeLauncher`.** Implement the right column behind `--runtime
   native`. The one genuinely new capability is **leashd "host mode"**: run
   outside a container, take `--cgroup <path>` + join a netns, with configurable
   paths (today it assumes container mounts `/leash` `/cfg` `/log`).
3. **Select by name.** `newLauncher("native", nil)` → `nativeLauncher`;
   docker/podman → `containerLauncher{rt}`. `Runtime` is now an implementation
   detail of the container launcher.

Step 1 is shippable upstream on its own (a clean internal refactor that makes
the seam honest); step 2 is the native backend; the existing `--runtime native`
PoC slots in at step 2's entry point.

## Open questions / risks to resolve before step 2

- **Mounts become allow-directory policy rules (resolved — this is how native
  handles working dirs).** In the container world `WorkloadSpec.Mounts` are
  bind-mounts and confinement is *what's mounted* (mount-ns isolation: the agent
  can't see what isn't mounted). The native world has **no mounts** — the agent
  runs on the real host filesystem and sees everything; confinement is *policy
  denies by path*. So `Provision` in a native launcher does **not** mount
  anything: it seeds the policy with each `Mount.Host` as an **allowed directory
  scope**, and the workload's working dir becomes the natural allow-prefix.
  macOS already proves the pattern: `LeashPolicyRule.matches`
  (`mac-leash/Shared/PolicyModels.swift`) enforces `file_open` by a normalized
  `hasPrefix` over a `directory(String)` scope, with grant granularity
  `once | always | directory(path)` — the path-prefix grant *is* the "mount."
  Linux-native mirrors it exactly: the eBPF LSM `file_open` allow-rule has the
  same prefix shape as ES's `hasPrefix`. Consequence: `WorkloadSpec.Mounts` is a
  cross-backend *intent* ("the agent should have this dir"); `containerLauncher`
  realizes it as `-v host:dest`, `nativeLauncher` as an allow-`directory` rule.
  Trade-off is the documented one — policy boundary holds, isolation does not (an
  allowed read is the real file, not a sandboxed copy): "leash on my real
  machine."
- **leashd host mode.** Does leashd hard-assume container paths/mounts? Host mode
  needs path config + the ability to attach given just a cgroup path. This is the
  real new work, not the box.
- **Privilege.** Host leashd needs `CAP_BPF`/`CAP_SYS_ADMIN` (root, setcap'd
  helper, or a systemd system service). The workload stays **unprivileged** in
  the scope — privilege moves from the container to leashd, not to the agent.
- **Shared netns.** leashd and the workload must share one netns for proxy
  redirect. A **named** netns (`ip netns add`, both `setns` in) is cleaner than
  `unshare`-in-child + `setns`-by-fd. The PoC used `unshare --user --net` only to
  prove isolation without root.
- **System vs user scope.** Enforcement needs root, so a **system** scope
  (`systemd-run --scope` without `--user`) keeps the cgroup host-visible for
  root leashd. The PoC's `--user` scope was a no-root convenience for the box
  demo only.
- **Readiness signal.** Replacing the shared-volume bootstrap marker with a
  host-leashd readiness fd must preserve the exact fail-closed timing.

## Files

- `docs/LAUNCHER-ABSTRACTION.md` — this sketch
- `docs/RUNTIME-NATIVE-POC.md` — the PoC that motivated it
- `scratch-native-poc/launcher-sketch/launcher.go` — compile-checked interface +
  both skeleton launchers (local, untracked)
