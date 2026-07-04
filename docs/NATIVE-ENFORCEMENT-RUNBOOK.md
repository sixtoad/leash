# Native enforcement — on-device runbook

> **Status — 2026-07-04:** The kernel-prep parts (enabling the `bpf` LSM) are
> current, but this runbook predates the full Layer-2 path. For the up-to-date,
> verified way to run a sandboxed workload today — netns **egress**, the workload
> **running as the invoking user**, **CA trust**, the Control-UI netns IP, and the
> **leashd log file** — use [CLAUDE-CODE-LEASHED.md](CLAUDE-CODE-LEASHED.md), and
> see [CHANGELOG.md](../CHANGELOG.md) for the shipped feature set.

How to take the container-free Linux backend from **built & runnable
(non-enforcing)** to **live enforcement**, on a machine you can reboot and run as
root. Everything here is gated on a privileged, eBPF-LSM-activated host — it
**cannot** be done in the dev sandbox, which is why it's a runbook, not code.

**Companion docs:** [`RUNTIME-NATIVE-POC.md`](RUNTIME-NATIVE-POC.md),
[`LAUNCHER-ABSTRACTION.md`](LAUNCHER-ABSTRACTION.md),
[`LEASHD-HOST-MODE.md`](LEASHD-HOST-MODE.md).

## What's already built (runs without this runbook)

- `--runtime native` selects `nativeLauncher` (Step 2.1): a delegated systemd
  cgroup-v2 box + (root-only) named netns; rootless box lifecycle verified.
- `leash --daemon --host` (Step 2.2): host-mode config/paths; re-execs the same
  binary; built and unit-tested.
- `leash --runtime native run` (Step 3): flows end to end to the launcher and
  stops at `StartEnforcement` with an actionable message + the exact privileged
  command it would run.

What this runbook adds: the **two host prerequisites** (Parts A–B), a **direct
engine smoke test** that proves Layer 1 attaches natively (Part C), and the
**Step 3b** code that finishes the full `leash --runtime native run` path
(Part D).

## Prerequisites

A Linux host (not a VM-in-a-VM) where you can edit GRUB, reboot, and `sudo`.
Verify the kernel can do it (the in-tree preflight checks this and prints the
remedy automatically on any `--runtime native`/Linux run):

```sh
zgrep -E 'CONFIG_BPF_LSM|CONFIG_DEBUG_INFO_BTF' /proc/config.gz 2>/dev/null \
  || grep -E 'CONFIG_BPF_LSM|CONFIG_DEBUG_INFO_BTF' /boot/config-$(uname -r)
stat -fc %T /sys/fs/cgroup        # want: cgroup2fs
cat /sys/kernel/security/lsm      # if this already lists "bpf", skip Part A
command -v systemd-run systemctl nsenter ip nft iptables
```

Need `CONFIG_BPF_LSM=y` and BTF (`CONFIG_DEBUG_INFO_BTF=y`). If `bpf` is missing
from the active LSM list, do Part A.

## Part A — Activate the eBPF LSM (the universal gate)

This is required on **every** Linux host for Layer 1, not a quirk of any box. The
value to add is your current active LSMs (`cat /sys/kernel/security/lsm`) with
`bpf` appended. **First identify your bootloader** — it is not always GRUB:

```sh
[ -d /sys/firmware/efi ] && bootctl status 2>/dev/null | grep -q systemd-boot \
  && echo "systemd-boot (use kernelstub — Part A.2)" || echo "GRUB (Part A.1)"
```

### A.1 — GRUB (Debian/Ubuntu/most distros)

```sh
sudo sed -i 's/\(GRUB_CMDLINE_LINUX="[^"]*\)"/\1 lsm=lockdown,capability,landlock,yama,apparmor,ima,evm,bpf"/' /etc/default/grub
sudo update-grub          # Fedora: sudo grub2-mkconfig -o /boot/grub2/grub.cfg
sudo reboot
```
**Rollback:** remove the `lsm=…` clause from `/etc/default/grub`, `update-grub`, reboot.

### A.2 — systemd-boot / kernelstub (Pop!_OS, and any systemd-boot host)

Pop!_OS has **no `/etc/default/grub`**; `update-grub` does nothing. Use
`kernelstub` (note the flag is `--add-options`/`-a`, NOT `--add-cmdline`):

```sh
sudo kernelstub --add-options "lsm=lockdown,capability,landlock,yama,apparmor,ima,evm,bpf"
sudo reboot
```
**Rollback:** `sudo kernelstub --delete-options "lsm=…,bpf"` (same string), reboot.
Plain systemd-boot without kernelstub: append `lsm=…,bpf` to the `options` line
in `/boot/efi/loader/entries/*.conf` (or `bootctl set-default`), reboot.

### Confirm (either path)

```sh
cat /sys/kernel/security/lsm    # must now include "bpf"
```

## Part B — Build leashd (= the leash binary)

leashd is `leash --daemon`; the eBPF Go bindings are committed, so it builds with
a stock Go toolchain — no clang needed unless you change the eBPF C:

```sh
CGO_ENABLED=1 go build -o /usr/local/bin/leash ./cmd/leash
```

Only if you modify `internal/lsm/*.c` and must regenerate bindings (the dev box
has no clang): use the dockerized codegen — `make lsm-generate-docker` (rootful
`sudo podman`, FQN images), as used for #67.

## Part C — Smoke-test the engine directly (proves Layer 1, bypasses the runner)

> **✅ VERIFIED on-device (Pop!_OS, kernel with `bpf` active, 2026-07-02).** A
> forbidden read returned `cat: /run/leash-denied: Permission denied` while an
> allowed read succeeded — selective, container-free enforcement. The recipe
> below is the corrected, working one.

Before finishing the runner path (Part D), prove native enforcement itself works.
This stands up the box by hand and runs host-mode leashd against it, so it
isolates "does the eBPF LSM attach + deny natively" from "is the full CLI wired."

```sh
sudo -i      # enforcement needs CAP_BPF + CAP_NET_ADMIN
ID=smoke; UNIT=leash-native-$ID.service; NS=leash-native-$ID
RUN=/run/leash/$ID; mkdir -p $RUN/public $RUN/private; chmod 700 $RUN/private

# 1. Box: a detached, delegated transient SERVICE (NOT --scope) + a named netns
#    with loopback up (a fresh netns has lo DOWN; leashd binds 127.0.0.1).
systemctl reset-failed $UNIT 2>/dev/null
systemd-run --property=Delegate=yes --collect --unit=$UNIT -- sleep infinity
CG=/sys/fs/cgroup$(systemctl show -p ControlGroup --value $UNIT)   # must NOT be /sys/fs/cgroup
ip netns add $NS && ip -n $NS link set lo up

# 2. Policy: permissive baseline + a forbid on one file. The resource MUST be in
#    the `resource in [ … ]` form — leash silently drops `resource == …` in a
#    when-clause ("no resources found in policy"). File::/Dir:: are the entities.
cat > $RUN/public/leash.cedar <<'EOF'
permit (principal, action in [Action::"FileOpen", Action::"FileOpenReadOnly", Action::"FileOpenReadWrite"], resource)
when { resource in [ Dir::"/" ] };
permit (principal, action == Action::"ProcessExec", resource) when { resource in [ Dir::"/" ] };
permit (principal, action == Action::"NetworkConnect", resource) when { resource in [ Host::"*" ] };
forbid (principal, action in [Action::"FileOpen", Action::"FileOpenReadOnly", Action::"FileOpenReadWrite"], resource)
when { resource in [ File::"/run/leash-denied" ] };
EOF
echo top-secret > /run/leash-denied

# 3. Host-mode leashd, inside the workload netns, attached to the box cgroup.
LEASH_DIR=$RUN/public LEASH_PRIVATE_DIR=$RUN/private \
nsenter --net=/run/netns/$NS -- \
  leash --daemon --host --cgroup "$CG" --policy $RUN/public/leash.cedar \
    --proxy-port 18000 --listen 127.0.0.1:18080 & sleep 2

# 4. Until the bootstrap handshake is wired (Part D / option A), satisfy it manually.
touch $RUN/public/bootstrap.ready    # filename: entrypoint.BootstrapReadyFileName
sleep 2                              # let leashd reach "Successfully started monitoring file opens"

# 5. Run workloads IN the box cgroup: control (allowed) then the forbidden read.
sh -c 'echo $$ > '"$CG"'/cgroup.procs && cat /etc/hostname'      # EXPECT: succeeds
sh -c 'echo $$ > '"$CG"'/cgroup.procs && cat /run/leash-denied'  # EXPECT: Permission denied

# 6. Teardown.
kill %1 2>/dev/null; ip netns del $NS; systemctl stop $UNIT
systemctl reset-failed $UNIT 2>/dev/null; rm -rf $RUN /run/leash-denied
```

A ready-to-run version is at `scratch-native-poc/smoke.sh` (local, gitignored).
If the forbidden read is denied, **native enforcement works** — the rest is
wiring. If leashd errors at attach with "kernel may lack an active bpf LSM",
Part A didn't take (recheck `/sys/kernel/security/lsm`).

### Two real bugs found during on-device verification (fix upstream)

1. **`resource == File::"…"` in a when-clause is silently dropped.** The
   transpiler's `extractResources` (`internal/transpiler/cedar_to_leash.go`) only
   reads a when-clause resource from the `resource in [ … ]` form
   (`ConditionResourceIn`); an `==` there yields "no resources found in policy"
   and the whole rule is skipped — a policy footgun. Support `==` in when-clauses
   or fail loudly instead of warning-and-dropping.
2. **nftables control-plane rule doesn't quote the cgroup path.** `apply-nftables.sh`
   emits `socket cgroupv2 level 1 /sys/fs/cgroup/…/x.service …` → `nft` errors
   `unexpected /`, so it falls back to blocking *all* local access to the UI port.
   Quote the path (or use the cgroup id) so cgroup-scoped isolation works on host
   paths too. Non-fatal (fallback preserves the boundary) but degrades precision.

## Part D — Step 3b: finish the runner's native path

With the engine proven, close the two code gaps so `sudo leash --runtime native
run <cmd>` works fully. All in `internal/runner/launcher_native.go` unless noted.

1. **Bootstrap handshake (option A — see LEASHD-HOST-MODE.md §4).** leashd
   `waitForBootstrap()` blocks on `bootstrap.ready` in `LEASH_DIR`; nothing
   writes it natively. Have the launcher write it once the workload is staged
   (e.g. in `Provision` after the holder is up, or a new `WaitReady` step),
   preserving the fail-closed ordering (workload must not run before leashd is
   live). This replaces the manual `touch` in Part C step 4.
2. **Post-enforcement exec path.** After `StartEnforcement`/`WaitReady`,
   `startContainers` still calls the container CLI: `installPromptAssets`,
   `detectShell`, `execNonInteractive`/`execInteractive` use `docker exec`. For
   native, route these through `nativeLauncher.execInBox` (already present —
   places a process in the box cgroup) extended to also `nsenter --net=<ns>` into
   the workload netns, so the user command inherits both the LSM-scoped cgroup
   and the enforced netns. Guard each with `r.usingNativeRuntime()` exactly like
   the Step-3 pre-launcher guards.
3. **`StartEnforcement` lifecycle.** It currently `cmd.Start()`s leashd detached.
   Track the process so `Remove`/`finishLifecycle` stops it on exit, and surface
   leashd's early failures (attach/netfilter) instead of racing past them.
4. **In-netns Control UI reachability (optional).** leashd's `--listen` UI binds
   inside the workload netns; to reach it from the host, add a veth pair (host ⇄
   netns) or a port-forward in `Provision`. Until then, drive policy via the
   config file / event log.

Verify Step 3b on-device: `sudo leash --runtime native run -- cat
/etc/leash-denied` should be denied by policy, the agent command should
otherwise run from the host filesystem, and teardown should leave no
`leash-native-*` units or `/run/netns/leash-native-*`.

## Safety notes

- Native runs the workload from the **real host filesystem** (no image rootfs):
  the policy boundary holds (every `file_open` is checked), but there's no
  mount-namespace isolation — "leash on my real machine". Use a scoped policy.
- leashd holds `CAP_BPF`/`CAP_SYS_ADMIN`/`CAP_NET_ADMIN`; the **workload stays
  unprivileged** in the scope.
- Always confirm teardown removed the scope unit and netns (the integration
  tests assert this for the box lifecycle).
