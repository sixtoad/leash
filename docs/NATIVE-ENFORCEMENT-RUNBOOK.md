# Native enforcement — runbook (Linux, container-free)

Canonical guide to leash's **container-free native runtime** on Linux: what it is,
how to prepare a host, how to run it, how it works end to end, and how to verify
and troubleshoot. This reflects the **shipped** architecture (released as
`native-v0.1.0`); see [CHANGELOG.md](../CHANGELOG.md) for the feature list and
[CLAUDE-CODE-LEASHED.md](CLAUDE-CODE-LEASHED.md) for the Claude Code recipe. The
design-era docs [`RUNTIME-NATIVE-POC.md`](RUNTIME-NATIVE-POC.md),
[`LAUNCHER-ABSTRACTION.md`](LAUNCHER-ABSTRACTION.md), and
[`LEASHD-HOST-MODE.md`](LEASHD-HOST-MODE.md) are historical.

## What it is

`--runtime native` runs the workload **directly on the host — no container** —
enforced by two layers:

- **Layer 1 — eBPF LSM** on a per-run cgroup: `file_open` / `exec` /
  `network-connect` decisions, uid-independent. Needs the `bpf` LSM active.
- **Layer 2 — MITM proxy** in a per-run network namespace: HTTPS is REDIRECTed to
  leashd's proxy, decrypted, and host/HTTP-policy-checked.

leash and `leashd` hold root for enforcement; the **workload runs as the invoking
user**. It's "leash on your real machine": the policy boundary holds (every
`file_open` is checked) but there is **no mount-namespace isolation**, so always
use a scoped policy. On walk, native is the **default** runtime (OS-detected).

## 1. Prerequisites

A Linux host you can reboot and `sudo` on. Check the kernel (the in-tree preflight
also checks this and prints the remedy on any native run):

```sh
zgrep -E 'CONFIG_BPF_LSM|CONFIG_DEBUG_INFO_BTF' /proc/config.gz 2>/dev/null \
  || grep -E 'CONFIG_BPF_LSM|CONFIG_DEBUG_INFO_BTF' /boot/config-$(uname -r)
stat -fc %T /sys/fs/cgroup        # want: cgroup2fs
cat /sys/kernel/security/lsm      # if this lists "bpf", skip step 2
command -v systemd-run systemctl nsenter ip iptables runuser
```

Need `CONFIG_BPF_LSM=y` + BTF (`CONFIG_DEBUG_INFO_BTF=y`). If `bpf` is missing
from the active LSM list, do step 2.

## 2. Activate the eBPF LSM (once per host)

Required on **every** Linux host for Layer 1. Add your current active LSMs
(`cat /sys/kernel/security/lsm`) with `bpf` appended. **Identify the bootloader
first** — it is not always GRUB:

```sh
[ -d /sys/firmware/efi ] && bootctl status 2>/dev/null | grep -q systemd-boot \
  && echo "systemd-boot (kernelstub — 2b)" || echo "GRUB (2a)"
```

**2a — GRUB** (Debian/Ubuntu/most):
```sh
sudo sed -i 's/\(GRUB_CMDLINE_LINUX="[^"]*\)"/\1 lsm=lockdown,capability,landlock,yama,apparmor,ima,evm,bpf"/' /etc/default/grub
sudo update-grub          # Fedora: sudo grub2-mkconfig -o /boot/grub2/grub.cfg
sudo reboot
```
Rollback: remove the `lsm=…` clause, `update-grub`, reboot.

**2b — systemd-boot / kernelstub** (Pop!_OS): there is **no `/etc/default/grub`**;
`update-grub` does nothing. The flag is `--add-options`, not `--add-cmdline`:
```sh
sudo kernelstub --add-options "lsm=lockdown,capability,landlock,yama,apparmor,ima,evm,bpf"
sudo reboot
```
Rollback: `sudo kernelstub --delete-options "lsm=…,bpf"`, reboot.

Confirm after reboot: `cat /sys/kernel/security/lsm` must now include `bpf`.

## 3. Install the binary

```sh
curl -fsSL https://raw.githubusercontent.com/sixtoad/leash/walk-integration/scripts/leash-install.sh | bash
# or from source:  scripts/install-leash.sh   (or  sudo scripts/install-leash.sh /usr/local/bin)
```

## 4. Run it

**Claude Code** (turnkey — generates a confinement policy, runs sandboxed):
```sh
cd <project> && scripts/leash-claude.sh          # see CLAUDE-CODE-LEASHED.md
```

**Any workload**, with your own Cedar policy:
```sh
sudo -E env "PATH=$PATH" "HOME=$HOME" leash --policy <policy.cedar> <command> [args…]
```

`sudo` is required (Layer 1 + netns need `CAP_BPF`/`CAP_NET_ADMIN`); `-E` +
explicit `PATH`/`HOME` let leash find the command and preserve the invoking user's
environment. Native is the default backend on walk; add `--runtime native` to be
explicit, or `--runtime docker` to opt into the container path.

## 5. How a run works (end to end)

1. **Box** — `Provision` starts a delegated systemd cgroup-v2 **transient service**
   (`systemd-run --property=Delegate=yes`; *not* `--scope`, which fails as root)
   and, for Layer 2, a named **network namespace** with **egress**: a veth pair
   (`10.<a>.<b>.1` host ⇄ `.2` netns, derived from the netns name), host NAT
   (`ip_forward` + `MASQUERADE` + `FORWARD` accept), and `/etc/netns/<ns>/resolv.conf`
   (public DNS — the host's `127.0.0.53` stub is meaningless in the netns).
2. **leashd (host mode)** — the launcher re-execs the same binary as
   `leash --daemon --host --cgroup <cg> [--policy …] [--lsm-only]`, entered into
   the netns via `nsenter --net` (which **preserves `/sys/fs/{cgroup,bpf}`** — `ip
   netns exec` would remount `/sys` and break the LSM) inside a **private mount ns**
   that bind-mounts the netns `resolv.conf`. leashd attaches the eBPF LSM to the
   cgroup and (Layer 2) applies the netfilter REDIRECT + starts the MITM proxy.
   Its stdout/stderr go to **`/tmp/leash-native-leashd-<netns>.log`**, not your
   TTY (so an interactive agent's UI isn't corrupted).
3. **Readiness (fail-closed)** — `WaitReady` writes the bootstrap marker, then
   **blocks until every LSM program has settled** (attached or failed) via an
   enforcement-ready marker. The workload is not launched until Layer 1 is live.
   It also publishes leash's MITM CA to a world-readable `/tmp` copy.
4. **Workload** — placed into the box cgroup (`echo $$ > cgroup.procs`, in the
   host PID ns so the pid resolves), `cd` to the workspace, then **hardened**:
   fresh **PID + IPC namespaces** with their own `/proc` (`unshare --ipc --pid
   --fork --mount-proc`) so it can't read host processes' `/proc/<pid>/environ` or
   share IPC; the private mount ns **masks** `/run/user/<uid>` (keyring/D-Bus) and
   `/tmp/.X11-unix` (X11); `DBUS_SESSION_BUS_ADDRESS`/`DISPLAY`/`XAUTHORITY` are
   scrubbed. Finally **dropped to the invoking user** (`runuser -u $SUDO_USER`).
   Under Layer 2 it inherits the netns and `NODE_EXTRA_CA_CERTS` (the `/tmp` CA
   copy) so Node clients trust the proxy. The cgroup placement stays in the host
   PID ns (the LSM is cgroup-scoped, unaffected by the workload's PID ns). This
   gives native container-grade **session isolation** (process table, IPC,
   keyring, GUI) on top of the file/exec/network policy.
5. **Teardown** — `Remove` tears down the egress (veth + host NAT rules +
   `/etc/netns/<ns>`), deletes the netns, removes the CA copy, and stops the unit.

**LSM-only fallback:** if egress setup fails, the run degrades to **host-netns
LSM-only** (Layer 1 keeps enforcing file/exec/network-connect; no L7 proxy) rather
than trapping the workload in a netns with no route out. Gated by
`nativeLayer2Enabled` / `layer2Active` (`internal/runner/launcher_native.go`).

**Control UI:** under Layer 2, leashd runs *inside the netns*, so the UI is at the
**netns IP** (`http://10.<a>.<b>.2:18080/`), **not** `localhost:18080` (which the
startup line currently still prints — a known wart).

## 6. Verify enforcement directly (engine smoke test)

To isolate "does the eBPF LSM attach + deny natively" from the full CLI, stand up
the box by hand and run host-mode leashd against it.

> **✅ VERIFIED on-device** (Pop!_OS, `bpf` active): a forbidden read returned
> `Permission denied` while an allowed read succeeded — selective, container-free
> enforcement.

```sh
sudo -i
ID=smoke; UNIT=leash-native-$ID.service; NS=leash-native-$ID
RUN=/run/leash/$ID; mkdir -p $RUN/public $RUN/private; chmod 700 $RUN/private

systemctl reset-failed $UNIT 2>/dev/null
systemd-run --property=Delegate=yes --collect --unit=$UNIT -- sleep infinity
CG=/sys/fs/cgroup$(systemctl show -p ControlGroup --value $UNIT)   # must NOT be /sys/fs/cgroup
ip netns add $NS && ip -n $NS link set lo up

# Policy: permissive baseline + a forbid on one file. The resource MUST use the
# `resource in [ … ]` form (leash silently drops `resource == …` in a when-clause).
cat > $RUN/public/leash.cedar <<'EOF'
permit (principal, action in [Action::"FileOpen", Action::"FileOpenReadOnly", Action::"FileOpenReadWrite"], resource)
when { resource in [ Dir::"/" ] };
permit (principal, action == Action::"ProcessExec", resource) when { resource in [ Dir::"/" ] };
permit (principal, action == Action::"NetworkConnect", resource) when { resource in [ Host::"*" ] };
forbid (principal, action in [Action::"FileOpen", Action::"FileOpenReadOnly", Action::"FileOpenReadWrite"], resource)
when { resource in [ File::"/run/leash-denied" ] };
EOF
echo top-secret > /run/leash-denied

LEASH_DIR=$RUN/public LEASH_PRIVATE_DIR=$RUN/private \
nsenter --net=/run/netns/$NS -- \
  leash --daemon --host --lsm-only --cgroup "$CG" --policy $RUN/public/leash.cedar \
    --proxy-port 18000 --listen 127.0.0.1:18080 & sleep 2
touch $RUN/public/bootstrap.ready ; sleep 2

sh -c 'echo $$ > '"$CG"'/cgroup.procs && cat /etc/hostname'      # EXPECT: succeeds
sh -c 'echo $$ > '"$CG"'/cgroup.procs && cat /run/leash-denied'  # EXPECT: Permission denied

kill %1 2>/dev/null; ip netns del $NS; systemctl stop $UNIT
systemctl reset-failed $UNIT 2>/dev/null; rm -rf $RUN /run/leash-denied
```

If the forbidden read is denied, native enforcement works. If leashd errors at
attach with "kernel may lack an active bpf LSM", step 2 didn't take (recheck
`/sys/kernel/security/lsm`). (`--lsm-only` here skips the proxy/netfilter so the
test needs no egress; drop it to exercise Layer 2.)

## 7. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `not confirmed ready` warning, workload ran anyway | Readiness didn't settle in time — check the leashd log for attach errors; usually the `bpf` LSM isn't active (step 2). |
| Workload can't reach the network / `ETIMEOUT` | Egress didn't come up → LSM-only fallback (no netns route). Check `/tmp/leash-native-leashd-<ns>.log` and the `egress setup failed` line. |
| `SELF_SIGNED_CERT_IN_CHAIN` | Workload can't read/trust the CA. Ensure the policy permits reading `/tmp` (the CA copy lives there); non-Node tools need the CA on the system bundle (pending). |
| UI blank at `localhost:18080` | Under Layer 2 the UI is at the **netns IP** (`10.<a>.<b>.2:18080`), not localhost. |
| Agent TUI garbled | Old binary — leashd output now goes to the log file, not the TTY. |
| `nft: unexpected /` on the control-plane rule | Upstream [#83](https://github.com/strongdm/leash/issues/83); the fallback is harmless inside the netns. |

## 8. Known upstream bugs (found during verification)

1. **`resource == File::"…"` in a when-clause is silently dropped.** The
   transpiler's `extractResources` (`internal/transpiler/cedar_to_leash.go`) only
   reads the `resource in [ … ]` form; an `==` yields "no resources found in
   policy" and the rule is skipped. Use `in [ … ]`. *(Not yet filed.)*
2. **nftables control-plane rule doesn't quote the cgroup path** — filed as
   [strongdm/leash#83](https://github.com/strongdm/leash/issues/83). Non-fatal;
   its fallback blocks all in-netns access to the UI port (which is only the
   agent, so the intent holds).

## 9. Safety notes

- **Filesystem**: no mount-namespace isolation — the workload sees the **real
  host filesystem**; the policy is the only boundary there. Use a scoped,
  default-deny policy (a wrong rule = exposure, with no rootfs behind it).
- **Session**: PID/IPC/keyring/GUI *are* isolated (fresh PID+IPC ns, keyring/D-Bus
  + X11 masks, env scrub) — see step 4. So the residual "runs in your session"
  risk is narrowed to the filesystem, which the policy covers.
- leashd holds `CAP_BPF`/`CAP_SYS_ADMIN`/`CAP_NET_ADMIN`; the **workload runs as
  the invoking user**, not root.
- **Shared kernel**: a kernel exploit escapes leash (as it would a container);
  only a VM contains that class. For untrusted content, run leash inside a
  container/VM.
- Confirm teardown removed the unit, netns, veth, and host NAT rules (the box
  lifecycle integration test asserts the unit/netns cleanup).
