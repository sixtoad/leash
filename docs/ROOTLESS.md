# Rootless podman: the leash enforcer daemon

Rootless podman is the safer way to run containers: no root daemon, and a
container breakout lands in an unprivileged user namespace. Leash's kernel
layer (Layer 1, the eBPF LSM programs that enforce file, exec, directory
mutation and network-connect policy) cannot load from there: the leash
container is root only inside a user namespace, and loading a
`BPF_PROG_TYPE_LSM` program needs `CAP_BPF` and `CAP_PERFMON` in the
initial user namespace.

Rootless runs therefore get Layer 1 from the **leash enforcer daemon**: a
small, socket-activated system service that holds only those two
capabilities and attaches the same eBPF LSM programs, compiled from the same
policy, to the rootless workload's cgroup. A rootless run then reports
`enforcement=lsm`, with the same guarantees as a rootful run.

There is no weaker automatic mode. Without a usable daemon a rootless run is
**refused before anything starts**. The only alternative is the existing,
explicit `--allow-proxy-only` opt-out, which is reported honestly as
`enforcement=proxy-only`.

## Setup

```bash
sudo leash daemon install        # once per host; adds $SUDO_USER to the "leash" group
# log out and back in (or: newgrp leash) so your session has the group
leash daemon status              # exit 0 when rootless runs can use it
leash --runtime podman -- your-agent ...
```

`leash daemon install` is idempotent and can be re-run to upgrade. It:

- copies the running `leash` binary to `/usr/local/lib/leash-enforcerd/leash`,
  owned by root. The service never executes a binary a user can replace.
- creates the system group `leash` and the system user `leash-enforcer`;
- writes `leash-enforcerd.socket` and `leash-enforcerd.service` to
  `/etc/systemd/system` and enables the socket;
- adds the user (`--user <name>`, default `$SUDO_USER`) to `leash`;
- warns when the kernel does not run BPF LSM programs (`bpf` missing from
  `/sys/kernel/security/lsm`; see `leash doctor`).

To change the binary of a running daemon, run `sudo systemctl restart
leash-enforcerd.service`. This detaches every attached session, and those runs
stop (see "Losing enforcement").

`sudo leash daemon uninstall` stops and removes the units, the binary, the
socket, the user and the group. The audit log in `/var/log/leash-enforcerd`
is kept unless you pass `--purge`.

Requirements: Linux with systemd, cgroup v2 with systemd user delegation
(the default for rootless podman on current distributions), podman with crun
(for `--group-add keep-groups`), and a kernel with `bpf` among its active LSMs.

## What a rootless run does

1. The runner detects a rootless engine (`podman info` reports
   `Host.Security.Rootless`). It asks the daemon for its status over
   `/run/leash/enforcerd.sock`. If the daemon is unreachable, refuses the
   caller, or reports that BPF LSM programs do not run, the run stops with the
   reason and the fix:

   ```
   rootless podman cannot load the eBPF LSM (Layer 1) itself, so leash will not start (fail-closed).
   Kernel enforcement for rootless runs comes from the leash enforcer daemon, which is not usable: dial unix /run/leash/enforcerd.sock: connect: no such file or directory.
   Install it once with:  sudo leash daemon install
   Check it with:         leash daemon status
   Or pass --allow-proxy-only to run with only the L7 proxy (filesystem, exec and socket policies are then NOT enforced).
   ```

2. The leash container gets the socket's directory mounted at
   `/run/leash-enforcer`, `--group-add keep-groups` (rootless podman otherwise
   drops the caller's `leash` group membership), and `LEASH_ENFORCER_SOCKET`.
   The workload container gets none of these.
3. Before the bootstrap, leashd sends the daemon the workload's cgroup and the
   active policy as strict Cedar (`Compilation.StrictText`). It resolves the
   policy's hostname connect rules in the workload's network namespace and sends
   those addresses too, which is exactly what a rootful leashd loads. In a
   rootful run, leashd's own initial policy load also attaches before the
   bootstrap.
4. The daemon checks the caller and the cgroup (below). It starts a
   per-session worker, which compiles the policy with `cedar.CompileLayers`
   (the legacy rewrite, the engine and `transpiler.CompileKernel`), checks the
   kernel's limits, and loads it with `lsm.LSMManager`: the same code leashd
   runs as root. The worker answers once every program has attached and `bpf`
   is confirmed active.
5. leashd writes the enforcement-ready marker. It reports `"enforcement":
   "lsm"` and `"layer1Via": "enforcer-daemon"`, and the client prints
   `leash: enforcement=lsm layer1=active layer2=active via=enforcer-daemon`.
6. Policy changes (file reloads, the Control UI's runtime layer) are validated
   against the kernel's limits, then sent to the daemon. A change the daemon
   cannot apply is an LSM update failure, and a file reload rolls back.
   Enforcement events from the daemon's programs flow back into leashd's event
   log and the Control UI.
7. At teardown leashd detaches, and the worker detaches its programs and exits.

The L7 proxy (Layer 2) and the netfilter rules in the pod's network namespace
work as in a rootful run. The leash container is `--privileged` inside the
rootless user namespace, which owns the pod's network namespace.

## What is enforced

| Layer | Rootful (Docker/podman) | Rootless podman + daemon |
|---|---|---|
| file open (read / write), directory mutations, hard links | eBPF LSM | same programs, same tables |
| exec | eBPF LSM | same |
| network connect / sendmsg (IPv4 and IPv6, by IP) | eBPF LSM | same; hostnames resolved in the workload's netns as before |
| HTTP(S) proxy, MCP, header rewrites | MITM proxy | same |
| netfilter redirect, QUIC drop, control-plane block | in the pod netns | same (verified with slirp4netns, podman 4.9's default, and pasta, podman 5's) |
| exec argv capture in event logs | tracepoint, root | not available: tracefs is root-only, and the daemon does not have the privilege |

Verified on a real kernel with an identical policy: the same denials, rootful
and through the daemon (forbidden read, write outside the permitted tree,
mkdir and unlink outside it, forbidden exec, TCP and UDP to non-permitted
addresses, HTTPS allowed and denied by the proxy).

## Security model

**What the daemon can do.** Load and attach BPF LSM programs and their maps,
nothing else. A BPF LSM program can only return a denial: it cannot grant
access the kernel's other checks refuse. Every program the daemon loads is
scoped by its maps to one cgroup subtree. So the worst a caller can make the
daemon do is deny operations of processes in a cgroup the caller owns, which
is something the caller could already do to its own processes.

**Who can talk to it.**
- The socket is created by systemd: `root:leash`, mode `0660`. Only members of
  `leash` can connect.
- `SO_PEERCRED` gives the caller's uid and pid. A uid inside a range of
  `/etc/subuid` is attributed to that range's owner. Container root in a
  keep-id user namespace is such a subordinate uid, and only its owner (via
  `newuidmap`) or root can run processes as it. A uid that is itself an
  account is never remapped, so an overlapping range cannot make one account
  act as another. The resolved account must be a member of `leash` (checked
  again in the daemon, on top of the socket mode). Root is refused, since it
  does not need the daemon.
- **A governed workload cannot use it.** The workload container never gets the
  socket. On top of that, a connection from any process whose cgroup is
  inside a governed cgroup is refused at connect and on every request. That
  covers a process that connected earlier and later moved into the workload.

**Which cgroups it accepts.** The target must be strictly inside the caller's
delegated systemd subtree,
`/sys/fs/cgroup/user.slice/user-<uid>.slice/user@<uid>.service/...` (never
the service itself or anything above). Every component must be a real
directory (no symlinks). The delegated service directory must be owned by the
caller, and the target by the caller or one of its subordinate uids (crun
creates a keep-id container's cgroup as container root). The target must be a
live cgroup v2 directory with processes in it. A target that overlaps a
governed cgroup (same, inside, or containing) is refused. The validated
cgroup's inode is handed to the worker, which refuses to attach if the cgroup
was replaced in between. Another user can neither attach to your cgroups nor
detach your sessions: a session is bound to the connection that attached it.

**The service.** Dedicated user `leash-enforcer`;
`AmbientCapabilities=CapabilityBoundingSet=CAP_BPF CAP_PERFMON` (no
`CAP_SYS_ADMIN`; kernels ≥ 5.11 account BPF memory per cgroup, and
`LimitMEMLOCK=infinity` covers older accounting). It also runs with
`NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`,
`PrivateDevices`, `PrivateNetwork`, `PrivateIPC`, `ProtectKernelTunables`,
`ProtectKernelModules`, `ProtectKernelLogs`, `ProtectControlGroups`,
`ProtectClock`, `ProtectHostname`, `RestrictAddressFamilies=AF_UNIX`,
`RestrictNamespaces`, `RestrictSUIDSGID`, `MemoryDenyWriteExecute`,
`LockPersonality` and `SystemCallFilter=@system-service bpf` (minus mount,
swap, reboot, module, raw-io, clock, cpu-emulation and obsolete). `bpf` is
part of systemd's `@privileged` set, so that set cannot be denied. The daemon
has no network: it never resolves names and receives addresses from the
client, as the kernel table needs them.

**Limits.** 256 connections (32 per caller), 128 sessions (16 per caller),
5 requests/s per connection (burst 20), 2 MiB per request line, 1 MiB of
policy text, 1024 resolved hosts with at most 64 addresses each, and 90 s for
a worker to attach. A slow client cannot stall a session: its event stream is
bounded, and excess events are dropped and counted; enforcement is
unaffected.

**Audit.** Every connection, request, refusal, attach, disconnect and session
end is written as a JSON line to `/var/log/leash-enforcerd/audit.log` and to
the journal (`journalctl -u leash-enforcerd`). Each line carries the peer
uid, the resolved owner, the pid, the peer's cgroup, the target cgroup, the
session, the SHA-256 of the policy (never its text), the result and the
reason.

**Losing enforcement.** A session ends when its client detaches, when its
cgroup is removed or has no processes left (the container stopped, including
after a leash crash), or when the daemon stops. A client that disconnects
without detaching does not end the session: enforcement stays attached until
the cgroup goes away (fail closed). If the daemon or a worker goes away while
the workload runs, leashd sees the session end and exits with `kernel
enforcement lost`. The runner then sees the leash container stop and kills the
workload container. A daemon-enforced workload never keeps running without its
kernel enforcement.

**Residual risks.**
- `SO_PEERCRED` reports the pid at connect time. A caller could pass its
  connected socket to another of its own processes, but such a process is the
  same user outside the workload: inside the workload the socket is not
  mounted, and requests are re-checked against the peer pid's cgroup.
- A user can deny operations to their own processes outside leash by
  attaching to their own cgroups. That is not an escalation.
- The daemon trusts its caller's resolved addresses for hostname rules. They
  only feed rules that cover the caller's own workload.
- SELinux hosts (Fedora, RHEL): the leash container connecting to a socket in
  `/run` may need a policy module; not verified.
- Rootless Docker is not supported yet. Its containers cannot keep the
  caller's `leash` group, so a rootless Docker run is refused unless
  `--allow-proxy-only` is passed.

## Machine-readable surface

- `leash version --json` advertises the `rootless-daemon` capability.
- `enforcement.ready` gains `"layer1Via": "enforcer-daemon"`; `enforcement`
  stays `"lsm"`, so callers that compare `enforcement` with `"lsm"` (Walk) keep
  working unchanged.
- `leash daemon status --json` reports `socket`, `reachable`, `usable`,
  `error`, `remedy` and the daemon's `version`, `protocol`, `bpfLSM`, `uid`
  and `sessions`.

The protocol (newline-delimited JSON, v1) is in `internal/enforcerd/protocol.go`.
