# Security Model

Leash combines kernel‑level enforcement (eBPF LSM) with an application‑layer proxy to provide defense‑in‑depth for agent workloads.

## Trust Boundaries

- Agent container: governed workload, scoped by cgroup.
- Manager container: privileged, attaches BPF programs and runs the HTTP(S) proxy.
- Host: remains outside governance; enforcement triggers only for allowed cgroups.

## Deny‑By‑Default

Policies aim for deny‑by‑default with explicit, explainable allows. Start in Record/Shadow to reduce friction and then enforce.

## Enforcement Layers

- Kernel (eBPF LSM):
  - `file_open` decisions including read vs. write
  - `bprm_check_security` for `proc.exec`
  - `socket_connect` / `socket_sendmsg` for outbound `net.send`
  - `socket_create` for packet, raw IP and SCTP sockets, whose traffic no
    address rule can see: denied unless the policy restricts no destination
    (see below)
- Proxy (HTTP[S]):
  - Allow/Deny per host
  - Header injection at the boundary (secrets never enter the agent)

### Packet, raw and SCTP sockets

A packet socket bound with `bind()`, or a raw IP socket with `IP_HDRINCL`,
emits frames or IP packets with `send()` and no destination address, and
SCTP adds peers through `sctp_connectx()`, the `sendmsg()` address list and
the peer's own address list, none of which pass `socket_connect` (#188).
Leash closes this at three points:

- **Kernel:** `lsm_socket_create` refuses `AF_PACKET`, `AF_XDP`, `SOCK_RAW` on
  `AF_INET`/`AF_INET6`, `SOCK_SEQPACKET` on an IP family and `IPPROTO_SCTP`
  in the governed cgroup with `EPERM`, unless the policy restricts no
  destination (connect default allow, no deny connect rule, no MCP forbid).
  This holds whatever capabilities the workload has (rootless podman,
  custom `--cap-add`). Each decision is logged as `event=net.socket`.
- **Native mode:** the workload has no `CAP_NET_RAW`, nor any other
  capability (empty bounding set, `no_new_privs`, drop-user; see
  [Workload capabilities](#workload-capabilities)).
- **Container mode:** a run never starts without the kernel gate (leash
  always fails closed when the eBPF LSM is unavailable), so the target keeps
  the runtime's capability set: dropping `NET_RAW` would add nothing the
  gate does not already refuse, and it breaks
  `ping` in Debian and Ubuntu images, whose iputils `ping` carries the
  `cap_net_raw+ep` file capability and cannot even be executed without
  `NET_RAW` in the bounding set (measured on #188).

`ping`: iputils `ping` opens an ICMP datagram socket
(`SOCK_DGRAM`/`IPPROTO_ICMP`) first. That is an ordinary addressed socket,
decided by the connect rules with port 0 (`Host::"10.0.0.1"` permits pinging
it, `Host::"10.0.0.1:443"` does not), and it needs the workload's group
inside `net.ipv4.ping_group_range`: Docker opens the range to every group;
a fresh network namespace (native mode) and Podman's default (`0 0`) do not,
so `ping` already failed there without `CAP_NET_RAW`. BusyBox `ping` uses
only a raw socket and is refused under a restricting policy, as are tools
that need raw sockets (`tcpdump`, `nmap -sS`, `mtr`, `arping`).

### Workload capabilities

**Native mode** (#203). The workload holds no capability and cannot regain
one. `leash --harden-exec --user <user>`, the last step of the native launch
(after leash's own cgroup placement, mounts and `unshare`), runs as root and,
on one locked OS thread:

1. sets `no_new_privs`;
2. drops every capability from the bounding set and clears the ambient set
   (this needs `CAP_SETPCAP`, which is why it runs before the user switch;
   until #203 it ran after `runuser` and failed silently, leaving
   `CapBnd=000001ffffffffff`);
3. switches to the invoking user (supplementary groups from NSS, gid, uid)
   and sets `HOME`, `SHELL`, `USER`, `LOGNAME` as `runuser -u` did;
4. clears the inheritable, permitted and effective sets;
5. installs the seccomp filter (mount family, `unshare`, `setns`);
6. checks the result and refuses to run the workload if any capability set is
   non-empty or `no_new_privs` is unset;
7. runs the workload. As PID 1 of the box's PID namespace it stays as init
   (reaps orphans, forwards `SIGTERM`/`SIGHUP`/`SIGUSR1`/`SIGUSR2`; the
   terminal delivers `SIGINT`/`SIGQUIT` to the workload directly), as
   `runuser` did before it.

Nothing the native box needs runs after this step with privilege: the CA
trust is environment variables, the masks and namespaces are set up before
it, and the agent runs as the user. Inside the box `/proc/self/status` shows
`CapInh`, `CapPrm`, `CapEff`, `CapBnd`, `CapAmb` all zero, `NoNewPrivs: 1` and
`Seccomp: 2`. A setuid-root binary (`sudo`) runs without raising its euid, and
a file-capability binary with the effective bit (iputils `ping`,
`cap_net_raw+ep`) cannot be executed (`EPERM`). `--user root` gets the same
treatment: uid 0 with no capabilities. `runuser`'s PAM session (for example
`pam_limits`) no longer runs for the workload; the limits are those of the
`sudo` session.

`--allow-namespaces` (nested containers, sandbox tools) skips this step and
keeps the earlier `runuser` launch with the runtime's bounding set and no
`no_new_privs`: rootless podman/docker inside the box need `newuidmap`'s setuid
bit or file capability, which either would disable. That flag already
reopens the bind-mount bypass and is off by default.

**Container mode** keeps the runtime's default capability set for the target
(Docker: `CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `FSETID`, `KILL`, `SETGID`,
`SETUID`, `SETPCAP`, `NET_BIND_SERVICE`, `NET_RAW`, `SYS_CHROOT`, `MKNOD`,
`AUDIT_WRITE`, `SETFCAP`; Podman's default omits `NET_RAW`, `MKNOD` and
`AUDIT_WRITE`), and leash adds no `--cap-drop` or `no-new-privileges`. The
target is an arbitrary image whose workload is often root and whose
entrypoint and tools rely on these: `leash-entry` installs the CA as root or
through `sudo` in a non-root image (#181), entrypoints `chown` volumes and use
`gosu`/`su-exec`/`sudo` (`SETUID`, `SETGID`, `AUDIT_WRITE`), package installs
need `CHOWN`/`DAC_OVERRIDE`/`FOWNER`/`FSETID` and `setcap` in postinst scripts
(`SETFCAP`), dev servers bind low ports (`NET_BIND_SERVICE`). None of the
default capabilities lets the workload get around the kernel policy: the eBPF
LSM decides file opens, execs, connects and socket creation for the cgroup
whatever the capabilities (`NET_RAW` is covered by the socket gate above),
`SYS_ADMIN`/`BPF`/`NET_ADMIN` are not in the default set, and the runtime's
seccomp profile and device cgroup still apply (`MKNOD` creates no usable
device beyond the default ones). A user who wants less can pass the runtime's
own `--cap-drop` for their image; leash does not guess one for every image.

### Proxy Certificate Management

- Public/private CA split: Target container only sees `/leash/ca-cert.pem`, while leashd reads `/leash-private/ca-key.pem` via `LEASH_PRIVATE_DIR` (0700) and keeps the key file mode at `0600`.
- CA lifetime: the certificate and key always share one lifetime. Before leashd starts, the runner keeps an existing pair only when both files are present and match; a certificate without its key (e.g. a reused `LEASH_SHARE_DIR` whose previous per-run private dir is gone), a key without its certificate, a mismatched pair, or a legacy key in the share dir is removed, and leashd generates a fresh pair. When a run ends and its private dir is removed, the certificate is also removed from a reused `LEASH_SHARE_DIR`. Reusing `LEASH_SHARE_DIR` across runs is supported; the key is never moved into, copied to or made readable from the share dir.

## Scoping

Enforcement activates for specific cgroups only, avoiding host/system interference.

## Observability

Structured events via ring buffers are forwarded to a WebSocket for UIs and automations. See `docs/PROTOCOL.md`.

