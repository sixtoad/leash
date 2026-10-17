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
- **Native mode:** the workload has no `CAP_NET_RAW` (cleared bounding set,
  drop-user).
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

### Proxy Certificate Management

- Public/private CA split: Target container only sees `/leash/ca-cert.pem`, while leashd reads `/leash-private/ca-key.pem` via `LEASH_PRIVATE_DIR` (0700) and keeps the key file mode at `0600`.
- CA lifetime: the certificate and key always share one lifetime. Before leashd starts, the runner keeps an existing pair only when both files are present and match; a certificate without its key (e.g. a reused `LEASH_SHARE_DIR` whose previous per-run private dir is gone), a key without its certificate, a mismatched pair, or a legacy key in the share dir is removed, and leashd generates a fresh pair. When a run ends and its private dir is removed, the certificate is also removed from a reused `LEASH_SHARE_DIR`. Reusing `LEASH_SHARE_DIR` across runs is supported; the key is never moved into, copied to or made readable from the share dir.

## Scoping

Enforcement activates for specific cgroups only, avoiding host/system interference.

## Observability

Structured events via ring buffers are forwarded to a WebSocket for UIs and automations. See `docs/PROTOCOL.md`.

