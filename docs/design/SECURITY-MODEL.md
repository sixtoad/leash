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
- **Container mode:** the target container runs with `--cap-drop NET_RAW`;
  there is no opt-in.

`ping` normally keeps working: iputils and BusyBox fall back to an ICMP
datagram socket (`SOCK_DGRAM`/`IPPROTO_ICMP`) when the raw socket is refused
with `EPERM`. That needs the workload's group inside
`net.ipv4.ping_group_range`: Docker opens it to every group, Podman's default
(`0 0`) admits only gid 0. The datagram socket is an ordinary addressed
socket, decided by the connect rules with port 0. Tools that need raw
sockets (`tcpdump`, `nmap -sS`, `mtr`, `arping`) are not supported under a
policy that restricts egress.

### Proxy Certificate Management

- Public/private CA split: Target container only sees `/leash/ca-cert.pem`, while leashd reads `/leash-private/ca-key.pem` via `LEASH_PRIVATE_DIR` (0700) and keeps the key file mode at `0600`.

## Scoping

Enforcement activates for specific cgroups only, avoiding host/system interference.

## Observability

Structured events via ring buffers are forwarded to a WebSocket for UIs and automations. See `docs/PROTOCOL.md`.

