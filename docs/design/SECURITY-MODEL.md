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
  - `socket_connect` for outbound `net.send`
- Proxy (HTTP[S]):
  - Allow/Deny per host
  - Header injection at the boundary (secrets never enter the agent)

### Proxy Certificate Management

- Public/private CA split: Target container only sees `/leash/ca-cert.pem`, while leashd reads `/leash-private/ca-key.pem` via `LEASH_PRIVATE_DIR` (0700) and keeps the key file mode at `0600`.
- CA lifetime: the certificate and key always share one lifetime. Before leashd starts, the runner keeps an existing pair only when both files are present and match; a certificate without its key (e.g. a reused `LEASH_SHARE_DIR` whose previous per-run private dir is gone), a key without its certificate, a mismatched pair, or a legacy key in the share dir is removed, and leashd generates a fresh pair. When a run ends and its private dir is removed, the certificate is also removed from a reused `LEASH_SHARE_DIR`. Reusing `LEASH_SHARE_DIR` across runs is supported; the key is never moved into, copied to or made readable from the share dir.

## Scoping

Enforcement activates for specific cgroups only, avoiding host/system interference.

## Observability

Structured events via ring buffers are forwarded to a WebSocket for UIs and automations. See `docs/PROTOCOL.md`.

