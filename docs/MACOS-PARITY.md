# macOS enforcement parity

What the native macOS path (`mac-leash/` Swift extensions + `internal/darwind/`
Go daemon) enforces compared with Linux, and what it does not. The rule this
document holds the code to: **anything macOS cannot enforce must fail closed
or be refused, never silently weaker.**

## Architecture

- **`internal/darwind/`** (Go) runs the Cedar engine (the single decision
  core), the Control UI/API and websocket hub on `127.0.0.1:18080`, the MITM
  proxy on `127.0.0.1:18000` and the macsync state.
- **Policy pipeline.** `policy.Manager` compiles the Cedar policy once; the
  engine decides every userspace request (proxy, MCP) and
  `transpiler.CompileKernel` produces the kernel tables. On macOS a
  `macKernel` takes the place of `LSMManager`: `lsm.MacTablesFor` runs the
  kernel loaders' own compilation and `macsync.CompileTables` sends the result
  to the extensions as `mac.policy.tables`. A policy the extensions cannot
  enforce as written fails like a kernel refusal and the previous policy stays
  active everywhere.
- **LeashES** (Endpoint Security) tracks leashcli and everything it forks or
  execs, and decides exec, open and the file-system mutations from the tables.
- **LeashNetworkFilter** (`NEFilterDataProvider`) decides every TCP/UDP flow
  of a tracked PID from the connect table.
- **LeashProxy** (`NETransparentProxyProvider`) relays tracked TCP flows to
  the MITM proxy, which decides host names, MCP and header rewrites with the
  engine.
- The Swift matcher (`mac-leash/Shared/PolicyCore`) implements the four BPF
  lookups (open index, mutation index, exec rules, connect rules) and nothing
  else.

## What is enforced

| Capability | Linux | macOS | Notes |
|---|---|---|---|
| Startup without the enforcement layer | refuses (fail closed) | refuses: both extensions must be activated | no opt-out (`LEASH_REQUIRE_ENFORCEMENT` removed) |
| Workload launch | after the LSM is attached | after ES, NE and the proxy are connected, ES and NE applied the daemon's current tables, and ES tracks leashcli | `leash --darwin exec` gate; leashcli runs nothing without the go-ahead |
| Policy semantics | kernel tables from Cedar | the same tables, the same lookups | parity test: random strict policies, Go model of the Swift matcher == `cedar.Authorize`; vectors replayed against Swift |
| File open, by mode (read / write) | eBPF `file_open` | ES `AUTH_OPEN` | exact, prefix and directory entries; longest prefix; forbid-overrides-permit via the compiled exceptions |
| File creation | `file_open` of the new file | ES `AUTH_CREATE` (write open of the new file), `AUTH_TRUNCATE`, `AUTH_CLONE`, `AUTH_COPYFILE`, `AUTH_EXCHANGEDATA` | |
| Directory mutations (mkdir, unlink, rmdir, rename, link) | mutation table | ES `AUTH_CREATE` (non-regular), `AUTH_UNLINK`, `AUTH_RENAME`, `AUTH_LINK` | same table, same over-denials |
| Hard-link source must be readable | link guard | `AUTH_LINK` | |
| Exec | eBPF `bprm_check_security` | ES `AUTH_EXEC` | exact and prefix rules, kernel length limits apply |
| Network: IPv4, IPv6, ports, default deny | eBPF connect/sendmsg | NE content filter | hostnames resolved at load, IPv4-mapped decided as IPv4 |
| DNS | a UDP flow like any other | the same | queries through the system resolver come from `mDNSResponder`, not the workload, as on any macOS process |
| Host names, wildcards, MCP, header rewrite / secret injection | MITM proxy | MITM proxy via LeashProxy | HTTP/1.1 and HTTP/2 |
| No policy / stale policy | kernel keeps the last policy; workload stopped if leashd exits | no tables → deny; daemon gone > 30 s → deny (ES and NE) | |
| Extension restart mid-run | n/a | LeashES re-tracks still-running leashed PIDs from the daemon | |
| Forked children | cgroup | ES `NOTIFY_FORK` | |
| Processes left running after leashcli exits | stay in the cgroup | stay tracked until they exit | |
| Control-plane isolation | netfilter REJECT of the leash ports | daemon listeners bound to loopback; connections from tracked PIDs refused (peer PID check); websocket clients cannot change rules; only the ES extension may report tracked PIDs | |
| Leash's own state (policy file, CA key, daemon log) | outside the box | protected paths, denied for every open, mutation and exec | |
| Policy file | inside the leash container | per-user state dir `0700`; ownership/permission checks; no `/tmp` (#12) | |

## Gaps (documented, not hidden)

- **Loopback.** The content filter never sees loopback flows, so a leashed
  process can connect to other local services (a database on `localhost`)
  whatever the connect policy says. Leash's own ports are guarded by the peer
  PID check. On Linux the workload's loopback is its own network namespace.
- **Unaddressed sockets** (#188). The content filter sees TCP and UDP only.
  An unprivileged process cannot open packet or raw sockets on macOS; ICMP
  datagram sockets are not filtered.
- **Containment.** No cgroup or network namespace: enforcement follows the
  PID lineage ES observes (exec and fork). A process the workload gets
  another service to start (`launchctl`, `open -a`, an XPC service) is not
  leashed. The macOS path suits a careless-but-trusted agent; run hostile code
  in the container runtime.
- **Process hardening** (seccomp, capabilities, namespaces): no macOS
  equivalent is applied.
- **Plugins** (`--inject-service`, authz sockets): refused in native macOS
  mode; darwind serves no plugin authorization socket.
- **Time-of-check.** ES decides opens and execs by path at the time of the
  event, like the eBPF LSM.

## Validation

- Unit: `go test ./internal/macsync ./internal/darwind ./internal/lsm`,
  `swift test --package-path mac-leash`; CI builds the app and all extensions.
- VM: the SIP/AMFI-relaxed validation VM (`docs/MACOS-VM-VALIDATION.md`,
  `.claude/skills/leash-macos-vm`).
