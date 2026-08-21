# Bubblewrap compatibility investigation

**Status:** Concluded

**Decision:** Do not integrate bubblewrap into Leash at this time.

## Question

Would adding bubblewrap to the native Linux runtime materially improve Leash,
and would it remain compatible with the injected-service path used to retrieve
Antigravity's token through a private D-Bus Secret Service?

## Current boundary

Native Leash already combines several independent controls:

- a cgroup-scoped eBPF LSM mediates file open, process execution, and network
  connections;
- a dedicated network namespace forces allowed egress through the policy-aware
  proxy;
- PID and IPC namespaces, private mounts, environment scrubbing, and socket
  masks isolate the host session;
- final `no_new_privs`, capability dropping, and seccomp hardening prevent the
  workload from remounting or entering namespaces after setup.

The filesystem remains the real host filesystem. Cedar and the eBPF LSM govern
access to it dynamically instead of constructing a static root filesystem.

## Antigravity token path

The token path is already brokered; the workload does not need the real session
bus.

1. `--inject-service` describes a protocol-agnostic helper binary, workload
   environment variable, Unix socket, and optional opaque configuration
   (`internal/runner/runner.go:121-132`, `:491-547`).
2. Leash starts the helper outside the workload namespaces, as the invoking
   user, with that user's `XDG_RUNTIME_DIR`. This lets the helper reach the real
   keyring while root and the sandboxed workload cannot
   (`internal/runner/launcher_native.go:274-379`, `:476-485`).
3. Socket paths beneath the real D-Bus, `/run/user`, systemd, container runtime,
   `/proc`, `/sys`, and `/dev` locations are rejected. The resolved path is
   checked again after symlink resolution (`internal/runner/runner.go:443-487`,
   `internal/runner/launcher_native.go:310-318`).
4. The helper must create its socket before the workload is launched. Failure is
   fatal rather than a fallback to the real session bus
   (`internal/runner/launcher_native.go:368-379`).
5. Native execution injects the private socket address into the workload. When
   the injected variable is `DBUS_SESSION_BUS_ADDRESS`, Leash keeps that value
   while the real `/run/user/<uid>` remains masked
   (`internal/runner/launcher_native.go:1173-1193`, `:1231-1243`).

Commit `009c23e` replaced the earlier in-tree, protocol-specific secret broker
with this generic injected-service contract. The runner tests use `agy` as the
workload and accept the provisioner's absolute `leash-plugin-secretbroker` path
(`internal/runner/inject_test.go:64-73`, `:259-273`).

## Bubblewrap compatibility

Bubblewrap is technically compatible with this design. A correct composition
would:

1. keep the secret-broker plugin outside bubblewrap;
2. enter Leash's existing network namespace rather than unsharing another one;
3. preserve the invoking host UID for Unix peer credentials;
4. bind the injected socket directory at the identical absolute path;
5. apply that bind after creating a private `/tmp` when the socket is under
   `/tmp`;
6. run Leash's final seccomp hardening only after bubblewrap finishes its mount
   and namespace setup.

The container backend already demonstrates the relevant boundary crossing: it
binds every injected socket directory into the target at the identical path and
sets the mapped environment variable (`internal/runner/launcher_native.go:382-404`,
`internal/runner/runner.go:2332-2340`). Bubblewrap would require the same
operation; it would not require exposing `/run/user` or the real D-Bus.

A naive integration would break token retrieval if it created a private `/tmp`
after mounting the injected socket, mapped the workload to an unrelated UID, or
placed the broker inside the sandbox where it could no longer reach the host
keyring.

## Value assessment

Bubblewrap's incremental benefit would be an independent, static filesystem
visibility boundary: a path omitted from the mount namespace would remain
unavailable even if Cedar were accidentally permissive or the LSM layer were
unavailable.

That benefit does not justify integration today:

- **It conflicts with dynamic policy.** Cedar rules can hot-reload. A path newly
  permitted at runtime would still be absent from bubblewrap's immutable mount
  view until the workload restarted.
- **It weakens native-mode compatibility.** Coding agents routinely discover
  shells, SDKs, package managers, caches, credentials, and user-installed tools
  across the host. Maintaining a correct static mount projection would recreate
  much of a container runtime's provisioning problem.
- **The stronger filesystem mode already exists.** Docker and Podman provide a
  root filesystem and explicit bind mounts while retaining Leash's LSM, proxy,
  Cedar, telemetry, and injected-service integration.
- **It adds another platform gate.** Availability and configuration of
  unprivileged user namespaces vary across hardened Linux installations.
- **It adds security-sensitive ordering and testing.** Network namespace
  inheritance, socket rebinding, UID mapping, resolver and CA exposure, and
  pre-seccomp setup would all become new launch invariants.
- **It does not improve token mediation.** The existing private broker socket is
  already the narrow boundary. Bubblewrap would only transport that same socket
  through another mount namespace.

## Decision

Keep the current architecture:

- use native mode when host-tool compatibility and hot-reloadable Cedar policy
  are the priority;
- use Docker or Podman when an independent root-filesystem boundary is required;
- retain the existing injected-service broker for Antigravity token retrieval in
  both modes.

Reconsider bubblewrap only if a concrete requirement emerges for
**container-free execution with an LSM-independent static filesystem boundary**.
That should be an explicit, opt-in profile rather than a default or replacement
for either existing runtime.

## Verification performed

The relevant parsing, socket validation, helper lifecycle, environment mapping,
teardown, and native command-construction tests pass:

```text
go test ./internal/runner -run 'Test(ParseInjectService|ValidateInjectSocket|SpawnInjectServicesContainer|TeardownInjectedPlugins|ParseArgsInjectService|NativeWorkloadScript)' -count=1
```
