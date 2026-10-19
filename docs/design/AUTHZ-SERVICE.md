# Cedar decision engine and plugin authorization service (#142)

Status: design + implementation, stacked in three PRs (engine, preparser and
kernel compiler; adapters; socket service). Builds on #138 (deterministic rule
precedence), which this stack is based on.

## 1. Goal and the hard requirement

Injected plugins (`--inject-service`) need to ask Leash, at request time, "may I
do X on Y?" instead of carrying their own static allow-lists. Typical cases are
the Walk secret broker (per-secret grants, some time-bound or approved per
request), the #113 code-indexer MCP gate (per-call retrieval checks), and any
action a future plugin manifest (#18) declares.

The owner's requirements:

- Those answers must come from **the same code that decides for every other
  adapter**. No second evaluator, no per-adapter copy of decision logic.
- **Cedar's own evaluator** (cedar-go `Authorize`) is that code. Every
  userspace adapter (proxy connect, MCP tools/call, the authz socket, any
  future userspace check) is a Cedar request against the active policy set.
- **Semantics are strict Cedar**: forbid overrides permit, default deny.
- The kernel (eBPF) and macOS tables are compiled only from a **restricted,
  provably equivalent subset** of Cedar; anything else that would affect a
  kernel-enforced action fails the load.
- Existing policies keep working: a **preparser** rewrites Leash's legacy
  "most specific wins" policies into equivalent strict Cedar. Strict Cedar is
  the **default** dialect (contract 3); the legacy dialect is an explicit
  opt-in, `@leash_semantics("legacy")` (§4.1).

## 2. How Cedar policy flows

```
leash.cedar ─► parse (cedar-go) ─► @leash_semantics?
                                      │ "legacy"                    │ none or "cedar"
                                      ▼                             │
                      transpiler.RewriteLegacy (preparser)          │
                      legacy IR per policy ─► strict Cedar          │
                                      └──────────────┬──────────────┘
                                                     ▼
                                        strict cedar.PolicySet
                       ┌─────────────────────────────┼──────────────────────────────┐
                       ▼                             ▼                              ▼
             engine.New (package engine)   transpiler.CompileKernel        HTTP rewrites
             cedar.Authorize + Leash's     kernel subset only, else        (configuration,
             entity hierarchy              the load fails                  unchanged)
                       │                             │
     ┌─────────────────┼────────────────┐            ├─► lsm.LSMManager ─► BPF maps (Linux)
     ▼                 ▼                ▼            └─► macsync ─► ES / NE (macOS)
 proxy connect     MCP tools/call   authz socket
```

`policy.Manager` keeps each layer (file, runtime) as Cedar. On every change it
rewrites the legacy layers together, appends the strict layers, builds one
engine and compiles one set of kernel tables from the result, and publishes
both. A change that fails any step is rejected and leaves the previous
policy active. When a strict layer is present, the legacy layers' rules are
rewritten as usual but the legacy *global* defaults (the MCP default permit,
the file-open default allow of an allow on `/`) are not added: the strict
layer's default deny governs.

## 3. Architecture

### 3.1 Options considered

- **A. A decision function over the transpiled IR** (`lsm.Decider`, the first
  version of this stack). One function per rule kind, with Leash's deviations
  from Cedar built in, and cedar-go only as parser and test oracle. It keeps
  the kernel's semantics as the source of truth, but it is a hand-written
  evaluator: every new Cedar feature a plugin wants (conditions, `like`,
  `has`, sets) must be re-implemented and kept in sync with cedar-go.
- **B. cedar-go's evaluator as the engine, the kernel compiled from a
  subset.** Userspace decisions are `cedar.Authorize`. Leash's only
  contribution is the request: the entity hierarchy that gives
  `resource in E` its meaning for files, hosts and MCP tools. The kernel
  enforces tables compiled from the same policy set by a compiler that
  accepts only constructs it can compile exactly. Legacy semantics survive as
  a rewrite to strict Cedar, not as evaluator behavior.

**Decision: B** (owner decision). There is one evaluator, it is Cedar's, and
the kernel is a compiled view of the same policy that the parity tests prove
equivalent.

### 3.2 The engine (`internal/engine`)

`engine.New(*cedar.PolicySet)` partitions the set once and is immutable; a
policy change builds a new engine.

- **Routing (optimizations only).** Built-in policies are indexed by the
  actions their scope can match, and a request's parents are filtered to the
  entities some policy names; both only skip evaluations that are false.
- **Built-in requests.** `DecideOpen(path, FileOpenReadOnly|FileOpenReadWrite)`,
  `DecideExec(path)`, `DecideConnect(host, ip, port)`, `DecideMCP(server,
  tool)` build a Cedar request (principal `Workload::"workload"`, the action,
  the resource with its parents, context) and call `cedar.Authorize`.
  `Decide(Request)` routes the generic socket request. The engine implements
  the proxy's `PolicyChecker` (`CheckConnect`, `CheckMCPCall`,
  `HasMCPPolicies`).
- **Plugin requests** (`<Namespace>::Action::"Verb"`) are Cedar requests with
  the socket's principal, the given resource (no hierarchy) and context.
- **Namespace rule.** A plugin request is evaluated only against policies
  whose action scope names its namespace. A policy whose action is
  unconstrained applies to Leash's built-in actions only, so a broad
  `forbid (principal, action, resource)` written for the workload never
  decides a plugin's question, and every plugin grant is explicit. A policy
  that names both Leash and plugin actions fails the load. An action entity
  must be `Action::"..."` or `<Namespace>::Action::"..."`.
- **Annotations.** `@id("...")` names a policy in decisions and audit;
  `@expires("<RFC 3339>")` stops it from applying at that instant (the
  engine skips expired policies; Cedar itself ignores annotations). A
  malformed `@expires` fails the load.
- **Decisions** carry `Allow`, a stable reason (`matched_permit`,
  `matched_forbid`, `default_deny`, ...) and the deciding policy IDs (exactly
  cedar.Authorize's diagnostic reasons: every applicable forbid on a deny,
  every applicable permit on an allow). A condition that errors makes its
  policy not apply, as in Cedar; the error is reported in `Detail`.
- **MCP inspection.** `HasMCPPolicies` is false only when an unconditional
  permit covers every MCP call and no other policy can apply to McpCall. In
  strict mode with no MCP policy at all every call is denied, so the proxy
  inspects MCP traffic.

#### Leash's entity hierarchy

Leash has no entity store: a built-in resource's parents are a pure function
of the request (`internal/engine/entities.go`). This is what `resource in E`
means, and what the kernel compiler compiles.

| Resource | Is `in` |
|---|---|
| `File::"<path>"` (open, exec) | Nothing else of type `File`: `File::"p"` is **exactly** the path p (`resource in File::"p"` and `resource == File::"p"` both mean p). `FilePrefix::"q"` for every byte prefix `q` of the path, the path itself included (`FilePrefix::"/bin/rm"` covers `/bin/rm` and `/bin/rmdir`; it is the strict form of a legacy `File` rule). `Dir::"d/"` (and `Dir::"d"`, the same directory) for every directory `d/` above the path. For **opens only**, also the directory itself: `Dir::"/x/"` covers `/x` (#119). |
| `Host::"<name>"` (or `Host::"<ip>"` without a name) | `Host::"name"` (lowercased, trailing dot removed), `Host::"*.zone"` for every proper label suffix (`*.example.com` covers `a.example.com`, not `example.com` or `evilexample.com`), `Host::"<ip>"`, `Host::"*"`; with a known port each of those also as `Host::"<x>:<port>"`, plus `Host::"*:<port>"`. An IP literal is an address, never a name. |
| `MCP::Tool::"<tool>"` (lowercased) | `MCP::Server::"<server>"` (lowercased; scheme, path and port removed). `context.server` carries the normalized server. |
| `Action::"FileOpenReadOnly"`, `Action::"FileOpenReadWrite"` | `Action::"FileOpen"` (write `action in Action::"FileOpen"` for both). |

### 3.3 Kernel compilation (`transpiler.CompileKernel`)

The kernel subset, required of every policy that can apply to
`FileOpenReadOnly`, `FileOpenReadWrite`, `ProcessExec` or `NetworkConnect`
(including policies with an unconstrained action):

- principal unconstrained (also required for McpCall: the proxy cannot tell
  principals apart either);
- no `@expires`;
- the resource scope and every `when`/`unless` built only from
  `resource in E`, `resource in [E, ...]`, `resource == File::"path"`,
  `resource == Host::"name"`,
  `resource is T [in E]`, `action == A`, `action in A|[...]`, `action != A`,
  `true`/`false`, `&&`, `||`, `!` and if-then-else; no context, principal or
  attributes;
- `File`/`FilePrefix`/`Dir` IDs absolute and at most 255 bytes (`==` only on
  `File`: a `Dir` or `FilePrefix` never equals a file request's resource);
  `Host` IDs lowercase, one of `name`, `*.zone`, `*`, IPv4, each optionally
  `:port`; other resource types for built-in actions are rejected (a legacy
  file should be migrated, which canonicalizes `Net::*` types);
- `action == Action::"FileOpen"` is rejected: it matches no request.

Anything else fails the load with the policy named and the reason.
MCP and plugin policies are userspace only and may use the full language,
with one limit for MCP (#164): the MCP adapters (the proxy's tools/call
check and the socket's built-in `McpCall` query) send the workload as
principal, `MCP::Tool`/`MCP::Server` entities without attributes or tags,
and a context holding only `server`. An `McpCall` policy whose condition
reads another context key, the principal, or an attribute or tag could
never apply as written, so it fails the load (permit or forbid), naming the
policy, its line and the construct. Plugin policies are not restricted: the
plugin sends the context they test.

**Files and execs: regions.** Every `FilePrefix`/`Dir` entity named by a
kernel policy is a *prefix point*; every exact `File`, and (for opens) every
`Dir`'s directory itself, is a *single*. The non-single paths whose longest
matching prefix point is `x` form a region; each single is a region of its
own. Within a region every resource atom has the same truth value, and the
subset admits no other resource test, so `cedar.Authorize` decides the whole
region the same way. The compiler evaluates one representative path per
region and action with the engine and emits a longest-prefix rule for each
prefix region (a rule equal to its enclosing region's decision is pruned),
then an exact rule for each single the prefix rules would decide otherwise.
The root region becomes the kernel default (an allow on `/`), split per open
mode when the modes differ.

- **Exact rules, file open and link:** `lsm.ExactPath` rules compile to the
  file-open index's exact map (the map the directory-self entries use) with a
  specificity above every prefix of the path; the hard-link guard reads the
  same index. A generic exact deny also enters the mutation hooks' exact
  deny map (mkdir/unlink/rmdir/rename of that path). A directory whose own
  decision agrees with its contents' is emitted as one directory rule
  (prefix plus self), the form macOS reads as a Directory rule.
- **Exact rules, exec:** `lsm_exec` has no exact map. An exact exec rule is
  its path followed by a NUL byte: `check_exec_policy` compares rule bytes
  against the NUL-terminated resolved path, so the NUL matches only where
  the path ends, and the rule (one byte longer) outranks every prefix. No BPF
  change; the 64-byte exec rule limit leaves 63 bytes for an exact path.
  Both limits are checked at compile time, naming the policy and its line.
- An exact allow on `/` covers only the root directory; it does not turn
  the kernel default to allow.

**Directory mutations.** mkdir, unlink, rmdir, both sides of rename, the
new name of a hard link and every other new name (`path_mknod`: a regular
file from `open(O_CREAT)` or `mknod`, a fifo, a device, a unix socket's path,
#204) are checked by the kernel against the path they create or remove,
before the entry exists, through a
table of their own: allow prefixes, deny prefixes and exact denies. They have
no Cedar action. A mutation of path t is allowed iff Cedar allows
`FileOpenReadWrite` on t **and** on a new entry of t's directory (writing the
directory's contents), `engine.DecideMutation`. So a granted tree
`Dir::"/work/"` lets the workload create and remove entries below `/work`,
but not remove or rename `/work` itself unless `/` is writable too, and a
forbidden file cannot be unlinked even in a writable directory.

- **Creates (#204).** `file_open` runs only after the kernel created the
  inode, so a create used to leave an empty file behind even when the open
  was denied. `lsm_mknod` decides the new name first, with this table: no new
  decision, no new Cedar meaning. `open(O_CREAT)` asks before the kernel knows
  whether the name exists; a denial only drops `O_CREAT`, so the open of an
  existing file still proceeds and `file_open` decides it (a `file.create`
  denial record can then precede an allowed open). An allowed regular create
  writes no record of its own (the open writes one); other objects do.
  Unlike mkdir, the hook never skips on the overlay correlation (overlayfs
  creates its backing objects through `vfs_create`/`vfs_mknod`, which do not
  re-enter `path_mknod`), but an allowed create still installs it for the
  backing opens of the new file. `path_mknod` is not a sleepable hook, so
  the kernel refuses `bpf_d_path` there: the parent path is rebuilt by
  walking dentries and mounts as `d_path` does (to the task's root, or the
  namespace root), one step per `bpf_loop` iteration so the verifier checks
  the step once. Symlinks (`path_symlink`) are still not gated on Linux.

- The compiler builds this table from those decisions, as `lsm.OpMutation`
  rules carried with the open rules: the single source of truth. It is never
  inferred from the open rules. Inferring it is what broke mutations in the
  first rework: the region compiler folds read-only and read-write into one
  generic rule and prunes nested read-write rules, and the old inference only
  took read-write directory allows. The loader still derives a table from the
  open rules for rule sets built in code, which carry no `OpMutation` rule.
- **BPF change (one function, `check_mutation_policy`):** each trie still
  returns its longest matching prefix, and its value is now that prefix's
  specificity (the rule's length). The longer of the allow and the deny wins,
  a tie denies, an exact deny always denies, no match denies. A derived table
  stores 1 everywhere, so any deny still outranks any allow there, exactly as
  before. Without this change the table is deny first, which cannot express
  a permit nested in a forbid nested in a permit: the common "allow
  everything, deny a directory, allow a subdirectory" shape (and every
  `unless` exception under a broad permit) would have to fail the load.
- Same regions as the open index, one representative each, top down: a
  region whose decision differs from the one its nearest enclosing rule
  gives gets a rule at its point; a single (an exact `File`, a directory
  itself) gets an exact deny where the table would allow it.
- **Over-denial with a warning:** the table has no exact allow. Where Cedar
  allows mutating one single path that the table denies around it (an exact
  permit carved out of an excluded prefix, e.g. `permit ... resource ==
  File::"/etc/hostname"` next to `unless { resource in
  FilePrefix::"/etc/hostname" }`), the kernel denies mutations of that path
  (opens of it are still allowed), and the load logs a warning naming the
  policy, its line and the path (`transpiler.KernelWarning`; the linter
  reports it as `kernel_stricter`). Nothing in the mutation table is ever
  rejected: denying is always possible, and the kernel is only ever
  stricter than Cedar here, never looser.
- **Over-denial (documented):** below a `FilePrefix` that does not end in
  `/` (the strict form of a legacy `File` rule, e.g. `FilePrefix::"/dev/null"`),
  paths with a `/` after the prefix but not right after it (`/dev/nullx/y`)
  may be denied where Cedar allows them. The prefix names a file, so such
  paths only exist under an equally named directory. The kernel is stricter
  there, never looser.
- The hard-link guard needs the source to be readable: a read-only open
  through the open index.

**Connect: symbolic.** For `NetworkConnect` each policy must reduce to a
constant or a disjunction of single `Host` atoms (no conjunction or negation
of two host constraints, no `unless` on a host). Forbids become deny rules,
permits allow rules; the kernel's deny-first first-match scan is then exactly
forbid-overrides-permit. An unconstrained permit is the default allow; an
unconstrained forbid denies everything (no allow rule survives). The default
is always written as explicit, so the loader's own guesses (an address-less
allow rule or `allow *` turning the default to allow) never apply.
`Host::"*:443"` compiles to an address-less rule on port 443.

**Sockets no address rule can see (#188).** A packet socket (`AF_PACKET`,
`AF_XDP`) bound with `bind()` and a raw IP socket (`SOCK_RAW`, e.g. with
`IP_HDRINCL`) send with `send()` and no destination address, so no
`NetworkConnect` request exists for them. SCTP (`IPPROTO_SCTP`, and
`SOCK_SEQPACKET` on an IP family, which is SCTP even with protocol 0) adds
peers past `socket_connect`: `sctp_connectx()` passes only
`security_sctp_bind_connect`, the `SCTP_DSTADDRV4`/`V6` address list of a
`sendmsg()` passes no LSM hook at all, and a peer advertises further
addresses in INIT-ACK and ASCONF. A per-address `lsm/sctp_bind_connect`
program would therefore still miss destinations, so these sockets are
decided once, at creation (`lsm_socket_create` on `socket_create`, in the
connect object): **denied with `EPERM`** (the error a missing `CAP_NET_RAW`
gives) **unless the policy restricts no destination**: the compiled connect default
is allow, there is no deny connect rule of any kind (address, port, hostname
or `*.zone`), and no `McpCall` forbid can apply (`PolicySet.ProxyRestricted`,
set by the compiler for a forbid that reaches `McpCall` with a resource
scope that can be an MCP entity; a packet socket can also bypass the
proxy). There is no Cedar action for them: a `permit` could only be all or
nothing, and the one policy shape under which they cannot reach anything
the policy forbids is already expressible. `TestKernelCompileUnaddressedSockets`
pins the verdict per policy shape, and `checkKernelParity` asserts on every
random set that the kernel allows them only where `cedar.Authorize` allows
every probed connection (hosts, IPv4, v4-mapped and IPv6 addresses, ports).
ICMP datagram sockets (`SOCK_DGRAM`, `IPPROTO_ICMP`/`ICMPV6`, which iputils
`ping` opens first) are ordinary addressed sockets: `sendto()` is decided by
the connect rules, with port 0 (`Host::"10.0.0.1"` permits ping to it,
`Host::"10.0.0.1:443"` does not). A run never starts without this kernel
gate (SECURITY-MODEL.md).

**Inherent divergence (documented, unchanged):** the kernel matches connects
by IP. Hostname rules are resolved to IPs when the policy loads and wildcards
are not loaded at all; the proxy (the engine) matches the name. A forbidden
host that shares an IP with a permitted one blocks that IP in the kernel.

**macOS** enforces the same tables. `lsm.MacTablesFor` runs the kernel
loaders' own compilation (the file-open index with its exact and prefix
entries per open mode, specificity and order; the mutation index; the exec
rules in precedence order; the connect rules with hostnames resolved at load
and the explicit default) and `macsync.CompileTables` sends it to the
extensions as `mac.policy.tables`, with leash's protected paths and ports.
The Swift matcher (`mac-leash/Shared/PolicyCore`) implements the four BPF
lookups over those tables and nothing else. `macsync`'s parity test compiles
random strict policies, decides them with a Go model of the Swift matcher and
compares with `cedar.Authorize` (2500 sets, ~800,000 decisions); the same
vectors are replayed against the Swift code by `swift test --package-path
mac-leash`. Differences that are macOS's own:

- Endpoint Security reports `/tmp`, `/etc` and `/var` as `/private/...`; the
  matcher maps them back to the short form, and a policy naming a path only
  reachable in the `/private` form fails to compile for macOS.
- Creating a regular file is decided as a write open of it (Linux sees the
  created file in `file_open`); creating any other object (directory, symlink,
  fifo) as a mutation; truncate, clonefile, copyfile and exchangedata as write
  opens. Linux does not gate symlink or fifo creation: macOS is stricter there.
- The content filter never sees loopback flows, so loopback connections are
  not decided by the connect table on macOS. Leash's own listeners refuse
  leashed clients instead (peer PID check).
- A flow that names its destination but not its address is allowed only when
  the table allows every address on its port.
- Packet, raw and SCTP sockets: the content filter sees TCP and UDP flows
  only; an unprivileged workload cannot open packet or raw sockets on macOS.

### 3.4 Tests

| What | Test | Result |
|---|---|---|
| Legacy rewrite == legacy semantics | `TestLegacyRewriteIsEquivalentToLegacySemantics` (lsm): random legacy files (file, exec, connect, MCP; principals, ignored conditions, `unless`-as-`when`, `Host::"*"`, `Net::*`, never-matching rules) and random requests; the legacy model over the legacy IR vs cedar.Authorize over the rewrite | 3000 files, 600,000 decisions, equal |
| Nesting | `TestLegacyRewriteNestingProperty`: alternating forbid/permit chains up to depth 6, shuffled, every open mode and exec | 2000 chains, 360,000 decisions, equal |
| Layers | `TestLegacyRewriteAcrossLayers`: file + runtime layer rewritten together vs the legacy Manager merge | 1000 pairs, 150,000 decisions, equal |
| Raw IR layers | `TestLegacyRewriteOfRawIRLayers` | 500 layers, 75,000 decisions, equal |
| Kernel == Cedar (files, exec) | `TestKernelCompileMatchesCedarForStrictPolicies`: random strict subset policies (exact `File` via `==` and `in`, `FilePrefix`, `Dir`; boolean combinations, actions, `unless`, `is`) through CompileKernel and the real loaders (`OpenLsm`/`ExecLsm`/`ConnectLsm.LoadPolicies`) and the BPF lookup models (the exec model reads the NUL-terminated path), with the mutation table (mkdir/unlink/rmdir/rename, longest-prefix model of the changed `check_mutation_policy`) and the hard-link guard | 3000 sets (none rejected), 960,000 decisions; equal, except mutations denied at warned exact paths and below loose `FilePrefix`es (never the reverse) |
| Kernel == Cedar (connect, IP) | `TestKernelCompileMatchesCedarForConnect` (also checks mutations and links) | 3000 sets, 720,000 decisions, equal |
| Packet/raw/SCTP sockets (#188) | `TestKernelCompileUnaddressedSockets` (verdict per policy shape); every `checkKernelParity` set: an allowed verdict implies `cedar.Authorize` allows every probed connection | never looser than Cedar |
| End to end | `TestKernelCompileOfRewrittenLegacyPolicies`: legacy → rewrite → kernel tables (open, exec, connect, mutation, link) vs cedar.Authorize; every rewritten legacy file must compile | 2000 files (13 with a warned exact-path over-denial), 640,000 decisions; equal, except the documented mutation over-denials |
| Legacy model == kernel | `TestLegacyModel*MatchesKernel*` pin the oracle to the loaders | 5000 sets each |
| Plugin decisions | `TestPluginDecisionsAreCedarAuthorize`, namespace rule, `@expires`, routing | |
| Unenforceable constraints (#164) | `TestLegacyRejectsUnenforceablePermits`, `TestLegacyRejectsNarrowedForbids`, `TestLegacyForbidWithDroppedConditionIsStricter`, `TestStrictMCPConditionsMustBeSupplied`, `TestPluginConditionsAreEvaluatedWithRequestContext`, `TestServerPluginConditionsSurviveTheUnenforceableCheck`; the random generators above flag such policies, assert the rewrite rejects exactly those that have an effect, and check equivalence on the rest | |

The oracle (`internal/lsm/legacy_model_test.go`) is test-only: it is the
#150 `Decider` matcher code, kept as the statement of the legacy semantics
and pinned to the kernel loaders. Mutation checks: disabling the exceptions,
the synthesized defaults, the equal-length rule, the directory-self parent,
the region pruning, the directory self entries, the split root or the
explicit connect default each makes these tests fail.

## 4. Legacy semantics and the preparser

### 4.1 Mode selection

**Strict Cedar is the default** (owner decision; contract 3, capability
`cedar-strict-default`). A file is legacy only when one of its policies
carries `@leash_semantics("legacy")`; it is then rewritten at load, with an
info log listing every forbid that gained exceptions and every dropped
construct. Every other file is strict: an unmarked one, or one marked
`@leash_semantics("cedar")` (accepted as an explicit strict marker). Mixing
both values fails the load. (Before contract 3 the default was the other way
round: a file was strict only when marked `"cedar"`.)

The marker is an **annotation**, not a comment: cedar-go keeps annotations in
the AST and in `MarshalCedar`, so the marker survives every path that parses
and re-emits policies (the policy API, the Control UI, runtime layers); the
parser drops comments. One marked policy makes the whole file legacy, so a
statement the policy API prepends to a legacy runtime layer is read as legacy
too; the statements it generates (`action in Action::"FileOpen"`,
`resource in File::/Dir::`, `resource == Host::`, MCP tool and server) read
the same in both dialects.

Every place that reads a policy decides the dialect the same way, through
`transpiler.DetectSemantics` in `cedar.CompileLayers`: the policy file and
its reloads (leashd, darwind), the runtime layer of the policy API and the
Control UI editor (Cedar text, `runtime.cedar`), the enforcer daemon's
session policy, and `leash policy lint`. Rules built in code (an IR layer
without Cedar source) are legacy by definition; an empty one (a cleared
runtime layer) adds nothing, not even legacy defaults. The rewrite output,
the policies `leash policy migrate` writes and the session text leashd sends
the enforcer daemon (`Compilation.StrictText`) carry no marker: they are
strict by default. macOS needs nothing of its own: the ES and NE extensions
enforce the kernel tables compiled from the merged strict set (macsync).

`leash policy lint` (and `POST /api/policies/validate`) warns with
`legacy_semantics_suspected` when an **unmarked** file decides differently
than its legacy reading: it compares the two on requests built from the
file's own entities and names an example, and it flags `unless` clauses and
MCP forbids without any MCP permit. A load that fails on an unmarked file
adds the migrate / mark-legacy hint to the error.

### 4.2 Algorithm

Legacy semantics are, by definition, those of the IR the legacy transpiler
produces (#138): each policy lowers to rules, and the matchers take the most
specific one. The rewrite keeps that lowering as the meaning of a legacy
policy:

1. Lower each legacy policy (in source order, all legacy layers together) with
   the legacy transpiler. Plugin-action policies are kept as written.
2. Expand every generic `FileOpen` rule into `FileOpenReadOnly` and
   `FileOpenReadWrite` (exactly the rules that apply to each request mode).
3. For each forbid rule F (action a, path f), its exceptions are the permits
   P of action a with `len(P) > len(f)` and P's path starting with f. These
   are exactly the permits that are both more specific than F and match a
   path F matches (a `Dir` self match is shorter than its rule, so it is
   covered). Equal length adds no exception: the forbid wins, as in #138.
4. Emit, per legacy policy, one strict policy per (effect, action set,
   exception set), with `when { resource in [...] }` and
   `unless { resource in [exceptions] }`. Connect rules become
   `resource in [Host::...]` lists; MCP forbids `resource in
   [MCP::Server...] && resource in [MCP::Tool...]`.
5. Add the global defaults legacy had: the MCP default permit, and a
   lowest-specificity file-open permit when any allow sits on `/`.

Correctness (also checked by the property tests): legacy allows a request iff
its most specific matching rule is an allow A. Then every matching forbid is
shorter than A (a tie goes to the forbid), so each has A as an exception and
none applies, while A's permit applies: Cedar allows. Legacy denies by a most
specific forbid F iff no longer matching permit exists, so F has no applicable
exception and Cedar denies. With no matching rule both fall to the same
default.

Nesting needs nothing special: `forbid /a`, `permit /a/b`, `forbid /a/b/c`,
`permit /a/b/c/d` becomes `forbid /a unless [/a/b, /a/b/c/d]`, `permit /a/b`,
`forbid /a/b/c unless [/a/b/c/d]`, `permit /a/b/c/d`.

Principals and conditions: legacy semantics ignore principal constraints and
every condition except a whole `resource in [...]` or `context.hostname`
`==`/`like` clause on built-in actions, and read `unless` as `when`. A
permit enforced that way grants more than it says (fail-open), so since #164
the rewrite **rejects** every permit that carries such a constraint and still
grants a file, exec or connect rule, naming the policy, its line and the
construct; a permit that grants nothing (an MCP permit, a policy whose
resources sat inside the ignored condition) is dropped with a note as before.
A forbid enforced without its constraint only forbids more (stricter): it is
emitted without it, with a note. A forbid that would be enforced on *fewer*
requests than written is rejected as well: one whose resources appear only
in an ignored condition or an `unless` (legacy would drop it, or forbid
exactly what it exempts), or an MCP forbid that names servers or tools inside
such a condition (the legacy MCP lowering scans the whole policy for
servers). The check reads the policy's AST, not the legacy parser's guesses,
so `context.path in [Dir::"/a/"]` or `principal in Group::"g"` (which the
legacy parser took for resources) count as ignored conditions. A strict file
that constrains the principal of a built-in policy fails the load.

### 4.3 Every legacy deviation

| # | Legacy behaviour | Strict form | |
|---|---|---|---|
| 1 | File/exec: the longest matching rule wins; a longer permit beats a shorter forbid | the forbid gains `unless { resource in P }` | equal length: forbid wins (#138) |
| 2 | Generic `FileOpen` rule applies to read-only and read-write opens | expanded to both actions; `Action::"FileOpen"` is their group | strict `action == Action::"FileOpen"` is rejected |
| 3 | Any allow rule on `/` (any mode) makes the file-open default allow for every mode | `@leash_rewrite("file-open-default-allow") permit (principal, action in [RO, RW], resource)` | |
| 4 | `File::"/x"` matches every path it byte-prefixes | `FilePrefix::"/x"` (strict `File::` is exact) | kernel semantics |
| 5 | `Dir::"/x"` is `/x/`: the subtree and, for opens, `/x` itself | the hierarchy (`Dir::"/x"` = `Dir::"/x/"`; self for opens) | exec has no self match |
| 6 | `resource == E` in the head means `in E` | `resource in E` (with E's legacy meaning: `FilePrefix` for a file) | strict `==` is exact |
| 7 | The head resource and `resource in [...]` conditions are a union | one resource list | |
| 8 | `unless { resource in [...] }` is read as `when` | forbid with a resource in its head: `when`, with a note (stricter). Permit: **rejected** (#164) | **behaviour change:** a permit granted what its `unless` excludes; a forbid whose only resources are in the `unless` forbade exactly what it exempts, and is rejected too |
| 9 | Principal constraints ignored | forbid: dropped, with a note (stricter). Permit granting a file, exec or connect rule: **rejected** (#164) | **behaviour change**; rejected in strict |
| 10 | Conditions other than a whole `resource in` or `context.hostname` clause ignored | forbid: dropped, with a note (stricter), unless its resources are only in the ignored condition, then **rejected**. Permit granting a rule: **rejected** (#164) | **behaviour change**: the permit was enforced unconditionally (fail-open) |
| 11 | `context.hostname ==`/`like` names the host | `resource in Host::"..."` | |
| 12 | A policy that lowers to no rule (unsupported action, no resource, unconstrained action) is skipped with a warning | dropped, with a note | in strict an unconstrained action applies to every built-in action |
| 13 | MCP is default-allow; MCP permits are no-ops | `@leash_rewrite("mcp-default-allow") permit (principal, action == Action::"McpCall", resource)`; legacy MCP permits dropped, with a note | |
| 14 | An MCP server forbid also forbids connections to the server host | an explicit `forbid ... NetworkConnect ... resource in Host::"server"` | |
| 15 | MCP server/tool normalization | the hierarchy normalizes requests; emitted IDs are normalized | |
| 16 | `Host::"*"` is the connect default; `forbid` beats `permit` | forbid dropped (strict default deny); permit becomes an unconstrained connect permit, dropped with a note if any forbid `Host::"*"` exists | |
| 17 | `Host::"0.0.0.0"` (no address, no port) matches every connection; `0.0.0.0:p` any host on port p | unconstrained / `Host::"*:p"` | |
| 18 | `Net::DnsZone::"z"` is `*.z` (apex excluded); `Net::Hostname`, `Net::Endpoint` are hosts | canonical `Host::` entities | |
| 19 | Hostnames compare case-insensitively, a trailing dot ignored | the hierarchy normalizes; emitted IDs lowercased | |
| 20 | Proxy wildcards lacked the label boundary (`*.example.com` matched `evilexample.com`) | **not reproduced** | a bug, fixed for the current proxy in `fix/proxy-wildcard-label-boundary`; the oracle includes the fix |
| 21 | An IP literal sent as the hostname was matched against hostname wildcards | **not reproduced**: an IP literal is an address | |
| 22 | Rules that never match (relative paths, host names with a trailing dot, spaces or a bare `*.`) | dropped, with a note | strict rejects such entities |
| 23 | Exec argument rules (line format only) | an allow with arguments never matched: dropped; a deny with arguments: rejected | no Cedar source produces them |
| 24 | Kernel connect quirks: an address-less allow rule or `allow *:443` set the kernel default to allow everything; `forbid *:22` was dropped by the kernel (DNS) | the kernel compiler writes an explicit default and `*:p` as a port rule | the kernel now matches Cedar (stricter) |
| 25 | Plugin actions already had Cedar semantics | kept as written | namespace rule |
| 26 | Kernel matches connects by IP, the proxy by name | unchanged | inherent |
| 27 | macOS ES rule order (file before directory, deny first), open mode ignored, network rules without ports and with suffix-matched names | the extensions enforce the kernel tables (§3.3) | fixed: macOS == kernel, parity-tested |
| 28 | Layer merge: a raw-IR runtime layer with an *explicit* default allow overrode a file `forbid Host::"*"` | union: a forbid default wins | Cedar layers cannot express an explicit allow default; only IR built in code could |
| 29 | Directory mutations were allowed only by read-write directory allow rules (generic `FileOpen` allows did not count), denied by any covering generic forbid, deny first | Cedar: `FileOpenReadWrite` on the path and on a new entry of its directory, compiled into the mutation table | the table is now longest-prefix (one BPF function); generic `FileOpen` permits now allow mutations; a permit nested in a forbid now allows mutations below it |
| 30 | Packet, raw IP and SCTP sockets got the connect default per address-bearing call; a bound packet or raw socket and SCTP `connectx` passed unchecked (#188) | no Cedar form: denied at `socket_create` unless the policy restricts no destination (§3.3) | the kernel is stricter: allowed only where Cedar allows every connection |

### 4.4 What cannot be made equivalent

- **#20 and #21** are deliberately not reproduced (bugs).
- **#26**: the kernel cannot match names; documented.
- **#28**: only reachable from IR built in code, not from Cedar.
- **#30**: packet, raw and SCTP sockets have no destination to decide; the
  kernel allows them only where Cedar allows every connection.
- **#29**: the mutation table has no exact allow; a mutation Cedar allows at
  one single path that the table denies around it is denied by the kernel,
  with a load-time warning naming the policy and path (§3.3). Below a loose
  `FilePrefix` the kernel may deny mutations Cedar allows (documented
  over-denial). The kernel is never looser than Cedar.
- **Exec argument denies** (line format): no Cedar form; such layers fail.
- **#8, #9, #10 on a permit** (and on a forbid they would narrow) are
  deliberately not reproduced since #164: the legacy behaviour allowed more
  than the policy said. Such files fail to load until the constraint is
  removed or the file is made strict.

## 5. Migration

- **A legacy file must say so, or be migrated.** Since contract 3 an
  unmarked file is strict Cedar. Mark a legacy file
  `@leash_semantics("legacy")` and it is rewritten at load, with the info log
  describing every change; decisions are unchanged except #20, #21, #24 and
  #28. A file with a permit whose principal constraint, condition or
  `unless` legacy semantics ignored (#8, #9, #10) no longer loads (#164);
  `leash policy migrate` and the linter (`unenforceable_condition`) report
  the same error.
- `leash policy migrate <file>` reads the file as legacy (unless it is marked
  `@leash_semantics("cedar")`: nothing to do) and prints plain strict Cedar
  without a marker, with a header listing the exceptions and dropped
  constructs; `--write` replaces the file atomically. The output is checked
  like a load (the engine builds, the kernel compiles); its header makes a
  second migrate a no-op.
- Every policy Leash ships was migrated this way and is checked to decide
  like its legacy original (`TestMigratedBuiltInPoliciesKeepTheirDecisions`:
  the built-in bootstrap policy, the release-gate Walk policy
  `e2e/testdata/walk33-combined.cedar`, the CEDAR.md example; the originals
  are kept as `@leash_semantics("legacy")` fixtures in
  `internal/lsm/testdata`).
- After migrating, write strict Cedar: `resource == File::"/x"` for one file,
  `resource in Dir::"/x/"` for a tree, `FilePrefix::"..."` for a byte
  prefix (what a legacy `File` rule was), `forbid`
  overrides `permit` (add `unless` for an exception), MCP and connect need
  explicit permits, `action in Action::"FileOpen"` for both open modes.
- **Walk** (and any provisioner) that generates unmarked legacy-style
  policies must, against a leash advertising `cedar-strict-default`, either
  emit strict Cedar or mark its output `@leash_semantics("legacy")`.

## 6. Plugin actions in Cedar

### 6.1 Entity types and namespaces

- **Principal:** `Plugin::"<id>"`, set by Leash from the authenticated
  socket, never taken from the request. `<id>` is the `--inject-service`
  `id=` (default: the plugin binary's base name).
- **Actions:** `<Namespace>::Action::"<Verb>"`, for example
  `Secret::Action::"Read"`. The root `Action::` namespace is Leash's.
- **Resources:** `<Namespace>::<Type>::"<id>"` by convention, for example
  `Secret::Item::"gemini"`. No hierarchy: `in E` is `== E`.
- **Context:** whatever the plugin sends (§7.2).

### 6.2 What policy authors can write

Any Cedar: plugin policies are evaluated by cedar-go, so conditions, `like`,
`has`, sets, `if-then-else` and extension functions all work, with Cedar's
semantics (any applicable forbid denies; otherwise any applicable permit
allows; otherwise deny; a condition that errors makes its policy not apply).

```cedar
// Static per-secret grant (secret broker)
permit (principal == Plugin::"secretbroker",
        action == Secret::Action::"Read",
        resource == Secret::Item::"gemini");

// Time-bound grant
@id("gemini-until-noon")
@expires("2026-10-16T12:00:00Z")
permit (principal, action == Secret::Action::"Read", resource == Secret::Item::"gemini");

// #113: retrieval only, one repo and revision, mutation never
permit (principal == Plugin::"code-indexer",
        action == CodeIndex::Action::"Retrieve",
        resource == CodeIndex::Repo::"github.com/acme/app")
when { context.revision == "abc123" && ["search", "symbols", "bundle"].contains(context.tool) };
forbid (principal, action == CodeIndex::Action::"Retrieve", resource)
when { context has tool && context.tool like "*index*" };
```

Write `context has x && ...` in forbids: under Cedar semantics a forbid whose
attribute is missing does not apply. A policy only decides plugin requests of
the namespaces its action scope names (§3.2).

Built-in actions may be queried too, by plugins granted the `Action`
namespace (§7.4): the request goes through the same engine methods the proxy
uses, with the workload as principal, so a stdio MCP gate (#113) can ask
`Action::"McpCall"` on `MCP::Tool::"<tool>"` with `context.server` and get the
HTTP proxy's answer.

## 7. The authorization socket

### 7.1 Transport and authentication

- **One private Unix socket per plugin**, served by leashd, the process that
  holds the live policy. The runner creates a per-run directory (root-owned,
  0711) with one subdirectory per authz-enabled plugin (owned by the plugin's
  uid, 0700). leashd binds `<dir>/<id>/authz.sock` there, chowns it to the
  plugin uid and sets it to 0600. The path reaches the plugin as
  `LEASH_AUTHZ_SOCKET` and `LEASH_AUTHZ_PLUGIN_ID` in its environment.
- **Identity comes from the socket, not the request.** leashd knows which
  plugin owns each listener, so the principal is `Plugin::"<id>"` for every
  request on that listener. A plugin cannot claim to be another plugin.
- **Peer credentials (defence in depth).** On Linux, `SO_PEERCRED` uid must be
  the plugin's uid (or 0). On macOS, `LOCAL_PEERCRED` is checked the same way.
- **Workload exclusion.** The workload runs as the same uid as the plugin, so a
  uid check alone cannot tell them apart:
  - Container backends: the authz directory is bind-mounted only into the
    leashd container, never into the target container.
  - Native: leashd sees host pids, so it rejects any peer whose
    `/proc/<pid>/cgroup` is inside the box cgroup. The workload cannot connect
    even if it guesses the path. `authz=` requires that cgroup: without one
    leashd refuses to serve the authz sockets and fails to start (fail
    closed), since it could not tell the workload from the plugin.
- **Why not a shared socket.** A shared socket would need in-band identity
  (tokens) and give no per-plugin rate limiting or revocation. Passing a
  pre-connected fd to the plugin was also considered. The `runuser` spawn path
  makes fd inheritance fragile, and the plugin could not reconnect after a
  leashd restart.

### 7.2 Wire protocol (v1)

Newline-delimited JSON over the stream socket. One request per line; responses
come back in order. The Go types live in `pkg/authz` and are shared by the
server and the client.

```json
{"v":1,"id":"42","action":{"type":"Secret::Action","id":"Read"},
 "resource":{"type":"Secret::Item","id":"gemini"},
 "context":{"agent":"antigravity","attempt":2,"approved":true,"tags":["a"],
            "owner":{"__entity":{"type":"User","id":"sixto"}}}}
```

```json
{"v":1,"id":"42","decision":"allow","reason":"matched_permit",
 "policies":["gemini-until-noon"],"principal":{"type":"Plugin","id":"secretbroker"},
 "generation":7}
```

- `decision` is `allow` or `deny`. There is no third value. Anything other than
  `allow` (including a missing or unknown value) is a deny.
- `reason` is one of `matched_permit`, `matched_forbid`, `default_allow`
  (reserved: strict Cedar has no default allow), `default_deny`,
  `unsupported_action`, `invalid_request`, `no_policy`,
  `namespace_not_granted`, `rate_limited`, `unsupported_version`,
  `peer_rejected` (audit only: the connection is refused). The list is
  append-only. `approval_required` is reserved (§8).
- `policies` holds the deciding policy IDs (`@id`, else the legacy source
  `<file>:<line>` of a rewritten policy, else the Cedar ID), for plugin and
  built-in actions alike. `rule` is kept in the schema and left empty.
  `error` holds a human-readable detail for invalid requests.
- `generation` is the policy generation the decision was taken against
  (monotonic per leashd process). Use it for audit and correlation, not for
  caching.
- Context mapping: a JSON string is a Cedar String; an integer is a Long
  (fractions are rejected); a bool is a Bool; an array of those is a Set;
  `{"__entity":{"type","id"}}` is an entity (Cedar's JSON convention). Any
  other object, and `null`, is rejected.
- Versioning: `v` must be `1`. A different version gets a deny with
  `unsupported_version` and the server's `v`. Unknown fields are ignored, so
  additions stay compatible. A breaking change bumps `v`, and the server can
  serve both versions during a transition.

### 7.3 Fail-closed semantics

- **Client (`pkg/authz`):** any connect or transport error, timeout (2s by
  default), malformed response, id mismatch or unsupported version returns a
  deny along with the error. The only way to get `Allowed() == true` is a
  well-formed `allow` from the server.
- **Server:** it answers deny for every malformed request and keeps the
  connection. Before the first policy loads, everything is denied
  (`no_policy`). If leashd dies, the socket goes away and the client fails
  closed.
- **Spawn:** a plugin spawned with `authz=` gets the socket env only when the
  authz service is configured. If leashd cannot bind the socket, it logs the
  failure, and every query fails closed in the client.

### 7.4 Namespace grants

The `--inject-service` spec takes `authz=<Ns>[+<Ns>...]`, for example
`authz=Secret` or `authz=CodeIndex+Action`. The `+` separator keeps nested
namespaces such as `Walk::Secret` unambiguous. A request for an action outside
the granted namespaces is denied with `namespace_not_granted`, before
evaluation. Leash's own actions are queryable only with an explicit `Action`
grant. When #18 lands, the plugin manifest will declare its namespaces (and
the action and resource types it will ask about), and leash will grant the
intersection of the manifest and the operator's spec.

### 7.5 Policy hot-reload consistency

`policy.Manager` builds **one** engine per policy change and publishes it,
with a new generation, to the proxy and the authz server under one lock
(`policy.Decisions`). Each request is evaluated against a single snapshot, so
no decision sees half of a reload, and the proxy and plugins switch to a new
policy at the same instant. A policy that fails to rewrite, build or compile
for the kernel leaves the previous engine and kernel tables in place.

### 7.6 Limits

| Limit | Value |
|---|---|
| Request line | 64 KiB. A longer line gets a deny, and the connection is closed. |
| Context | 64 keys; strings up to 4 KiB; sets up to 256 elements, one level deep |
| Rate | 200 requests/s per plugin, burst 400. Over the limit: deny with `rate_limited`; the connection stays open. |
| Connections | 16 concurrent per plugin. Extra connections are refused. |
| Idle timeout | 2 minutes |

### 7.7 Audit

Every decision is written to leash's event log, next to the file, exec and
network decisions, in the same logfmt style:

```
time=… event=authz.decision plugin=secretbroker action=Secret::Action::"Read" resource=Secret::Item::"gemini" decision=allow reason=matched_permit policies="gemini-until-noon" generation=7 context_keys="agent,attempt"
```

Context **values** are not logged. They can carry secrets or source fragments,
and #113 forbids logging retrieved content. Only the keys are recorded.

### 7.8 Capability

`leash version --json` advertises `authz-socket`, appended at the end of the
capability list to keep the order deterministic. It means "this leash accepts
`--inject-service ...,authz=...` and serves protocol v1". Callers such as Walk
should test for it before relying on the socket.

### 7.9 Go client (`pkg/authz`)

The package uses only the standard library, so Walk can import it without
pulling in leash internals.

```go
c, err := authz.NewFromEnv()        // LEASH_AUTHZ_SOCKET
d, err := c.Check(ctx, authz.Request{
    Action:   authz.UID("Secret::Action", "Read"),
    Resource: authz.UID("Secret::Item", "gemini"),
    Context:  map[string]any{"agent": "antigravity"},
})
if d.Allowed() { ... }               // false on any error
```

## 8. How the use cases map

| Use case | How |
|---|---|
| Secret broker, static | Walk writes one `permit` per agent `Secrets` entry, or a `Secret::Item` permit set, and spawns the broker with `authz=Secret`. The broker calls `Check` per `SearchItems`/`GetSecret` instead of using its allow-list. |
| Secret broker, time-bound | `@expires` on the permit. It is added through the existing Cedar policy API (`POST /api/policies`) or by editing the file; the hot reload swaps the engine. |
| Secret broker, approved per request | Future. A permit annotated `@approval("prompt")` decides `deny` with `approval_required`. leashd's Control UI prompts. Approval adds a short `@expires` permit (or a one-shot grant keyed by request id), and the plugin retries. Only the reason is reserved here; no prompt ships. |
| #113 code-indexer gate | `CodeIndex::Action::"Retrieve"` per call, with `context.revision` and `context.tool`, plus mutation forbids. If the channel is MCP over stdio, the gate can query the built-in `McpCall` instead, so HTTP and stdio MCP share one policy. |
| #18 manifest actions | The manifest declares namespaces, actions and resource types. Leash grants them (§7.4) and lints policies against them. |
| Audit | `event=authz.decision` in the event log and the Control UI stream. |

## 9. Delivery

1. **Engine, preparser, kernel compiler** (this document, `internal/engine`,
   `transpiler.RewriteLegacy`, `transpiler.CompileKernel`, the
   mode-aware linter, `leash policy migrate`, the oracle, equivalence and
   parity tests).
2. **Adapters:** the policy pipeline (`cedar.Compilation`, `policy.Manager`
   layers as Cedar, joint rewrite of legacy layers, kernel tables from the
   strict set), the proxy and MCP on the engine, `policy.Decisions`, leashd
   and darwind wiring. The wildcard label-boundary fix for the current proxy
   is its own PR (`fix/proxy-wildcard-label-boundary`).
3. **Socket service:** `internal/authz` server on the engine, `pkg/authz`
   client, leashd wiring, the runner `authz=` key, the capability.

Follow-ups: Walk emits strict policies; the approval flow; #18 manifest ingestion; a
real-kernel run of the parity cases.
