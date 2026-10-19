# Leash Cedar Policy Reference (Consolidated)

> [!WARNING]
> Because Leash relies on enforcement mechanisms (e.g. eBPF) which cannot evaluate Cedar policy, we translate Cedar intents into the available enforcement techniques. At policy authoring and validation time, we lint and validate the Cedar statements to ensure only those statements which are enforceable are saved and applied. The translations are simple, but may result in some intuition violations for anyone familiar with Cedar's authorization model.  


> [!NOTE]
> **Policy files are strict Cedar by default** (contract 3, capability `cedar-strict-default`): any applicable `forbid` denies, otherwise any applicable `permit` allows, otherwise the request is denied. Every userspace decision (the proxy's connect check, MCP tools/call, the plugin authorization socket) is made by Cedar's own evaluator (cedar-go), and the kernel enforces tables compiled from the same policies (#142). Leash's older **legacy dialect** (the most specific file rule wins, MCP allowed by default, `File::` as a path prefix) is an explicit opt-in: mark the file `@leash_semantics("legacy")` and it is rewritten at load to equivalent strict Cedar. `leash policy migrate <file>` converts a legacy file for good, and `leash policy lint <file>` warns when an unmarked file looks written for the legacy dialect. See [Dialects](#dialects-strict-cedar-default-and-legacy) and `docs/design/AUTHZ-SERVICE.md`.

Leash loads the initial access‑control policy from `/cfg/leash.cedar`. At startup
the daemon validates Cedar, compiles it to kernel tables in memory, and loads them
into the eBPF LSM programs; the HTTP MITM proxy evaluates the same policies with Cedar.

This is the single, authoritative reference for authoring Cedar policies in Leash.
All examples use Cedar’s standard Action entity with PascalCase identifiers. No
other action namespace is accepted in documentation or generated output.

## Quick Start

Leash starts with a permissive Cedar policy so you can experiment immediately. Customize enforcement either through the Control UI (`http://localhost:18080/policies`) or the HTTP API:

```bash
curl -sS -X POST \
  -H 'Content-Type: text/plain' \
  --data-binary @./my-policy-file.cedar \
  http://localhost:18080/api/policies
```

## Autocomplete Support

The Control UI ships with a Monaco-based Cedar editor that consumes the daemon’s completion API. Suggestions are context-aware and cover keywords, actions, resources, MCP identifiers, HTTP rewrite snippets, and contextual keys such as `context.header`.

### HTTP API

The daemon exposes `POST /api/policies/complete`. Requests include the full Cedar buffer and the current cursor location:

```bash
curl -sS \
  -H 'Content-Type: application/json' \
  -d '{"cedar":"permit (principal, action == , resource);","cursor":{"line":1,"column":33}}' \
  http://127.0.0.1:18080/api/policies/complete | jq
```

Example response excerpt:

```json
{
  "items": [
    {
      "label": "Action::\"FileOpen\"",
      "kind": "action",
      "insertText": "Action::\"FileOpen\"",
      "detail": "Allow reading or writing files (per v1 semantics)",
      "documentation": "Maps to LSM file open rules.",
      "range": {
        "start": {"line": 1, "column": 29},
        "end":   {"line": 1, "column": 33}
      }
    }
  ]
}
```

The completion engine blends static catalogs with runtime hints:

- Active policy resources from the manager snapshot (files, directories, hosts, MCP servers/tools, HTTP headers).
- Recent hostnames and header names observed by the websocket event ring.
- MCP servers and tools captured by the proxy observer.

The API always returns `200 OK` with a list of items; malformed Cedar, partial statements, and comment contexts yield empty lists rather than errors.

### Control UI Behaviour

- Syntax highlighting, bracket handling, and snippets are powered by Monaco.
- Suggestions auto-update as the caret moves; Tab/Enter commits items, and snippets include tab stops.
- Validation markers use `/api/policies/validate` and surface lint errors inline.
- The UI displays short help text for the top-ranked suggestion beneath the editor.

## Statement Anatomy

Every policy statement grants (`permit`) or denies (`forbid`) a combination of
action + resource. Optional `when` clauses narrow the match using contextual
conditions.

```cedar
permit (
    principal,
    action in Action::"FileOpen",
    resource
) when {
    resource in [ Dir::"/workspace/" ]
};
```

Key elements:

- **effect** – `permit` or `forbid`.
- **action** – a Cedar `Action::"PascalCase"` identifier such as `FileOpen`, `ProcessExec`, `NetworkConnect`, or `HttpRewrite`. `Action::"FileOpen"` is the group of the two open modes: write `action in Action::"FileOpen"` (`action == Action::"FileOpen"` matches no request and is rejected).
- **resource** – entity describing what is touched (e.g. `Dir::"/path/"`, `File::"/file"`,
  `FilePrefix::"/bin/rm"`, `Host::"example.com"`). Match files and directories with
  `resource in ...`: `File::"/p"` is exactly the path `/p`, `Dir::"/d/"` the tree below `/d`
  (and `/d` itself for opens), `FilePrefix::"/q"` every path those bytes prefix.
- **conditions** – optional `when { ... }` block that constrains matches. Leash
  uses it primarily for HTTP rewrite header/value matching.

Statement order does not matter. Every action is plain Cedar: any applicable
`forbid` denies, otherwise any applicable `permit` allows, otherwise deny. A
`forbid` is not overridden by a more specific `permit`; write the exception
on the `forbid` (`unless { resource in [ ... ] }`).

### Supported Actions and Resources

| Action                            | Typical Resources                                | Notes |
| --------------------------------- | ------------------------------------------------ | ----- |
| `Action::"FileOpen"` / `Action::"FileOpenReadOnly"` / `Action::"FileOpenReadWrite"` | `Dir::"/path/"`, `File::"/path"` | Directories must end with `/` to include contents. |
| `Action::"ProcessExec"`          | `Dir::"/path/"`, `File::"/path"`                    | Path‑only matching; argument filtering not yet available. |
| `Action::"NetworkConnect"`       | `Host::"example.com"`, `Host::"*.domain"`, `Host::"ip:port"` | Wildcard hosts support a leading `*.` only. Ports optional. |
| `Action::"HttpRewrite"`          | `Host::"example.com"`                               | Requires `context.header` and `context.value`. |
| `Action::"McpCall"`              | `MCP::Server::"host"`, `MCP::Tool::"tool-name"`     | Default deny: MCP calls need a `permit`. |

### Plugin Actions

Actions outside the root `Action::` namespace (for example `Secret::Action::"Read"`) belong to injected plugins, which ask Leash for decisions over the authorization socket. They are evaluated by cedar-go itself, with Cedar semantics (forbid overrides permit, default deny) and the full Cedar language, against only the policies whose action scope names their namespace: a policy with an unconstrained `action` never decides a plugin action. `@id` names a policy in decisions; `@expires("<RFC 3339>")` makes it stop applying at that instant. See `docs/design/AUTHZ-SERVICE.md`.

### Dialects: strict Cedar (default) and legacy

A policy file without a `@leash_semantics` marker is plain Cedar over Leash's entity hierarchy (see `docs/design/AUTHZ-SERVICE.md` §3): `File::"/p"` is exactly one path, `Dir::"/d/"` a tree (and the directory itself for opens), `FilePrefix::"/q"` every path those bytes prefix, `Host::"*.zone"` every name in the zone, `Host::"*"` every host. `@leash_semantics("cedar")` marks the same thing explicitly.

`@leash_semantics("legacy")` (on any policy of the file) selects Leash's older dialect, where the most specific file or exec rule wins (a longer `permit` beat a shorter `forbid`), `File::"/p"` is a byte prefix, MCP calls are allowed unless forbidden (MCP permits are no-ops), `Host::"*"` is the connect default, and `unless` was read as `when`. A legacy file is rewritten to equivalent strict Cedar at load, and the daemon logs every `forbid` that gained an exception. Mixing both markers in one file is an error. A policy added through the policy API or the Control UI joins the layer it is added to and is read in that layer's dialect; the generated statements read the same in both.

**Migrating.** Until contract 3, an unmarked file was read as legacy. Such a file now means something else, and may fail to load (strict Cedar rejects `action == Action::"FileOpen"`, a principal constraint on a built-in action, or a `resource ==` on a directory). Either:

- `leash policy migrate <file> [--write]`: reads the file in the legacy dialect (unless it is marked `@leash_semantics("cedar")`) and prints plain strict Cedar with the same decisions, without a marker: a `forbid` that a more specific `permit` used to override gains an `unless { resource in ... }` exception, a `File::` rule becomes `FilePrefix::`, and the MCP and connect defaults become explicit policies. The output starts with a `// Migrated from legacy ...` header, so migrating it again is a no-op.
- or keep the old meaning by marking the file `@leash_semantics("legacy")`.

`leash policy lint <file>` (and the Control UI's validation) warns with `legacy_semantics_suspected` when an unmarked file decides differently than it would in the legacy dialect (for example a `File::` rule that relied on prefix matching, a `permit` nested under a `forbid`, an `unless`, or MCP forbids without any MCP permit), with an example request. Mark the file `@leash_semantics("cedar")` once you have checked it is meant as strict Cedar.

### Action→IR Mapping

Leash IR and logs use stable operation strings. Actions map as follows:

- `Action::"FileOpen"` → `file.open`
- `Action::"FileOpenReadOnly"` → `file.open:ro`
- `Action::"FileOpenReadWrite"` → `file.open:rw`
- `Action::"ProcessExec"` → `proc.exec`
- `Action::"NetworkConnect"` → `net.send`
- `Action::"HttpRewrite"` → `http.rewrite`
- `Action::"McpCall"` → `mcp.*` (MCP policy rules)

Notes:
- Directory resources must end with `/`. The transpiler normalises this; the linter warns when missing.
- `FileOpen` file and directory resource paths may contain at most 255 bytes (a directory's trailing `/` counts); parsers and loaders reject a longer individual rule. The kernel compares every byte of every accepted rule of the tables compiled from the strict policy (the compiler adds the entries that make longest-match equal Cedar's forbid-overrides-permit; see AUTHZ-SERVICE.md §3.3). The hard-link guard (judged as a read of the source) and the directory-mutation hooks (`mkdir`, `unlink`, `rmdir`, `rename`, and `mknod` for every other new name, #204) use the same full-length rules. A runtime path longer than 255 bytes cannot be matched and is denied.
- `ProcessExec` resource paths are still matched by the legacy 64-byte kernel matcher (at most 64 exec rules); the exec loader rejects a longer rule or a larger rule set instead of skipping it.
- `leash version --json` advertises both limits as `policyLimits.filePathBytes` / `policyLimits.execPathBytes` (capability `policy-path-limits`).
- CIDR ranges are not supported in policies (IPv6 literals are, #182).
- Hostname rules require the Leash proxy for hostname enforcement (kernel enforces IP only).
- `NetworkConnect` and `McpCall`, like every action, have no specificity order: any matching `forbid` wins over every matching `permit`. Connections are denied unless permitted, so a policy that only permits `Host::"api.example.com"` allows only that host; `Host::"*"` is every host (`forbid ... Host::"*"` denies every connection, whatever is permitted).
- The kernel enforces hostname rules on the IPs they resolve to. If a forbidden host and a permitted host share an IP (common behind a CDN), the kernel denies that IP, so the permitted host is blocked too. Use the proxy's hostname rules, not a hostname `forbid`, for hosts that share an IP with permitted ones.

## File Access Examples

Permit read/write access under `/var/app/` but deny writes to `/var/app/secrets/`:

```cedar
permit (
    principal,
    action in [Action::"FileOpen", Action::"FileOpenReadOnly", Action::"FileOpenReadWrite"],
    resource
) when {
  resource in [ Dir::"/var/app/" ]
};

forbid (
    principal,
    action == Action::"FileOpenReadWrite",
    resource
) when {
  resource in [ Dir::"/var/app/secrets/" ]
};
```

Read-only access to `/etc` and `/usr/share`:

```cedar
permit (
    principal,
    action in [Action::"FileOpen", Action::"FileOpenReadOnly"],
    resource
) when {
  resource in [ Dir::"/etc/" , Dir::"/usr/share/" ]
};
```

## Process Execution Examples

Allow tools from standard locations while forbidding a specific binary:

```cedar
permit (
    principal,
    action == Action::"ProcessExec",
    resource
) when {
  resource in [ Dir::"/bin/", Dir::"/usr/bin/", Dir::"/usr/local/bin/" ]
};

forbid (
    principal,
    action == Action::"ProcessExec",
    resource
) when {
    resource in [ File::"/usr/bin/nmap" ]
};
```

Currently Cedar policies match by executable path only; argument-level filtering
still requires IR-era deny rules and is on the roadmap for a future Cedar
extension.

## Network Connectivity Examples

Permit access to trusted APIs and block social media:

```cedar
permit (
    principal,
    action == Action::"NetworkConnect",
    resource
) when {
  resource in [ Host::"api.internal" , Host::"*.corp.example" ]
};

forbid (
    principal,
    action == Action::"NetworkConnect",
    resource
) when {
    resource in [ Host::"*.facebook.com" , Host::"*.instagram.com" ]
};
```

Permit database connections to an explicit host:port:

```cedar
permit (
    principal,
    action == Action::"NetworkConnect",
    resource
) when {
    resource in [ Host::"db.internal:5432" ]
};
```

## HTTP Rewrite Example

Leash can inject headers via the MITM proxy when `Action::"HttpRewrite"` is
used with contextual conditions:

```cedar
permit (
    principal,
    action == Action::"HttpRewrite",
    resource == Host::"api.example.com"
) when {
    context.header == "Authorization" &&
    context.value  == "Bearer prod-secret"
};
```

Each matching request to `api.example.com` receives the specified header and value before being forwarded upstream.

## MCP (Model Context Protocol) Examples

Leash monitors and enforces policies on MCP tool calls made by AI agents. MCP
policies use `Action::"McpCall"` with `MCP::Server` and `MCP::Tool` resources.

### Enforcement

- **Default deny**: an MCP call is allowed only by a `permit`, and any matching `forbid` denies it. To allow MCP in general and block a few tools, add `permit (principal, action == Action::"McpCall", resource);` next to the forbids.
- **Server-level denies**: a `forbid` on an `MCP::Server` denies its tool calls in the proxy. To block all network traffic to that host as well, also forbid `NetworkConnect` on `Host::"<server>"` (the legacy dialect did that implicitly).
- **Tool-specific denies**: the proxy enforces tool-level access control on `MCP::Tool` (with or without an `MCP::Server`).

### Block All Access to an MCP Server

Prevent any MCP communication with a specific server:

```cedar
forbid (
    principal,
    action == Action::"McpCall",
    resource
) when {
    resource in [ MCP::Server::"mcp.untrusted.com" ]
};
```

The proxy denies every tool call to that server. (Calls to other servers still need a `permit`.)

### Block a Specific Tool on a Server

Deny access to a specific MCP tool while allowing others:

```cedar
permit (principal, action == Action::"McpCall", resource);

forbid (
    principal,
    action == Action::"McpCall",
    resource == MCP::Tool::"resolve-library-id"
) when {
    resource in [ MCP::Server::"mcp.context7.com" ]
};
```

The proxy will allow other tools on `mcp.context7.com` but deny calls to `resolve-library-id`.

### Permit a Tool

Allow one tool on one server (every other MCP call stays denied):

```cedar
permit (
    principal,
    action == Action::"McpCall",
    resource == MCP::Tool::"safe-search"
) when {
    resource in [ MCP::Server::"mcp.internal" ]
};
```

In the legacy dialect MCP permits were no-ops (MCP was allowed by default); in strict Cedar they are the only way to allow a call.

## Example Policy File

A small end-to-end policy might look like:

```cedar
// Allow basic file access while protecting secrets
permit (principal, action in Action::"FileOpen", resource)
when { resource in [ Dir::"/workspace/" ] };

forbid (principal, action == Action::"FileOpenReadWrite", resource)
when { resource in [ Dir::"/workspace/secrets/" ] };

// Allow execution of trusted tools, but not rm (nor rmdir: a byte prefix)
permit (principal, action == Action::"ProcessExec", resource)
when { resource in [ Dir::"/bin/", Dir::"/usr/bin/" ] };

forbid (principal, action == Action::"ProcessExec", resource)
when { resource in [ FilePrefix::"/bin/rm" ] };

// Network policy
permit (principal, action == Action::"NetworkConnect", resource)
when { resource in [ Host::"api.internal", Host::"db.internal:5432" ] };

forbid (principal, action == Action::"NetworkConnect", resource)
when { resource in [ Host::"*.facebook.com", Host::"mcp.example.com" ] };

// MCP tool access control: every call is allowed except execute-shell on
// mcp.example.com (strict Cedar denies MCP calls no policy permits)
permit (principal, action == Action::"McpCall", resource);

forbid (principal, action == Action::"McpCall", resource == MCP::Tool::"execute-shell")
when { resource in [ MCP::Server::"mcp.example.com" ] };

// Inject a header for internal API calls
permit (principal, action == Action::"HttpRewrite", resource == Host::"api.internal")
when {
    context.header == "X-Leash-Auth" &&
    context.value  == "service-token"
};
```

## Validation and Tooling

The daemon validates Cedar at startup and whenever policies change. Invalid policies
return structured errors with file, line, column, snippet, and a suggested fix. Lint policies using the REST API:

```bash
curl -fsS -X POST localhost:18080/api/policies/validate \
  -H 'Content-Type: application/json' \
  --data '{"cedar": "permit (principal, action in Action::\"FileOpen\", resource in Dir::\"/workspace/\");"}'
```

Persistence is similarly performed through `/api/policies/persist`. Offline, `leash policy lint <file>` reports the same issues (exit 1 on an error) and `leash policy migrate <file>` converts a legacy file.

## Runtime Behavior Notes

- Cedar is the only persisted artifact. Generated IR never touches disk.
- Default posture is deny; `forbid` wins over a conflicting permit.
- Policies apply at the Leash container/cgroup scope; per‑principal enforcement not yet available.
- Directory resources must end with `/` to indicate recursive coverage.
- Hostname wildcards support leading `*.` only (e.g., `*.example.com`).
- IPv6 and CIDR resources are unsupported and will trigger lints.
- Packet sockets (`AF_PACKET`, `AF_XDP`), raw IP sockets (`SOCK_RAW`) and
  SCTP sockets cannot be governed by `Host` rules: a bound packet or raw
  socket sends with no destination address, and SCTP adds peers past the
  connect hook. The kernel refuses to create them (`EPERM`) unless the policy
  restricts no destination at all (connect default allow, no `forbid` on
  `NetworkConnect`, no `forbid` on `McpCall`). There is no action to permit
  them otherwise. iputils `ping` uses an ICMP datagram socket where
  `net.ipv4.ping_group_range` admits the workload's group (Docker containers
  do); it is decided by the connect rules with port 0, so `Host::"1.1.1.1"`
  permits pinging it and `Host::"1.1.1.1:443"` does not. BusyBox `ping`
  needs a raw socket. See `docs/design/SECURITY-MODEL.md`.
