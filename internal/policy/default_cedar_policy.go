package policy

// DefaultCedarPolicy is the permissive bootstrap policy expressed in Cedar.
// It allows read/write/open across the filesystem, process execution,
// outbound network connections to any host and every MCP call. This mirrors
// the historical permissive policy we used for first-boot.
//
// It is strict Cedar, the default dialect, as `leash policy migrate` wrote
// it from the historical legacy file (TestDefaultCedarPolicyKeepsTheLegacy
// Decisions in internal/lsm checks the two decide alike). Strict Cedar
// denies by default, so MCP calls need their explicit permit.
const DefaultCedarPolicy = `// Migrated from legacy Leash policy semantics by ` + "`leash policy migrate`" + `.
// Every policy below is plain Cedar (forbid overrides permit, default deny),
// Leash's default dialect, and decides exactly like the legacy file did.
//
// added: file-open-default-allow: an allow on "/" made the legacy file-open default allow for every mode
// added: mcp-default-allow: legacy MCP calls were allowed unless forbidden

permit (
    principal,
    action in [Action::"FileOpenReadOnly", Action::"FileOpenReadWrite"],
    resource
)
when { resource in Dir::"/" };

permit (
    principal,
    action == Action::"ProcessExec",
    resource
)
when { resource in Dir::"/" };

permit (
    principal,
    action == Action::"NetworkConnect",
    resource
);

@leash_rewrite("file-open-default-allow")
permit (
    principal,
    action in [Action::"FileOpenReadOnly", Action::"FileOpenReadWrite"],
    resource
);

@leash_rewrite("mcp-default-allow")
permit (
    principal,
    action == Action::"McpCall",
    resource
);
`

// DefaultCedar returns the permissive bootstrap Cedar policy.
func DefaultCedar() string { return DefaultCedarPolicy }
