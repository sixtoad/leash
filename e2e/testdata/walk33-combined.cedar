// Migrated from legacy Leash policy semantics by `leash policy migrate`.
// Every policy below is plain Cedar (forbid overrides permit, default deny),
// Leash's default dialect, and decides exactly like the legacy file did.
//
// Source: the combined policy Walk generated for the Walk #33 / Leash #78
// dogfood; the legacy original is internal/lsm/testdata/walk33-combined.legacy.cedar.
//
// added: mcp-default-allow: legacy MCP calls were allowed unless forbidden

permit (
    principal,
    action in [Action::"FileOpenReadOnly", Action::"FileOpenReadWrite"],
    resource
)
when { resource in [Dir::"/bin/", Dir::"/dev/", Dir::"/etc/", Dir::"/home/agent/.cache/", Dir::"/home/agent/.config/", Dir::"/home/agent/.local/", Dir::"/home/agent/.local/share/walk/codex-home/", Dir::"/home/agent/.npm/", Dir::"/leash/", Dir::"/lib/", Dir::"/lib64/", Dir::"/opt/", Dir::"/proc/", Dir::"/run/", Dir::"/sbin/", Dir::"/sys/", Dir::"/tmp/", Dir::"/usr/", Dir::"/workspace/", FilePrefix::"/proc", FilePrefix::"/sys"] };

permit (
    principal,
    action == Action::"FileOpenReadWrite",
    resource
)
when { resource in [Dir::"/dev/", Dir::"/home/agent/.cache/", Dir::"/home/agent/.config/", Dir::"/home/agent/.local/", Dir::"/home/agent/.local/share/walk/codex-home/", Dir::"/home/agent/.npm/", Dir::"/leash/", Dir::"/proc/", Dir::"/run/", Dir::"/tmp/", Dir::"/workspace/"] };

forbid (
    principal,
    action in [Action::"FileOpenReadOnly", Action::"FileOpenReadWrite"],
    resource
)
when { resource in [Dir::"/home/agent/.config/containers/", Dir::"/home/agent/.config/doctl/", Dir::"/home/agent/.config/gcloud/", Dir::"/home/agent/.config/gh/", Dir::"/home/agent/.config/helm/", Dir::"/home/agent/.config/op/", Dir::"/home/agent/.config/pulumi/", Dir::"/home/agent/.local/share/keyrings/", FilePrefix::"/home/agent/.bash_history", FilePrefix::"/home/agent/.bash_profile", FilePrefix::"/home/agent/.bashrc", FilePrefix::"/home/agent/.config/hub", FilePrefix::"/home/agent/.env", FilePrefix::"/home/agent/.netrc", FilePrefix::"/home/agent/.profile", FilePrefix::"/home/agent/.zprofile", FilePrefix::"/home/agent/.zsh_history", FilePrefix::"/home/agent/.zshenv", FilePrefix::"/home/agent/.zshrc"] };

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
)
when { resource in [Host::"192.168.1.1", Host::"1.1.168.192", Host::"1.1.1.1", Host::"8.8.8.8", Host::"registry.npmjs.org", Host::"api.openai.com", Host::"auth.openai.com", Host::"chatgpt.com", Host::"*.chatgpt.com"] };

@leash_rewrite("mcp-default-allow")
permit (
    principal,
    action == Action::"McpCall",
    resource
);
