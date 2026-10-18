// The "Example Policy File" of docs/design/CEDAR.md as it was written for the
// legacy dialect (now an explicit opt-in). The document shows its strict
// form, testdata/cedar-md-example.cedar; TestMigratedBuiltInPoliciesKeep
// TheirDecisions checks that the two decide alike.
@leash_semantics("legacy")
permit (principal, action in [Action::"FileOpen", Action::"FileOpenReadOnly", Action::"FileOpenReadWrite"], resource)
when { resource in [ Dir::"/workspace/" ] };

forbid (principal, action == Action::"FileOpenReadWrite", resource)
when { resource in [ Dir::"/workspace/secrets/" ] };

permit (principal, action == Action::"ProcessExec", resource)
when { resource in [ Dir::"/bin/", Dir::"/usr/bin/" ] };

forbid (principal, action == Action::"ProcessExec", resource)
when { resource in [ File::"/bin/rm" ] };

permit (principal, action == Action::"NetworkConnect", resource)
when { resource in [ Host::"api.internal" , Host::"db.internal:5432" ] };

forbid (principal, action == Action::"NetworkConnect", resource)
when { resource in [ Host::"*.facebook.com" ] };

forbid (principal, action == Action::"McpCall", resource == MCP::Tool::"execute-shell")
when { resource in [ MCP::Server::"mcp.example.com" ] };

permit (principal, action == Action::"HttpRewrite", resource == Host::"api.internal")
when {
    context.header == "X-Leash-Auth" &&
    context.value  == "service-token"
};
