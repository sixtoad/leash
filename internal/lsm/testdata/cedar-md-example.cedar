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
