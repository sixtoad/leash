// The built-in permissive bootstrap policy (policy.DefaultCedarPolicy) as it
// was written for the legacy dialect (now an explicit opt-in).
// TestMigratedBuiltInPoliciesKeepTheirDecisions checks that its strict
// migration decides alike.
@leash_semantics("legacy")
permit (principal, action in [Action::"FileOpen", Action::"FileOpenReadOnly", Action::"FileOpenReadWrite"], resource)
when { resource in [ Dir::"/" ] };

permit (principal, action == Action::"ProcessExec", resource)
when { resource in [ Dir::"/" ] };

permit (principal, action == Action::"NetworkConnect", resource)
when { resource in [ Host::"*" ] };
