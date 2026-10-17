package darwind

// errClientRuleMutation is the response to a websocket client that tries to
// change the enforced macOS rules directly (mac.rule.add/remove/clear,
// mac.network_rule.update, mac.policy.decision). The rules the extensions
// enforce are compiled from the Cedar policy and from nothing else.
const errClientRuleMutation = "refused: macOS rules come only from the Cedar policy; edit the policy file or use the Control UI"
