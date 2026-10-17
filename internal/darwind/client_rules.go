package darwind

// errClientRuleMutation is the response to a websocket client that tries to
// change the enforced macOS rules directly (mac.rule.add/remove/clear,
// mac.network_rule.update, mac.policy.decision). The rules the extensions
// enforce are compiled from the Cedar policy and from nothing else.
const errClientRuleMutation = "refused: macOS rules come only from the Cedar policy; edit the policy file or use the Control UI"

// darwinLoopback is where the daemon's Control UI/API and MITM proxy listen
// by default: the extensions and leashcli only ever connect over loopback.
const darwinLoopback = "127.0.0.1"
