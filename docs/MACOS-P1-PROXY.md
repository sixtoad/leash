# macOS P1 — routing workload traffic through the MITM proxy

P1 closes the biggest macOS gap: the `darwind` MITM proxy exists and runs (listening
on `:18000`), but **nothing routes workload traffic through it**, so header rewrite /
secret injection, MCP enforcement, TLS interception, and L7 host policy are all
unreachable on macOS. This doc is the plan; it lands in pieces.

## Why it's not just "turn it on"

On Linux, netfilter `REDIRECT` transparently sends egress to the proxy, which recovers
the real destination via `SO_ORIGINAL_DST`. macOS has neither: `NEFilterDataProvider`
can only allow/drop (not redirect), and there is no `SO_ORIGINAL_DST`. So macOS needs:

1. a **`NETransparentProxyProvider`** (new system extension) that actually intercepts
   tracked TCP flows and relays them to the local proxy, and
2. a way to tell the proxy each flow's **original destination** out-of-band.

## Architecture

```
tracked workload ──TCP──► NETransparentProxyProvider (Swift, new sysext)
                              │  opens 127.0.0.1:18000, writes PROXY v1 header
                              ▼
                          darwind MITM proxy (Go) ──► upstream (with MITM/policy)
```

- **Original destination transport: PROXY protocol v1.** The Swift provider knows the
  flow's remote endpoint; it prepends a one-line `PROXY TCP4 <src> <dst> <sport> <dport>`
  header before relaying bytes. The proxy reads that instead of `SO_ORIGINAL_DST`, then
  reuses the existing `handleTransparentHTTP/HTTPS` handlers unchanged.
- **Scope to tracked PIDs.** Like the content filter, the provider only proxies flows
  from leash-tracked PID lineage; everything else passes through untouched.
- **CA trust.** For TLS MITM the workload must trust the leash CA. `leashcli` exports
  `NODE_EXTRA_CA_CERTS` / `SSL_CERT_FILE` / `CURL_CA_BUNDLE` / `REQUESTS_CA_BUNDLE` /
  `GIT_SSL_CAINFO` pointing at the CA (mirrors the Linux native launcher).

## Workstream

- [x] **Go: PROXY-protocol ingestion** (this PR) — `MITMProxy.SetProxyProtocolIngestion(true)`
      makes `Run()` read a PROXY v1 header per connection (`readProxyProtocolV1Dest`)
      instead of `SO_ORIGINAL_DST`; the peek+route logic is shared via `serveTransparent`.
      darwind enables it (macOS has no `SO_ORIGINAL_DST`). Unit-tested on the host
      (`proxyprotocol_test.go`) — no VM needed.
- [ ] **Swift: `NETransparentProxyProvider` extension** — new system-extension target
      (pbxproj + Info.plist `NEProviderClasses` for `com.apple.networkextension.transparent-proxy`
      + entitlement). `handleNewFlow`: accept flows from tracked PIDs, open a marked
      socket to `127.0.0.1:18000`, write the PROXY v1 header, then relay bidirectionally.
      Needs VM runtime testing.
- [ ] **App: `NETransparentProxyManager` wiring** — activate/enable the transparent
      proxy (analogous to the existing `NEFilterManager` flow), with a rules/network
      config that scopes interception.
- [ ] **CA env injection** — `leashcli` exports the CA env vars for the launched workload.
- [ ] **Loopback bind hardening** — the proxy currently listens on `:port` (all
      interfaces); consider binding `127.0.0.1` on macOS so only local flows reach it
      (ties into P2 control-plane isolation).

## Notes

- The Swift provider and app wiring can only be validated in the SIP/AMFI-relaxed VM,
  so they land after this host-testable Go piece.
- Once traffic traverses the proxy, header rewrite (`internal/proxy/rewriter.go`), MCP
  enforcement (`internal/proxy/mcp_observer.go`), and TLS MITM (`internal/proxy/ca.go`)
  all activate on macOS with no further Go work — their backends already exist.
