# macOS enforcement parity roadmap

Tracks the work to bring the macOS native path (`mac-leash/` Swift extensions +
`internal/darwind/` Go daemon) up to parity with the Linux native enforcement
feature set. Target: **full parity** (P0–P2).

## Architecture recap

macOS does not use the Linux per-command model (cgroup + netns + eBPF LSM +
transparent proxy). Instead:

- **`internal/darwind/`** (Go) — runs Cedar policy, the Control UI/API on `:18080`,
  the WebSocket hub the Swift extensions connect to, and instantiates a
  `MITMProxy` + `HeaderRewriter` + `policy.Manager` + `macsync.Manager`.
- **LeashES** (Swift, Endpoint Security) — real `exec` authorization + file `open`
  gate for leash-tracked processes.
- **LeashNetworkFilter** (Swift, `NEFilterDataProvider`) — real L4 flow allow/drop
  + SNI/DNS learning.
- eBPF LSM is stubbed on darwin (`internal/lsm/stubs.go`); the Swift extensions
  replace kernel enforcement.
- Process tracking is **PID-lineage** based (`leashPID` label), not cgroup.

### The structural hole

Nothing routes workload traffic through the MITM proxy on macOS. `NEFilterDataProvider`
can only allow/drop, not redirect; there is no `NETransparentProxyProvider` /
`NEAppProxyProvider`, and `darwind`'s workload launch injects no `HTTP(S)_PROXY`
or CA env. So the proxy (and everything built on it — header rewrite, secret
injection, MCP enforcement, TLS MITM, L7 host policy) is constructed but off to the
side. `preflight_extensions_darwin.go` states plainly: *"native macOS has no proxy
fallback"* and it runs **UNENFORCED** by default.

## Parity matrix

| Capability | Linux | macOS today | Workstream |
|---|---|---|---|
| Exec control | eBPF LSM, default-deny | LeashES AUTH_EXEC (real), default-**allow** | P0 |
| File-open control | eBPF LSM, default-deny | LeashES AUTH_OPEN (real), default-allow | P0 |
| Network L4 egress | eBPF LSM IP+port, default-deny | Real drop; **CIDR fixed**; default-allow; UDP only DNS | P0 |
| Fail-closed posture | default-deny, `--require-lsm` | fail-open (warns, runs unenforced) | P0 |
| Interactive decisions | daemon/UI | wired but ES doesn't block-and-wait | P0 |
| L7 MITM proxy | transparent redirect + SO_ORIGINAL_DST | proxy exists in daemon, **not in path** | P1 |
| TLS CA injection | internal CA + env vars | none | P1 |
| Header rewrite / secret injection | proxy rewriter | not reachable (no proxy path) | P1 |
| MCP tool-call enforcement | proxy mcp_observer | not reachable (no proxy path) | P1 |
| DNS control | resolve-for-rules + annotate | observe-only, not enforced | P1 |
| Secret broker (`--inject-service`) | generic hook; keychain fetch | not wired on mac | P2 |
| cgroup/netns isolation | cgroup-v2 subtree + netns | none (PID-lineage only) | P2 |
| Control-plane port isolation | netfilter REJECT leash port | weak | P2 |
| Process hardening (caps/seccomp/ns) | harden_linux.go | none (different OS model) | P2 |

## Workstreams

### P0 — Make existing enforcement trustworthy

- [x] **CIDR matching** — `isIPInRange` was a stub returning `false`; now real IPv4/IPv6
      prefix matching (`FilterDataProvider+RuleEvaluation.swift`).
- [x] **Fail-closed default (LeashES, exec/file)** — `checkPolicyOrAllowDefault` now
      default-denies on a rule-miss when connected + a policy snapshot is loaded
      (`policyLoaded` flag guards the connect→first-snapshot window); degrades to
      allow + log when daemon/policy unavailable. `LeashMonitor+Handlers.swift`,
      `LeashCommunicationService(+Handlers).swift`.
- [x] **Fail-closed default (LeashNetworkFilter)** — implemented (both sides build;
      runtime-verify in VM: DNS resolves, permissive allows, tightened policy denies).
      `evaluateFlow` now default-denies on no-match when the connect default is deny +
      connected + rules loaded, exempts DNS, and degrades to allow otherwise. The
      connect default posture is propagated macsync → darwind payloads → Swift.
      Original **verified blocker:**
      `Host::"*"` transpiles to `ConnectDefaultAllow=true` and emits *no* concrete
      connect rule (`cedar_to_leash.go:125-146`), and `ConvertPolicyToMacRules`
      (`macsync/translator.go`) never propagates that default — so the permissive
      default policy yields an **empty** mac network rule set. A naive default-deny
      would therefore brick fresh setups (every tracked flow denied). Implementation
      required (cross-language, ~7 sites), all mapped:
      1. `macsync/manager.go`: add `networkDefaultAllow bool` (init true) +
         `SetNetworkDefaultAllow` / `GetNetworkDefaultAllow` (avoid changing
         `UpdateNetworkRules` signature so no call-site/test churn).
      2. `runtime_darwin.go`: at the policy push (~1317) call
         `SetNetworkDefaultAllow(policies.ConnectDefaultAllow)`; include
         `network_default_allow` in the query response (~926) and
         `broadcastNetworkRuleUpdate` (~1114) payload maps.
      3. Swift `FilterDataProvider+State.swift`: parse `network_default_allow`
         (default **true** if absent, for backward safety) + a `networkRulesLoaded`
         flag; store both under `syncQueue`.
      4. Swift `evaluateFlow`: on no-match — always `.allow` if `isDNSQuery` (DNS is
         plumbing, not the enforcement point, mirroring Linux); else `.allow` if
         `networkDefaultAllow`; else `.deny` only when connected + `networkRulesLoaded`
         (same gating as LeashES); otherwise `.allow` (degrade).
      Runtime-verify in the VM: DNS still resolves, permissive policy still allows,
      tightened policy (remove `Host::"*"`) denies unmatched flows.
- [ ] **Require-enforcement hard-fail into the extension** — the "if required, fail"
      half. Env doesn't reach the system extension; plumb `LEASH_REQUIRE_ENFORCEMENT`
      via app-group config or a daemon message so daemon-unreachable can fail closed
      when required. `preflight_extensions_darwin.go` already handles the launch-time
      gate.
- [ ] **Interactive decisions** — decide sync vs async. Either make ES block-and-wait
      on a `LeashPolicyDecision` from the daemon, or formally accept async allow +
      retro-kill. Files: `LeashMonitor+Handlers.swift`, `LeashCommunicationService+Handlers.swift`.
- [ ] **Domain persistence** — `persistResolvedDomains()` / `reloadResolvedDomains()`
      are empty; the SNI/DNS→IP cache is lost on restart. Files:
      `FilterDataProvider+RuleEvaluation.swift`, `+State.swift`.
- [ ] **`queryTrackedPIDs`** returns `[]` ("no query endpoint yet") — add the daemon
      endpoint or remove the dead path. `DaemonSync+Extensions.swift`.
- [ ] **NEMachServiceName caveat** (issue #19) — empty team prefix under ad-hoc; verify
      the network filter registers in the VM, mitigate if not.

### P1 — The L7 proxy layer (highest capability payoff)

- [ ] **Transparent proxy provider** — add a `NETransparentProxyProvider` (new system
      extension target, or convert the filter) that redirects leash-tracked TCP flows
      into `darwind`'s existing `MITMProxy`. This single piece unlocks the four items
      below, whose Go backends already exist.
      - Alternative/interim: inject `HTTP(S)_PROXY` env from `leashcli` (works only for
        proxy-respecting clients, not transparent).
- [ ] **CA trust injection** — export the leash CA to the workload (env vars
      `NODE_EXTRA_CA_CERTS` / `SSL_CERT_FILE` / `CURL_CA_BUNDLE` / …) from `leashcli`,
      mirroring the Linux launcher. Enables TLS MITM.
- [ ] **Header rewrite / secret injection** — once traffic traverses the proxy, wire
      `HeaderRewriter` through on mac (backend done in `internal/proxy/rewriter.go`).
- [ ] **MCP tool-call enforcement** — same; backend `internal/proxy/mcp_observer.go`.
- [ ] **DNS enforcement** — stop skipping DNS-query flows in `evaluateFlow`; drop
      queries to denied domains (or enforce at the proxy/resolver).

### P2 — Containment & secrets

- [ ] **Secret broker** — wire `--inject-service` on macOS (bind a helper's unix
      socket into the workload env); `keychain_darwin.go` already fetches from Keychain.
- [ ] **Containment story** — macOS has no cgroup/netns equivalent. Decide the
      accepted containment model (PID-lineage + system-extension scoping) and document
      the residual gap honestly.
- [ ] **Control-plane isolation** — block workload access to the `:18080` daemon port
      via the network filter (mac analog of the netfilter REJECT).
- [ ] **Process hardening** — evaluate the macOS analog (App Sandbox profile / limited
      entitlements for the launched workload); likely partial vs Linux seccomp/ns.

## Notes

- Local dev/build/run of the extensions: see `docs/MACOS-DEV.md` (ad-hoc signing,
  SIP/AMFI-relaxed VM). Gate the VM with `mac-leash/devtools/esprobe/run.sh`.
- Policy authoring is Cedar (shared with Linux, served by `darwind`); the Swift
  extensions are clients of the daemon rule snapshot — there is no mac-side config
  file today.
