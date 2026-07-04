# Transparent sandbox — the policy-aware agent

**Status: design spec (walk). Not yet implemented.**

leash enforces a hard boundary the agent can't cross. Today that boundary is
*opaque* to the agent: it discovers it by trial-and-error (bare `EACCES`),
wastes turns, misattributes failures, and fails silently. This spec makes the
same policy **visible to the agent** — so it plans within its limits, understands
denials, and asks the human to widen when it genuinely needs more.

## Principle

> **The agent gets the *map*; leash is the *fence*. The map is generated *from*
> the fence — one Cedar policy — so they can never drift.**

Everywhere else, the agent's "knowledge of its permissions" (its config) and the
actual enforcement are *separate artifacts that can disagree*. Here they are two
renderings of one Cedar source: the transpiler already produces the LSM rules;
the map is a second projection of the same input.

**Key safety property — awareness ≠ capability.** Telling the agent the policy
does **not** let it bypass anything; the eBPF LSM is still the gate. A
prompt-injected agent that *knows* the rules still can't cross them. So this is
UX/efficiency upside at ~zero security cost. (The policy is the user's own
confinement rules, not secrets — but see §6 on not leaking sensitive paths.)

## Goals / non-goals

**Goals:** the agent (a) knows its file/exec/network constraints *before* acting,
(b) gets a *structured reason* when denied, (c) can *request* a widening that a
**human** approves and leash hot-reloads. The map always matches the fence.

**Non-goals:** not a replacement for enforcement; not a prompt-injection defense
(awareness is advisory); the agent must **never** self-widen (§4); any compiled
native config (§3.B) is best-effort, not the boundary.

## 3. The three capabilities

### A. Policy briefing — preemptive awareness (build first)

A concise, agent-readable summary of the **effective** policy, rendered from the
same transpiled Cedar the LSM enforces (`internal/transpiler`), e.g.:

```
# Your sandbox (enforced by leash at the kernel level — you cannot bypass this)
READ:    <workspace>/, /usr, /etc, ~/.claude, ~/.claude.json   (default: DENY)
WRITE:   <workspace>/, ~/.claude, /tmp                          (default: DENY)
EXEC:    any
NETWORK: api.anthropic.com, *.anthropic.com, claude.com         (default: DENY)
DENIED example: ~/.ssh, other users' homes, arbitrary internet.
If you need more, ASK the human to widen the policy — do not retry blindly.
```

- **Generation:** a `leash policy explain`-style renderer over the transpiled
  policy (same struct that feeds the LSM), so the brief is exact.
- **Delivery (agent-agnostic):** write the brief to `$LEASH_DIR/policy-brief.md`
  and export `LEASH_POLICY_BRIEF=<path>`. The wrapper decides how to surface it —
  for Claude Code, `leash-claude.sh` appends it to the system prompt (or a
  `SANDBOX.md` the agent is told to read).

### B. Native-config projection — the Cedar→config compiler (deeper)

Compile the enforceable subset of the Cedar policy into the agent's **own**
permission config, so its native machinery (tool approval, allowed dirs) reflects
the constraints — defense-in-depth *and* native awareness.

| Cedar | Claude Code `settings.json` | Fidelity |
|---|---|---|
| `FileOpenReadOnly` Dir/File | `permissions.additionalDirectories` / `Read` allow | good |
| `FileOpenReadWrite` | `Edit`/`Write` allow | good |
| `NetworkConnect` Host | `sandbox.network.allowedDomains` / `WebFetch(domain:)` | good |
| `McpCall` `MCP::Tool` | `mcp__server__tool` allow/deny | good |
| `ProcessExec` (path) | `Bash(...)` (command-string) | poor — different model |

Output `~/.claude/settings.json` (or managed-settings to lock). **Best-effort,
agent-facing map only** — Claude perms are tool-scoped, not whole-tree; leash
stays the real boundary. (The landscape survey found this "one policy → many
static tool configs" direction apparently **unbuilt** — see
[AGENT-PERMISSIONS-LANDSCAPE.md](AGENT-PERMISSIONS-LANDSCAPE.md).)

### C. Reactive denials + the widen loop (the "suggest" gap)

- **Structured denial feedback.** The LSM already emits deny events (path,
  action). Expose recent denials with a reason + a suggested Cedar rule, e.g.
  `denied file.open:ro /etc/hosts — not in allow-list; to permit: permit(... File::"/etc/hosts")`.
  Surface via (i) a `denials` file the agent can read, (ii) the Control UI, and
  (iii) an MCP tool (§5). Correlation is by path+timestamp (kernel `EACCES` carries
  no in-band reason — §6).
- **Widen loop (human-gated).** The agent calls "request permission for X"; the
  **human** approves in the leash UI/terminal; leash writes the rule and
  **hot-reloads** (reuse the existing `/api/policies` + policy watcher +
  `UpdateRuntimeRules`, which already live-reloads the BPF maps). This is also the
  learn-from-denials capability almost nobody ships.

## 4. The human gate (critical)

`request_permission` **must not** self-grant — the agent proposes, a human
disposes. If the agent could widen its own policy, the fence is gone. So the
widen path always routes to a human decision (UI button / terminal prompt),
never an auto-approve. (An optional `--auto-widen` for trusted/dev use could
exist, but default is human-gated.)

## 5. Interface: a leash MCP server (agent-agnostic)

Wrap A + C behind a small MCP server leash exposes, so **any** MCP-capable agent
gets awareness without bespoke wiring — and it rides the MCP-authorization
convergence the field is standardizing on:

- `describe_policy()` → the brief (§3.A).
- `explain_denial(path?)` → recent denials + reasons + suggested rules (§3.C).
- `request_permission(action, resource)` → routes to the human gate (§4); returns
  granted/denied after hot-reload.

## 6. Risks / open questions

- **Denial→reason channel.** Kernel `EACCES` has no in-band reason; the agent
  correlates its failure to a leash deny-event by path+time — may be imprecise
  under bursts. Acceptable for guidance; not a guarantee.
- **Sensitive-path leakage.** The brief lists *denied categories* generically
  ("other users' homes", "arbitrary internet"), not an enumerated secret list, so
  it doesn't hand an attacker a target map beyond what they'd learn by probing.
- **Compiler lossiness (§3.B).** `ProcessExec` and whole-tree coverage don't map
  to Claude's tool-scoped model; the compiled config is a *hint*, leash enforces.
- **Sync on hot-reload.** When the policy live-reloads, the brief and any compiled
  config must regenerate — hook the same watcher callback.
- **Trust of the brief.** The agent could ignore/hallucinate around the brief;
  that's fine — the LSM still enforces. The brief is efficiency, not control.

## 7. Phasing

1. **A — policy briefing** (smallest, instant fix for the flailing).
2. **C — structured denials + human-gated widen** (reuses hot-reload; the learn loop).
3. **5 — MCP server** wrapping A + C (agent-agnostic).
4. **B — Cedar→config compiler** (native awareness; the apparently-novel piece).

## 8. Positioning

AgentCore already does a narrow version — Cedar + partial evaluation to *hide
disallowed MCP tools from the model's list*. This generalizes it to
**file/exec/network at the kernel boundary, agent-agnostic**, with a map provably
derived from the enforced policy. Sondera's runtime hook-bridge is the closest
prior art (one Cedar policy over many agents, but hook-scoped and enforcement-only,
no agent-facing map). The differentiated claim: **the same Cedar policy is both
the uncircumventable fence and the agent's map, and they cannot drift.**
