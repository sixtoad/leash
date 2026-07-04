# Agent permissions & sandboxing — landscape (and where leash fits)

A survey of how agentic coding tools handle **permissions and isolation**, and the
**authoring UX** for setting them — with leash/walk positioning. Reference material
for "why leash exists" and a to-do list of what to adopt. Compiled July 2026 from
official docs + reputable security research (URLs inline).

## Two axes

Every mature design separates two things:
- **Capability (the sandbox)** — what's technically possible (a read-only sandbox
  can't execute regardless of consent).
- **Consent (the approval policy)** — when the agent pauses for a human.

The strongest tools treat these as independent layers, plus a third: **org-managed
overrides** that lock policy above the user.

## Enforcement, at a glance

| Tool | Isolation (default) | OS primitive | Network egress | Permission model | Notable bypass |
|---|---|---|---|---|---|
| **Claude Code** | Sandbox opt-in | Seatbelt / bubblewrap+proxy | Proxy + domain allow-list (sandbox on) | `permissions.*` allow/deny/ask + modes; managed-settings lock | "Comment & Control" exfil |
| **Antigravity** | Sandbox **default-OFF** | Seatbelt / nsjail | Browser URL allow-list + net toggle | 3 policies + allow/deny lists; preset profiles | **RCE bypassed "Secure Mode"** (native tool ran before checks) |
| **Copilot (VS Code)** | Sandbox opt-in (Preview) | `chat.agent.sandbox.*` | `chat.agent.networkFilter` (Preview) | `chat.tools.terminal.autoApprove` allow/deny + regex; org kill-switch | CVE-2025-53773 (config-file RCE) |
| **Copilot (coding agent)** | **Always** (ephemeral Actions env) | Container/VM | **Default-ON egress firewall** + allow-list | PR review is the gate; single-branch/repo, no secrets | firewall **misses MCP + setup steps** |
| **OpenAI Codex** | Sandbox **default-ON** | Seatbelt / Landlock→bubblewrap+seccomp / WSL2 | **Default-deny** → loopback proxy + domain allow-list + method filter | `sandbox_mode` ⟂ `approval_policy`; org `requirements.toml` | bubblewrap `/proc/self/root` escape |
| **Cursor** | Sandbox layer | Seatbelt / seccomp+Landlock / WSL2 | Deny in sandbox; admin domain lists | Run Modes + `permissions.json` + LLM classifier | **denylist deprecated** after bypasses |
| **Aider / Cline / Roo / Cody / Zed / Amp** | **None** | — (host perms) | **None** | Approval prompts / allow-deny lists only | (runs as you) |
| **OpenHands / Devin** | Container / VM per session | Docker / "otterlink" microVM | Container nets / VPC | confirmation mode / autonomous | cloud-isolated |

## What the field has converged on (enforcement)

1. **OS primitives for local, containers/VMs for cloud.** Local CLIs/editors
   independently landed on the same stack: **Seatbelt (mac) + Landlock/seccomp/
   bubblewrap (Linux) + WSL2 (Win)**. Cloud agents use containers (Codex,
   OpenHands) or microVMs (Devin).
2. **Default-deny egress via a local proxy + domain allow-list** is the clearest
   convergence point — Codex, Cursor, Claude Code, Copilot's firewall all this
   shape. It's the anti-exfiltration lever.
3. **Layered config:** capability + consent + org-managed overrides.
4. **Command allow/deny lists are NOT a security boundary** — stated openly:
   Cursor deprecated its denylist and calls the allow-list "best-effort"; Zed/Roo
   add chained-command splitting because prefix matching is evadable.
5. **Threat framing = the "lethal trifecta"** (Willison: private data + untrusted
   content + external comms). Consensus: prompt injection is unsolved →
   **containment, not detection**.

Bypass evidence keeps proving the point that **in-agent controls aren't enough**:
Antigravity's Secure Mode → RCE (a native tool ran *before* the command checks),
Cursor's deprecated denylist, and "Comment & Control" (Apr 2026, CVSS 9.4)
exfiltrating `ANTHROPIC_API_KEY` across **Copilot + Claude Code + Gemini CLI at
once**. And OS sandboxes have documented escapes too (Codex & Claude bubblewrap
`/proc/self/root`), so they're defense-in-depth, not guarantees.

## Where leash fits (enforcement)

leash's architecture — **kernel eBPF LSM (L1) + default-deny egress MITM proxy
(L2)** — is exactly where the field is converging. Differentiators:

- **Agent-agnostic** — one Cedar policy for *any* agent/tool; the others are
  per-product (Claude settings, VS Code settings, Cursor Run Modes). leash is the
  substrate they'd each otherwise need.
- **Whole-cgroup coverage** — the agent's own process, subprocesses, **and MCP**.
  Copilot's firewall *documents* that it misses MCP + setup-steps; **nobody blocks
  the agent's own telemetry** — leash does (the Datadog demo).
- **Enforced below the agent** — a kernel LSM the agent can't disable, vs the
  in-process controls that keep getting bypassed.
- **Default-ON** — vs Antigravity/Copilot-VSCode/Claude sandboxes that are
  off/opt-in/preview.

Honest limits: native leash shares the OS-sandbox caveats (escapes exist, shared
kernel — a VM contains kernel exploits, native doesn't), and **microVM "wrap any
agent" products** (Docker Sandboxes `sbx`, GitHub's local/cloud sandboxes) offer
stronger *isolation* though coarser *policy*. leash's defensible niche is
fine-grained, agent-agnostic Cedar policy + whole-tree/telemetry coverage + a
container-free option — not isolation strength alone.

## Selected sources

- Willison, "The lethal trifecta" (2025-06-16) — https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/
- OpenAI Codex sandboxing — https://developers.openai.com/codex/concepts/sandboxing
- Cursor agent sandboxing (2026-02-18) — https://cursor.com/blog/agent-sandboxing ; denylist deprecation, The Register (2025-07-21) — https://www.theregister.com/2025/07/21/cursor_ai_safeguards_easily_bypassed/
- GitHub coding-agent firewall — https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/customize-the-agent-firewall ; risks — https://docs.github.com/en/copilot/concepts/agents/cloud-agent/risks-and-mitigations
- VS Code approvals — https://code.visualstudio.com/docs/agents/approvals
- Antigravity RCE / Secure-Mode escape (Pillar) — https://www.pillar.security/blog/prompt-injection-leads-to-rce-and-sandbox-escape-in-antigravity
- "Comment & Control" cross-tool exfil (SecurityWeek) — https://www.securityweek.com/claude-code-gemini-cli-github-copilot-agents-vulnerable-to-prompt-injection-via-comments/

## Friendly permission *authoring* — what people actually do

The striking finding: almost nobody makes *authoring rules* pleasant. The
"friendly" strategies mostly **avoid authoring** — presets, remembered approvals,
or letting the model decide.

1. **Graduated trust-level presets (the dominant pattern).** Pick a level, don't
   write rules. Claude Code (`default`/`acceptEdits`/`plan`/`auto`/`dontAsk`/
   `bypassPermissions`, `Shift+Tab`), Codex (Read-Only / Auto / Full-Access),
   Antigravity (Secure / Review-driven / Agent-driven / Custom), Copilot (Default
   / Bypass / Autopilot), Cursor (Auto-review / Allowlist / Run-Everything).
2. **In-context "always allow / remember", with scope.** VS Code is richest —
   the dialog offers **Single use / Session / Workspace / All future**; Zed's
   "Always for…" writes the config rule for you; Claude's "don't ask again" is
   tool-scoped. This *avoids* authoring rather than making it nice.
3. **Let the model/classifier decide (now mainstream).** Cursor Auto-review
   (allowlist → sandbox → an agentic classifier subagent for the ~5% ambiguous),
   Claude Code `auto` (a separate "reasoning-blind" Sonnet classifier), Cline (the
   model **self-tags** each command's `requires_approval`), OpenHands
   `LLMSecurityAnalyzer` (a `security_risk` field per tool). **Good for
   friendliness, disclaimed as security by every vendor** — self-assessment is
   circular (an injected model lies about risk), and obfuscation defeats it.
4. **Plan / preview mode** — approve a plan once vs. each action.
5. **Learn-from-usage / suggest-from-denials — thin / open space.** The only real
   instance is a Claude Code skill that scans past session transcripts and
   proposes an allow-list from patterns seen 3+ times. **No CLI auto-generates an
   allow-list from a dry run** (leash included — it has no `suggest`). This is
   largely unbuilt.
6. **Natural-language → policy — one shipping flagship.** AWS Bedrock **AgentCore
   Policy (NL2Cedar)**: describe in English which MCP tools an agent may call → an
   LLM drafts Cedar → a schema validator + **Cedar Analysis** (formal reasoning)
   verifies before enforcement. Otherwise research-stage (arXiv autoformalization).
7. **Visual/GUI editors — modest.** No dedicated graphical policy canvas; what
   exists is level selectors + rule lists (Claude `/permissions` TUI, VS Code,
   AgentCore's form-based Cedar builder, Permit.io/Descope/Oso repurposed IAM UIs).

## Cedar for agents — validated, **not** novel

"Cedar as the agent-permission language" is already shipping in 2026:
- **AWS Bedrock AgentCore Policy** — Cedar in the agent gateway, default-deny,
  evaluates every MCP tool call, uses partial evaluation to **hide disallowed
  tools from the model's tool list**. https://aws.amazon.com/blogs/security/why-policy-in-amazon-bedrock-agentcore-chose-cedar-for-securing-agentic-workflows/ (2026-05-20)
- **`cedar-policy/cedar-for-agents`** (official AWS org, v0.6) — generates a Cedar
  schema from an MCP server's tool descriptions. https://github.com/cedar-policy/cedar-for-agents
- **MCP authorization** is broadly converging on Cedar (vs OPA/Rego).
- **Coding agents specifically:** Sondera, "Hooking Coding Agents with the Cedar
  Policy Language" (2026-03-05) — one Cedar policy governing **Claude Code,
  Cursor, Copilot CLI, Gemini CLI** via hooks feeding a central Cedar engine as a
  runtime reference monitor. https://blog.sondera.ai/p/hooking-coding-agents-with-the-cedar
- Mature tooling: Cedar Playground, VS Code language server, and **Cedar Analysis**
  (formal verification proven in Lean — equivalence, does-this-edit-grant-new-access,
  shadowed permits). https://aws.amazon.com/blogs/opensource/introducing-cedar-analysis-open-source-tools-for-verifying-authorization-policies/

## The one genuinely novel gap

The industry's answer to "one policy, many tools" is a **central runtime PDP /
gateway** (AgentCore; Sondera's hook-bridge; OPA; OpenID AuthZEN) — one policy
evaluated **live**. **"Author one Cedar policy → compile it to multiple
tool-specific *static* configs"** (Claude `settings.json` + VS Code `chat.tools.*`
+ a firewall allow-list) **appears unbuilt** — direct searches found no such
project. It's attractive exactly where a live PDP isn't present: offline, no proxy,
native tool config. (Moderate confidence — proving a negative is hard, and
momentum favors runtime PDPs.)

## Emerging standards (runtime decision, not authoring format)

- **MCP Authorization** — OAuth 2.1 + **elicitation** (server requests input
  mid-session → JIT in-context consent); stable 2025-11-25.
- **OpenID AuthZEN** — agent-era drafts (2026-06): **AARP** (access-request &
  approval / consent tracking) + **COAZ** (AuthZEN profile for MCP tool authz).
- **Gap:** all standardize the runtime **decision/consent exchange**, not a
  portable **authoring format** across tools — reinforcing the novelty above.

## What leash should do about authoring

- **leash is already a runtime PDP** (kernel enforcement) — aligned with the
  winning pattern, but **agent-agnostic + whole-tree** where AgentCore/Sondera are
  MCP/hook-scoped.
- **Adopt the friendliness the field proved:** graduated trust-level presets;
  **NL→Cedar** (like AgentCore); **Cedar Analysis** for pre-flight verification
  (open source — free to wire in); and lead on the thin bit — **suggest /
  learn-from-denials** (observe a run → propose Cedar), which almost nobody has.
- **The differentiated bet: a Cedar→tool-config *compiler*** — author once, emit
  Claude `settings.json` + VS Code settings + a firewall allow-list *and* enforce
  the same policy at the leash boundary. That "compile-to-many-configs" framing is
  the apparently-unbuilt space; Sondera's runtime hook-bridge is the closest prior
  art to differentiate against.
