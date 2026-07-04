# Running Claude Code under leash (native, Linux)

How we sandbox **Claude Code** with leash's container-free native runtime: Claude
runs as *you* (not root), confined to your working directory, with its network
restricted to Anthropic — while leash enforces both layers (eBPF LSM + MITM
proxy). This is the downstream recipe; the native runtime itself lives in the
upstream-eligible slice (`feat/runtime-native-poc`).

## Install a ready binary (one-time)

**Download a prebuilt binary** from the GitHub Release (recommended — no toolchain):

```bash
curl -fsSL https://raw.githubusercontent.com/sixtoad/leash/walk-integration/scripts/leash-install.sh | bash
```

Detects your OS/arch, installs `leash` to `~/.local/bin` (override `LEASH_DEST`,
or `LEASH_TAG` for a specific release). Linux binaries are fully enforcing; on
macOS also `brew install --cask leash-app` (the binary is the CLI, enforcement is
in the app — see "macOS" below).

**Or build from source** onto your PATH:

```bash
scripts/install-leash.sh                    # -> ~/.local/bin/leash  (no sudo)
sudo scripts/install-leash.sh /usr/local/bin  # system-wide / env image
```

Build embeds the Control UI; if `internal/ui/dist` is still the stub, run
`make build-ui` (needs pnpm) first. Maintainers cut releases with
`scripts/release.sh <tag>`.

## Run Claude sandboxed

```bash
cd <your project>
scripts/leash-claude.sh
```

That generates the confinement policy from `$HOME`/`$PWD`, then runs Claude
sandboxed (workspace-confined, network → Anthropic only, running as you). If
`leash` isn't on PATH, point at it with `LEASH_BIN=/path/to/leash`. Everything
below is the *why*.

## Prerequisites

- **Linux** with the eBPF **`bpf` LSM active** — `cat /sys/kernel/security/lsm`
  must list `bpf`. If not, add it to the kernel command line and reboot (on
  systemd-boot / Pop!_OS: `sudo kernelstub --add-options "lsm=…,bpf"`; on GRUB,
  edit `GRUB_CMDLINE_LINUX`). See `docs/NATIVE-ENFORCEMENT-RUNBOOK.md`.
- **root** (`sudo`) — native enforcement needs `CAP_BPF`/`CAP_NET_ADMIN` to
  attach the LSM and set up the netns. The *workload* is dropped to your user.
- Claude authenticated normally at least once (so `~/.claude/.credentials.json`
  and `~/.claude.json` exist).

## What the sandbox allows — and why each entry matters

Default is **deny** (the policy never permits root `/` for reads), so it's an
explicit allow-list. Non-obvious entries, each learned the hard way:

| Entry | Why it's required |
|---|---|
| `Dir "/usr" … "/etc" "/proc" "/sys" "/dev"` (read) | Claude/Node can't even launch without libs, TLS roots, `/proc`, etc. |
| `File "$HOME/.claude.json"` (read+write) | **The login file.** Claude keeps account/config here — a *file in `$HOME`*, a sibling of the `.claude/` dir. Miss it and Claude can't see its login and drops to OAuth. `Dir "$HOME/.claude/"` does **not** cover it. |
| `Dir "$HOME/.claude/"` (read+write) | Token (`.credentials.json`), history, session state. |
| `Dir "/tmp/"` (read+write) | leash publishes its **CA cert** to `/tmp/leash-native-ca-<netns>.pem` for the workload to trust the MITM (leashd's own copy is in a `0700` root tree the dropped user can't read). Node's `NODE_EXTRA_CA_CERTS` points here — deny `/tmp` reads and TLS fails with `SELF_SIGNED_CERT_IN_CHAIN`. |
| `Dir "$HOME/.cache" ".config" ".local"` (read+write) | Claude's Bash tool + runtime write here; deny and its output pipe `EACCES`es. |
| `NetworkConnect` → Anthropic + resolvers only | Blocks Claude's third-party telemetry (see below). |

The confinement is real: Claude **cannot** read `~/.ssh`, other projects, or
`/root`, and cannot write outside the workspace / its own config.

## Claude Code emits telemetry to Datadog

With the network locked to Anthropic, you'll see leash deny (HTTP `403`) a
connection to **`http-intake.logs.us5.datadoghq.com`** — Datadog's log-intake
endpoint (their `us5` region is GCP-hosted; it shows up as a `34.128.x.x` /
`googleusercontent.com` address). That's **Claude Code's own telemetry/log
shipping**, not leash's. Claude tolerates the `403` fine; log shipping is
non-essential. This is exactly what the `NetworkConnect` allow-list is for: the
agent tries to phone home, and the policy stops it — matched by SNI at the proxy,
so it works regardless of the endpoint's rotating IPs.

## How it runs (architecture)

- **Privilege split.** leash/leashd stay root (to attach the LSM + build the
  netns); the workload is dropped to `$SUDO_USER` via `runuser`. So Claude runs
  non-root — which also lets it accept `--dangerously-skip-permissions` (Claude
  refuses that as root). The eBPF LSM enforces on the *cgroup*, uid-independent.
- **Layer 2 / egress.** The workload runs in a dedicated netns with veth + host
  NAT + a private-mount-ns `resolv.conf` (public DNS), entered via `nsenter --net`
  (which preserves `/sys/fs/{cgroup,bpf}` — `ip netns exec` would remount `/sys`).
  Claude's HTTPS is REDIRECTed to leashd's MITM proxy, decrypted, policy-checked,
  then forwarded out through the NAT.
- **Control UI.** Because leashd runs *inside the netns*, the UI is **not** at
  `localhost:18080` — it's at the **netns IP** printed in the egress setup
  (e.g. `http://10.x.y.2:18080/`). The `Leash UI: http://localhost:18080/` line
  is currently misleading under Layer 2 (fix pending).
- **leashd logs** go to `/tmp/leash-native-leashd-<netns>.log` (kept off the
  workload's TTY so they don't corrupt Claude's UI). `tail -f` it to watch
  enforcement/proxy activity.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Drops to OAuth login | A config read is denied — most often `~/.claude.json`. Add the missing path to the read list (check the panel or leashd log for the denied path). |
| `SELF_SIGNED_CERT_IN_CHAIN` / `tls: bad certificate` | Workload can't read/trust the CA. Ensure `/tmp` is in the **read** list; non-Node tools need the CA on the system bundle (pending). |
| TUI garbled by logs | Old binary — leashd's stdout now goes to the log file, not the TTY. |
| UI blank / unreachable | You're on `localhost` — use the **netns IP** from the startup log. |
| A tool/feature breaks | Its path/host isn't allowed. Watch denials in the panel and widen the policy — or use leash's suggest flow. |

## Portability

This is Linux-only (eBPF LSM + netns). **macOS** native support is the next phase
— the mechanism there is different (Endpoint Security + a network extension),
tracked separately.
