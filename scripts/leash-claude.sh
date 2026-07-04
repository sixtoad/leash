#!/usr/bin/env bash
#
# leash-claude.sh — run Claude Code sandboxed by leash (native, container-free).
#
# Confines Claude to the current directory (+ its own config), lets it read the
# system files it needs to run, and restricts its network to Anthropic endpoints
# (so its Datadog telemetry is blocked). Claude runs as the invoking user, not
# root; leash/leashd hold root only for enforcement.
#
# Usage:   cd <project> && LEASH_BIN=/path/to/leash scripts/leash-claude.sh [claude args...]
# Requires: Linux, root (sudo), and the eBPF `bpf` LSM active. See
#           docs/CLAUDE-CODE-LEASHED.md for the full recipe and prerequisites.
#
set -euo pipefail

LEASH_BIN="${LEASH_BIN:-leash}"          # override with the built binary path
WORKSPACE="$PWD"                          # Claude is confined to this dir
CLAUDE="$(command -v claude || true)"
[ -n "$CLAUDE" ] || { echo "leash-claude: 'claude' not found on PATH" >&2; exit 1; }

POL="$(mktemp --suffix=.cedar /tmp/leash-claude.XXXXXX)"
trap 'rm -f "$POL"' EXIT

# Confinement policy. Default is DENY (root '/' is not permitted for reads), so
# this is an explicit allow-list. See docs/CLAUDE-CODE-LEASHED.md for the why of
# each entry (esp. ~/.claude.json and /tmp, which are non-obvious).
cat > "$POL" <<EOF
// Reads: system dirs Claude needs to launch + its config + the workspace.
permit (principal, action in [Action::"FileOpen", Action::"FileOpenReadOnly"], resource)
when { resource in [
  Dir::"/usr/", Dir::"/lib/", Dir::"/lib64/", Dir::"/bin/", Dir::"/sbin/", Dir::"/opt/",
  Dir::"/etc/", Dir::"/proc/", Dir::"/sys/", Dir::"/dev/", Dir::"/run/", Dir::"/tmp/",
  File::"/proc", File::"/sys",  // allow listing the roots (the fresh PID ns already limits /proc to own pids)
  Dir::"$HOME/.claude/", Dir::"$HOME/.config/", Dir::"$HOME/.cache/",
  Dir::"$HOME/.npm/", Dir::"$HOME/.local/",
  File::"$HOME/.claude.json", File::"$HOME/.claude.json.backup",
  File::"$HOME/.bashrc", File::"$HOME/.profile",
  Dir::"$WORKSPACE/"
] };
// Writes: workspace + Claude's config/state + temp only.
permit (principal, action == Action::"FileOpenReadWrite", resource)
when { resource in [
  Dir::"$WORKSPACE/", Dir::"$HOME/.claude/",
  Dir::"$HOME/.cache/", Dir::"$HOME/.config/", Dir::"$HOME/.local/",
  File::"$HOME/.claude.json", File::"$HOME/.claude.json.backup",
  Dir::"/tmp/", Dir::"/dev/", Dir::"/proc/", Dir::"/run/"
] };
// Claude runs tools freely inside the box.
permit (principal, action == Action::"ProcessExec", resource) when { resource in [ Dir::"/" ] };
// Network: Anthropic + the netns DNS resolvers only. Everything else (Claude's
// Datadog telemetry, etc.) is denied — enforced by the proxy (SNI) for HTTPS.
permit (principal, action == Action::"NetworkConnect", resource)
when { resource in [
  Host::"api.anthropic.com", Host::"*.anthropic.com",
  Host::"claude.com", Host::"*.claude.com",
  Host::"1.1.1.1", Host::"8.8.8.8"
] };
EOF

echo "leash-claude: confining Claude to $WORKSPACE (+ ~/.claude); network → Anthropic only." >&2
# Set LEASH_OPEN=1 to auto-open the Control UI in your browser (handy under the
# TUI, where the printed URL scrolls away). Pass DISPLAY/XAUTHORITY through so
# leash can open the browser in your session (the workload still has them scrubbed).
env_extra=()
leash_flags=()
if [ -n "${LEASH_OPEN:-}" ]; then
  leash_flags+=(--open)
  [ -n "${DISPLAY:-}" ] && env_extra+=("DISPLAY=$DISPLAY" "XAUTHORITY=${XAUTHORITY:-$HOME/.Xauthority}")
fi
echo "leash-claude: policy=$POL  (Control UI opens in-browser if LEASH_OPEN=1; else see the netns IP in the log)" >&2

# -E + explicit PATH/HOME so leash finds claude and Claude finds ~/.claude auth.
exec sudo -E env "PATH=$PATH" "HOME=$HOME" "${env_extra[@]}" "$LEASH_BIN" "${leash_flags[@]}" \
  --policy "$POL" "$CLAUDE" --dangerously-skip-permissions "$@"
