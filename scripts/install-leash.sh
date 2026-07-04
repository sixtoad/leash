#!/usr/bin/env bash
#
# install-leash.sh — build leash from this checkout and install a ready binary
# onto a PATH directory, so `leash` (and scripts/leash-claude.sh) just work.
#
# Usage:
#   scripts/install-leash.sh                 # -> ~/.local/bin/leash  (no sudo)
#   scripts/install-leash.sh /usr/local/bin  # system-wide (run with sudo)
#
# The binary embeds the Control UI from internal/ui/dist. If that's still the
# build stub, run `make build-ui` first (needs pnpm) for the real dashboard.
#
set -euo pipefail

ROOT="$(git -C "$(dirname "$0")/.." rev-parse --show-toplevel)"
cd "$ROOT"
DEST="${1:-$HOME/.local/bin}"
mkdir -p "$DEST"

if [ ! -s internal/ui/dist/index.html ] || grep -q '>stub<\|<title>stub' internal/ui/dist/index.html 2>/dev/null; then
  echo "install-leash: WARNING: internal/ui/dist looks like the stub — the Control UI will be blank." >&2
  echo "install-leash:          run 'make build-ui' (needs pnpm) then re-run this to embed the real UI." >&2
fi

COMMIT="$(git rev-parse --short=7 HEAD 2>/dev/null || echo dev)"
BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "install-leash: building $(git branch --show-current 2>/dev/null || echo HEAD) -> $DEST/leash" >&2
CGO_ENABLED=0 go build -trimpath \
  -ldflags "-X main.commit=$COMMIT -X main.buildDate=$BUILD_DATE" \
  -o "$DEST/leash" ./cmd/leash

if command -v leash >/dev/null 2>&1 && [ "$(command -v leash)" = "$DEST/leash" ]; then
  echo "install-leash: installed $DEST/leash (on PATH ✓)" >&2
else
  echo "install-leash: installed $DEST/leash — add '$DEST' to PATH to use 'leash' directly." >&2
fi
