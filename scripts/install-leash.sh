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

# `leash version --json` reports `commit`, so a binary built from a modified tree
# must not advertise the pristine hash it was cut from. Three rules this shares
# with the Makefile, scripts/release.sh and build/publish-docker.sh:
#
#   - The marker is appended only when the commit lookup actually succeeded, so
#     the "dev" fallback never becomes "dev-dirty" — a 9-character string that is
#     neither a hash nor a documented sentinel.
#   - The check fails CLOSED. A git that errors (index lock, corrupt index,
#     ownership refusal) is stamped dirty and warned about, never silently read
#     as a clean tree. `[ -n "$(git status --porcelain 2>/dev/null)" ]` did the
#     opposite: stderr discarded, exit status ignored, no output read as pristine.
#   - It uses `git diff-index`, the same tracked-files test `git describe --dirty`
#     runs for VERSION below, so `version` and `commit` cannot disagree about the
#     same tree just because an untracked file is lying around.
COMMIT="$(git rev-parse --short=7 HEAD 2>/dev/null || true)"
if [ -z "$COMMIT" ]; then
  COMMIT="dev"
else
  git update-index -q --refresh >/dev/null 2>&1 || true
  dirty_rc=0
  git diff-index --quiet HEAD -- >/dev/null 2>&1 || dirty_rc=$?
  if [ "$dirty_rc" -ne 0 ]; then
    COMMIT="$COMMIT-dirty"
    if [ "$dirty_rc" -ne 1 ]; then
      echo "install-leash: WARNING: could not read the tree state (git diff-index exit $dirty_rc); assuming modified, stamping $COMMIT" >&2
    fi
  fi
fi
VERSION="$(git describe --tags --always --dirty 2>/dev/null || echo dev)"
BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "install-leash: building $(git branch --show-current 2>/dev/null || echo HEAD) -> $DEST/leash" >&2
CGO_ENABLED=0 go build -trimpath \
  -ldflags "-X main.version=$VERSION -X main.commit=$COMMIT -X main.buildDate=$BUILD_DATE" \
  -o "$DEST/leash" ./cmd/leash

if command -v leash >/dev/null 2>&1 && [ "$(command -v leash)" = "$DEST/leash" ]; then
  echo "install-leash: installed $DEST/leash (on PATH ✓)" >&2
else
  echo "install-leash: installed $DEST/leash — add '$DEST' to PATH to use 'leash' directly." >&2
fi
