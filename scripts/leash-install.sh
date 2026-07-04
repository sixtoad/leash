#!/usr/bin/env bash
#
# leash-install.sh — download a prebuilt leash binary from the GitHub Release and
# install it onto your PATH. Detects OS/arch and grabs the latest release asset.
#
#   curl -fsSL https://raw.githubusercontent.com/sixtoad/leash/walk-integration/scripts/leash-install.sh | bash
#
# Env:  LEASH_REPO (default sixtoad/leash), LEASH_DEST (default ~/.local/bin),
#       LEASH_TAG  (default: latest release)
#
set -euo pipefail

REPO="${LEASH_REPO:-sixtoad/leash}"
DEST="${LEASH_DEST:-$HOME/.local/bin}"
TAG="${LEASH_TAG:-latest}"

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) echo "leash-install: unsupported arch '$arch'" >&2; exit 1 ;;
esac
case "$os" in linux|darwin) ;; *) echo "leash-install: unsupported OS '$os'" >&2; exit 1 ;; esac

asset="leash_${os}_${arch}.tar.gz"
if [ "$TAG" = latest ]; then
  url="https://github.com/$REPO/releases/latest/download/$asset"
else
  url="https://github.com/$REPO/releases/download/$TAG/$asset"
fi

mkdir -p "$DEST"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
echo "leash-install: downloading $asset ($TAG) → $DEST/leash" >&2
curl -fsSL "$url" | tar -xz -C "$tmp"
install -m755 "$tmp/leash" "$DEST/leash"

if command -v leash >/dev/null 2>&1 && [ "$(command -v leash)" = "$DEST/leash" ]; then
  echo "leash-install: installed $DEST/leash (on PATH ✓) — run: leash --help" >&2
else
  echo "leash-install: installed $DEST/leash — add '$DEST' to PATH to use 'leash' directly." >&2
fi
if [ "$os" = darwin ]; then
  echo "leash-install: NOTE — macOS enforcement also needs the signed app: brew install --cask leash-app" >&2
fi
