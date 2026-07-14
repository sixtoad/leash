#!/usr/bin/env bash
#
# release.sh — cross-build leash and publish a GitHub Release on the fork.
#
# Usage:  scripts/release.sh <tag>        e.g. scripts/release.sh native-v0.1.0
# Env:    LEASH_REPO   (default: sixtoad/leash)
#
# Builds linux/darwin × amd64/arm64, tars each, writes checksums, and cuts a
# GitHub Release from the current branch with those assets. Linux binaries are
# fully enforcing; the macOS binary is the CLI that drives an installed Leash.app.
#
set -euo pipefail

TAG="${1:?usage: scripts/release.sh <tag>  (e.g. native-v0.1.0)}"
REPO="${LEASH_REPO:-sixtoad/leash}"
ROOT="$(git -C "$(dirname "$0")/.." rev-parse --show-toplevel)"
cd "$ROOT"
BRANCH="$(git branch --show-current)"

# The Control UI must be real, not the build stub (it's embedded in the binary).
if [ ! -s internal/ui/dist/index.html ] || grep -q '>stub<\|<title>stub' internal/ui/dist/index.html 2>/dev/null; then
  echo "release: internal/ui/dist is the stub — run 'make build-ui' first (needs pnpm)." >&2
  exit 1
fi

# The leash-entry helper binaries are embedded in the binary (go:generate builds
# them into bundled_*_gen.go, which are gitignored). Regenerate them fresh so the
# release never ships empty embeds — otherwise the binary fails at runtime with
# "embedded binary leash-entry-... missing" (as a fresh-clone build would).
echo "release: generating embedded leash-entry binaries..." >&2
go generate ./internal/entrypoint/...
for f in internal/entrypoint/bundled_linux_amd64_gen.go internal/entrypoint/bundled_linux_arm64_gen.go; do
  [ -s "$f" ] || { echo "release: $f empty after generate — leash-entry embed failed" >&2; exit 1; }
done

DIST="$ROOT/dist"
rm -rf "$DIST"; mkdir -p "$DIST"
COMMIT="$(git rev-parse --short=7 HEAD)"
DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

for pair in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do
  os="${pair%/*}"; arch="${pair#*/}"
  echo "release: building $os/$arch..." >&2
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath \
    -ldflags "-X main.version=$TAG -X main.commit=$COMMIT -X main.buildDate=$DATE" \
    -o "$DIST/leash" ./cmd/leash
  tar -C "$DIST" -czf "$DIST/leash_${os}_${arch}.tar.gz" leash
  rm -f "$DIST/leash"
done
( cd "$DIST" && sha256sum *.tar.gz > checksums.txt )

echo "release: publishing $TAG to $REPO (target $BRANCH, $COMMIT)..." >&2
gh release create "$TAG" --repo "$REPO" --target "$BRANCH" --title "$TAG" --notes "\
leash native build from \`$BRANCH\` ($COMMIT).

- **Linux** binaries are fully enforcing (eBPF LSM + MITM proxy).
- **macOS** binary is the CLI for an already-installed \`Leash.app\` (\`brew install --cask leash-app\`).

Install (Linux/macOS):
\`\`\`
curl -fsSL https://raw.githubusercontent.com/$REPO/$BRANCH/scripts/leash-install.sh | bash
\`\`\`
Then sandbox Claude Code: \`cd <project> && scripts/leash-claude.sh\` (see docs/CLAUDE-CODE-LEASHED.md)." \
  "$DIST"/*.tar.gz "$DIST/checksums.txt"

echo "release: done → https://github.com/$REPO/releases/tag/$TAG" >&2
