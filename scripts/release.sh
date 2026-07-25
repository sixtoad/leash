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

# The eBPF LSM bytecode (internal/lsm/*_bpf*.go, bpf2go output) is likewise
# gitignored and NOT committed, so a fresh clone can't `go build` the Linux binary
# without it. Regenerate it too — same fresh-clone-build gap as above. Prefer the
# host toolchain (fast), fall back to the Docker toolchain if clang/libbpf aren't
# usable (non-Linux, or a restricted CI box).
echo "release: generating eBPF LSM bytecode..." >&2
if ! make lsm-generate >&2; then
  echo "release: host lsm-generate unavailable; using the Docker toolchain..." >&2
  make lsm-generate-docker >&2
fi
for f in internal/lsm/lsmopen_bpfel.go internal/lsm/lsmexec_bpfel.go internal/lsm/lsmconnect_bpfel.go; do
  [ -s "$f" ] || { echo "release: $f missing after lsm-generate — bpf2go failed" >&2; exit 1; }
done

DIST="$ROOT/dist"
rm -rf "$DIST"; mkdir -p "$DIST"
COMMIT="$(git rev-parse --short=7 HEAD)"
# `leash version --json` promises that a binary built from a modified tree carries
# a "-dirty" marker instead of advertising the pristine commit it was cut from.
# Stamp it here too, or the release build would be the one path that breaks the
# promise. Loud, but not fatal: cutting a release from a dirty tree is the
# operator's call, misreporting it is not.
#
# `git diff-index` rather than `git status --porcelain`: tracked files only, the
# same test `git describe --dirty` runs, so `version` and `commit` cannot
# disagree because of an untracked file. And it fails CLOSED — a git that errors
# (index lock, corrupt index, ownership refusal) is stamped dirty, not read as
# pristine. `[ -n "$(git status --porcelain 2>/dev/null)" ]` failed open: empty
# stdout from a *failed* command is indistinguishable from a clean tree.
git update-index -q --refresh >/dev/null 2>&1 || true
dirty_rc=0
git diff-index --quiet HEAD -- >/dev/null 2>&1 || dirty_rc=$?
if [ "$dirty_rc" -ne 0 ]; then
  COMMIT="$COMMIT-dirty"
  if [ "$dirty_rc" -eq 1 ]; then
    echo "release: WARNING: working tree is modified — stamping commit as $COMMIT" >&2
  else
    echo "release: WARNING: could not read the tree state (git diff-index exit $dirty_rc); assuming modified, stamping commit as $COMMIT" >&2
  fi
fi
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
