#!/usr/bin/env bash
# Publish one coherent native Leash release: manager image first, immutable CLI
# default second, parity/E2E gate third, GitHub Release last.
set -euo pipefail

DRY_RUN=0
if [ "${1:-}" = "--dry-run" ]; then
  DRY_RUN=1
  shift
fi

TAG="${1:?usage: scripts/release.sh [--dry-run] <native-vX.Y.Z>}"
if [[ ! "$TAG" =~ ^native-v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  printf '%s\n' "release: tag must match native-vX.Y.Z, got $TAG" >&2
  exit 1
fi

REPO="${LEASH_REPO:-sixtoad/leash}"
MANAGER_REPO="${LEASH_MANAGER_REPO:-ghcr.io/sixtoad/leash-manager}"
ROOT="$(git -C "$(dirname "$0")/.." rev-parse --show-toplevel)"
cd "$ROOT"

if [ -n "$(git status --porcelain)" ]; then
  printf '%s\n' "release: working tree must be clean so CLI and manager provenance name one commit" >&2
  exit 1
fi

COMMIT="$(git rev-parse HEAD)"
DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
MANAGER_TAG="$MANAGER_REPO:$TAG"
TEMP="$(mktemp -d /tmp/leash-native-release.XXXXXX)"
cleanup() { rm -rf "$TEMP"; }
trap cleanup EXIT

for command in docker git go python3 sha256sum tar; do
  command -v "$command" >/dev/null 2>&1 || { printf '%s\n' "release: required command not found: $command" >&2; exit 1; }
done
if (( !DRY_RUN )); then
  command -v gh >/dev/null 2>&1 || { printf '%s\n' "release: required command not found: gh" >&2; exit 1; }
fi

if [ ! -s internal/ui/dist/index.html ] || grep -q '>stub<\|<title>stub' internal/ui/dist/index.html 2>/dev/null; then
  printf '%s\n' "release: internal/ui/dist is the stub — run 'make build-ui' first (needs pnpm)." >&2
  exit 1
fi

printf '%s\n' "release: generating embedded leash-entry binaries..." >&2
GOFLAGS="${GOFLAGS:-} -buildvcs=false" go generate ./internal/entrypoint/...
for file in internal/entrypoint/bundled_linux_amd64_gen.go internal/entrypoint/bundled_linux_arm64_gen.go; do
  [ -s "$file" ] || { printf '%s\n' "release: $file missing after generation" >&2; exit 1; }
done

printf '%s\n' "release: generating eBPF LSM bytecode..." >&2
if ! make lsm-generate >&2; then
  printf '%s\n' "release: host generation unavailable; using Docker toolchain..." >&2
  make lsm-generate-docker >&2
fi
for file in internal/lsm/lsmopen_bpfel.go internal/lsm/lsmexec_bpfel.go internal/lsm/lsmconnect_bpfel.go; do
  [ -s "$file" ] || { printf '%s\n' "release: $file missing after generation" >&2; exit 1; }
done

if ((DRY_RUN)); then
  LOCAL_MANAGER="leash-manager-release-test:$TAG"
  printf '%s\n' "release: building local manager fixture $LOCAL_MANAGER..." >&2
  docker build --file Dockerfile.leash --target final-prebuilt \
    --build-arg BASE_BUILD_IMAGE=build-base \
    --build-arg BASE_RUNTIME_IMAGE=runtime-base \
    --build-arg UI_SOURCE=ui-prebuilt \
    --build-arg COMMIT="$COMMIT" \
    --build-arg BUILD_DATE="$DATE" \
    --build-arg VERSION="${TAG#native-v}" \
    --build-arg CHANNEL=release \
    --build-arg GIT_REMOTE_URL="$(git config --get remote.origin.url 2>/dev/null || echo unknown)" \
    --tag "$LOCAL_MANAGER" .
  MANAGER_DIGEST="$(docker image inspect --format '{{.Id}}' "$LOCAL_MANAGER")"
  MANAGER_REF="$MANAGER_DIGEST"
else
  printf '%s\n' "release: publishing versioned manager $MANAGER_TAG without a floating tag..." >&2
  METADATA="$TEMP/manager-metadata.json"
  LEASH_IMAGE="$MANAGER_REPO" RELEASE_CHANNEL=release \
    ./build/publish-docker.sh --only-leash --no-latest --metadata-file "$METADATA" "$TAG"
  MANAGER_DIGEST="$(METADATA="$METADATA" python3 - <<'PY'
import json
import os

with open(os.environ["METADATA"], encoding="utf-8") as handle:
    metadata = json.load(handle)
print(metadata.get("containerimage.digest", ""), end="")
PY
)"
  [ -n "$MANAGER_DIGEST" ] || { printf '%s\n' "release: manager publication did not return a digest" >&2; exit 1; }
  MANAGER_REF="$MANAGER_REPO@$MANAGER_DIGEST"
  docker pull "$MANAGER_REF" >/dev/null
  gh api --method PUT "/user/packages/container/leash-manager/visibility" -f visibility=public >/dev/null
fi

LABELS="$(docker image inspect --format '{{json .Config.Labels}}' "$MANAGER_REF")"
LABELS="$LABELS" COMMIT="$COMMIT" python3 - <<'PY'
import json
import os

labels = json.loads(os.environ["LABELS"])
required = {
    "org.opencontainers.image.revision": os.environ["COMMIT"],
    "io.leash.manager.contract.version": "1",
    "io.leash.manager.contract.min-compatible": "1",
}
for key, expected in required.items():
    if labels.get(key) != expected:
        raise SystemExit(f"manager label {key}: {labels.get(key)!r} != {expected!r}")
PY

DIST="$ROOT/dist"
rm -rf "$DIST"
mkdir -p "$DIST"
for pair in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do
  os="${pair%/*}"
  arch="${pair#*/}"
  printf '%s\n' "release: building $os/$arch..." >&2
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -buildvcs=false -trimpath \
    -ldflags "-X main.version=$TAG -X main.commit=$COMMIT -X main.buildDate=$DATE -X main.managerImage=$MANAGER_REF -X main.managerRevision=$COMMIT -X main.managerContract=1" \
    -o "$DIST/leash" ./cmd/leash
  BUILD_INFO="$(go version -m "$DIST/leash")"
  case "$BUILD_INFO" in
    *"main.commit=$COMMIT"*"main.managerImage=$MANAGER_REF"*) ;;
    *) printf '%s\n' "release: $os/$arch build metadata does not match manager provenance" >&2; exit 1 ;;
  esac
  tar -C "$DIST" -czf "$DIST/leash_${os}_${arch}.tar.gz" leash
  rm -f "$DIST/leash"
done
(cd "$DIST" && sha256sum ./*.tar.gz > checksums.txt)

case "$(uname -m)" in
  x86_64) HOST_ARCH=amd64 ;;
  aarch64|arm64) HOST_ARCH=arm64 ;;
  *) printf '%s\n' "release: unsupported E2E host architecture $(uname -m)" >&2; exit 1 ;;
esac
tar -C "$TEMP" -xzf "$DIST/leash_linux_${HOST_ARCH}.tar.gz"
chmod +x "$TEMP/leash"
"$ROOT/scripts/verify-native-release.sh" "$TEMP/leash" "$MANAGER_REF" "$COMMIT"

if ((DRY_RUN)); then
  printf '%s\n' "release: dry-run verified manager $MANAGER_TAG ($MANAGER_REF) and all CLI archives; no release was published" >&2
  exit 0
fi

printf '%s\n' "release: publishing $TAG to $REPO only after manager, archive, and E2E verification..." >&2
gh release create "$TAG" --repo "$REPO" --target "$COMMIT" --title "$TAG" --notes "\
Leash native release from commit \`$COMMIT\`.

- Manager tag: \`$MANAGER_TAG\`
- Manager digest: \`$MANAGER_DIGEST\`
- CLI default: \`$MANAGER_REF\`
- Manager contract: \`1\`
- Linux binaries are fully enforcing; macOS binaries drive an installed Leash.app.

The release gate executed the archived Linux CLI with no manager override, the exact Walk #33 combined policy, a named non-root target, and fail-closed LSM enforcement." \
  "$DIST"/*.tar.gz "$DIST/checksums.txt"

printf '%s\n' "release: done → https://github.com/$REPO/releases/tag/$TAG" >&2
