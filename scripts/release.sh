#!/usr/bin/env bash
# Publish one coherent native Leash release: manager image first, immutable CLI
# default second, parity/E2E gate third, GitHub Release last.
set -euo pipefail

DRY_RUN=0
RESUME_EXISTING_MANAGER=0
RELEASE_SOURCE_OVERRIDE=""
while [[ "${1:-}" == --* ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1 ;;
    --resume-existing-manager) RESUME_EXISTING_MANAGER=1 ;;
    --release-source-root)
      [ "$#" -ge 2 ] || { printf '%s\n' "release: --release-source-root requires a path" >&2; exit 1; }
      RELEASE_SOURCE_OVERRIDE="$2"
      shift
      ;;
    *) printf '%s\n' "release: unknown option $1" >&2; exit 1 ;;
  esac
  shift
done

TAG="${1:?usage: scripts/release.sh [--dry-run] [--resume-existing-manager --release-source-root <path>] <native-vX.Y.Z>}"
if [ "$#" -ne 1 ]; then
  printf '%s\n' "release: usage: scripts/release.sh [--dry-run] [--resume-existing-manager --release-source-root <path>] <native-vX.Y.Z>" >&2
  exit 1
fi
if [[ ! "$TAG" =~ ^native-v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  printf '%s\n' "release: tag must match native-vX.Y.Z, got $TAG" >&2
  exit 1
fi

REPO="${LEASH_REPO:-sixtoad/leash}"
MANAGER_REPO="ghcr.io/sixtoad/leash-manager"
MANAGER_OWNER="${MANAGER_REPO#ghcr.io/}"
MANAGER_OWNER="${MANAGER_OWNER%%/*}"
MANAGER_PACKAGE="${MANAGER_REPO##*/}"
TOOL_ROOT="$(git -C "$(dirname "$0")/.." rev-parse --show-toplevel)"
source "$TOOL_ROOT/scripts/native-release-remote.sh"
MANAGER_VERSION="$(native_manager_version "$TAG")" || exit 1
RELEASE_ROOT="$(native_release_source_root "$TOOL_ROOT" "$RELEASE_SOURCE_OVERRIDE" "$RESUME_EXISTING_MANAGER")" || exit 1
cd "$RELEASE_ROOT"

if ((DRY_RUN && RESUME_EXISTING_MANAGER)); then
  printf '%s\n' "release: --resume-existing-manager cannot be combined with --dry-run" >&2
  exit 1
fi

if [ -n "$(git -C "$TOOL_ROOT" status --porcelain --untracked-files=all)" ]; then
  printf '%s\n' "release: recovery tooling checkout must be clean" >&2
  exit 1
fi

COMMIT="$(git -C "$RELEASE_ROOT" rev-parse HEAD)"
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
  REMOTE_MODE="$(native_remote_mode "$TEMP" "$REPO" "$MANAGER_OWNER" \
    "$MANAGER_PACKAGE" "$TAG" "$RESUME_EXISTING_MANAGER")" || exit 1
else
  REMOTE_MODE=dry-run
fi

if [ ! -s internal/ui/dist/index.html ] || grep -q '>stub<\|<title>stub' internal/ui/dist/index.html 2>/dev/null; then
  printf '%s\n' "release: internal/ui/dist is the stub — run 'make build-ui' first (needs pnpm)." >&2
  exit 1
fi

if [ "$REMOTE_MODE" != resume ]; then
  printf '%s\n' "release: generating embedded leash-entry binaries..." >&2
  GOFLAGS="${GOFLAGS:-} -buildvcs=false" go generate ./internal/entrypoint/...
fi
for file in internal/entrypoint/bundled_linux_amd64_gen.go internal/entrypoint/bundled_linux_arm64_gen.go; do
  [ -s "$file" ] || { printf '%s\n' "release: $file missing after generation" >&2; exit 1; }
done

if [ "$REMOTE_MODE" != resume ]; then
  printf '%s\n' "release: generating eBPF LSM bytecode..." >&2
  if ! make lsm-generate >&2; then
    printf '%s\n' "release: host generation unavailable; using Docker toolchain..." >&2
    make lsm-generate-docker >&2
  fi
fi
for file in \
  internal/lsm/lsmopen_bpfeb.go internal/lsm/lsmopen_bpfeb.o \
  internal/lsm/lsmopen_bpfel.go internal/lsm/lsmopen_bpfel.o \
  internal/lsm/lsmexec_bpfeb.go internal/lsm/lsmexec_bpfeb.o \
  internal/lsm/lsmexec_bpfel.go internal/lsm/lsmexec_bpfel.o \
  internal/lsm/lsmconnect_bpfeb.go internal/lsm/lsmconnect_bpfeb.o \
  internal/lsm/lsmconnect_bpfel.go internal/lsm/lsmconnect_bpfel.o; do
  [ -s "$file" ] || { printf '%s\n' "release: $file missing after generation" >&2; exit 1; }
done

MANAGER_BUILD_ARGS=(
  --file Dockerfile.leash --target final-prebuilt
  --build-arg BASE_BUILD_IMAGE=build-base
  --build-arg BASE_RUNTIME_IMAGE=runtime-base
  --build-arg UI_SOURCE=ui-prebuilt
  --build-arg COMMIT="$COMMIT"
  --build-arg BUILD_DATE="$DATE"
  --build-arg VERSION="$MANAGER_VERSION"
  --build-arg CHANNEL=release
  --build-arg GIT_REMOTE_URL="$(git config --get remote.origin.url 2>/dev/null || echo unknown)"
)

# Validate the exact multi-platform graph, child architectures, labels, and
# digests before a fresh immutable registry name exists. A recovery instead
# validates the already-published index and never invokes a manager build/push.
PREFLIGHT_OCI="$TEMP/manager-preflight.oci.tar"
HAS_BUILDX=0
if docker buildx version >/dev/null 2>&1; then
  HAS_BUILDX=1
  if [ "$REMOTE_MODE" != resume ]; then
    printf '%s\n' "release: verifying local multi-arch manager before publication..." >&2
    timeout 10m docker buildx build \
      --platform linux/amd64,linux/arm64 \
      --output "type=oci,dest=$PREFLIGHT_OCI" \
      "${MANAGER_BUILD_ARGS[@]}" .
    python3 "$TOOL_ROOT/scripts/verify-manager-manifest.py" oci "$PREFLIGHT_OCI" \
      --revision "$COMMIT" --version "${TAG#native-v}" --channel release
  fi
elif (( !DRY_RUN )); then
  printf '%s\n' "release: Docker Buildx is required for multi-arch publication" >&2
  exit 1
else
  printf '%s\n' "release: Docker Buildx unavailable; Podman dry-run will verify the host fixture only" >&2
fi

publish_fresh_manager() {
  native_require_release_names_absent "$TEMP" "$REPO" "$TAG"
  native_require_manager_absent "$TEMP" "$MANAGER_OWNER" "$MANAGER_PACKAGE" "$TAG"
  printf '%s\n' "release: publishing versioned manager $MANAGER_TAG without a floating tag..." >&2
  METADATA="$TEMP/manager-metadata.json"
  (
    unset LEASH_SOURCE_IMAGE ECR_LEASH_IMAGE EXTRA_LEASH_IMAGES
    LEASH_IMAGE="$MANAGER_REPO" RELEASE_CHANNEL=release \
      ./build/publish-docker.sh --only-leash --no-latest --metadata-file "$METADATA" "$MANAGER_VERSION"
  )
  MANAGER_DIGEST="$(METADATA="$METADATA" python3 - <<'PY'
import json
import os

with open(os.environ["METADATA"], encoding="utf-8") as handle:
    metadata = json.load(handle)
print(metadata.get("containerimage.digest", ""), end="")
PY
)"
  [ -n "$MANAGER_DIGEST" ] || { printf '%s\n' "release: manager publication did not return a digest" >&2; return 1; }
}

resume_existing_manager() {
  printf '%s\n' "release: safely resuming from existing manager $MANAGER_TAG without build or push..." >&2
  TAG_MANIFEST="$TEMP/manager-tag.json"
  MANAGER_DIGEST="$(native_resolve_manager_digest "$MANAGER_TAG" "$TAG_MANIFEST")" || return 1
}

if ((DRY_RUN)); then
  LOCAL_MANAGER="localhost/leash-manager-release-test:$TAG"
  printf '%s\n' "release: building local manager fixture $LOCAL_MANAGER..." >&2
  BUILD_ARGS=("${MANAGER_BUILD_ARGS[@]}" --tag "$LOCAL_MANAGER" .)
  if ((HAS_BUILDX)); then
    docker buildx build --load "${BUILD_ARGS[@]}"
  else
    command -v podman >/dev/null 2>&1 || { printf '%s\n' "release: dry-run requires Docker Buildx or Podman" >&2; exit 1; }
    podman build --format docker "${BUILD_ARGS[@]}"
    podman save --format docker-archive --output "$TEMP/manager.tar" "$LOCAL_MANAGER"
    docker load --input "$TEMP/manager.tar" >/dev/null
  fi
  MANAGER_DIGEST="$(docker image inspect --format '{{.Id}}' "$LOCAL_MANAGER")"
  MANAGER_REF="$MANAGER_DIGEST"
else
  native_execute_manager_mode "$REMOTE_MODE" publish_fresh_manager resume_existing_manager
fi

if (( !DRY_RUN )); then
  MANAGER_REF="$MANAGER_REPO@$MANAGER_DIGEST"
  MANAGER_INDEX="$TEMP/manager-index.json"
  MANAGER_IMAGE_AMD64="$TEMP/manager-image-amd64.json"
  MANAGER_IMAGE_ARM64="$TEMP/manager-image-arm64.json"
  timeout 2m docker buildx imagetools inspect --raw "$MANAGER_REF" >"$MANAGER_INDEX"
  MANAGER_DIGEST_AMD64="$(python3 "$TOOL_ROOT/scripts/verify-manager-manifest.py" descriptor \
    "$MANAGER_INDEX" --os linux --arch amd64)"
  MANAGER_DIGEST_ARM64="$(python3 "$TOOL_ROOT/scripts/verify-manager-manifest.py" descriptor \
    "$MANAGER_INDEX" --os linux --arch arm64)"
  timeout 2m docker buildx imagetools inspect \
    --format '{{json .Image}}' "$MANAGER_REPO@$MANAGER_DIGEST_AMD64" >"$MANAGER_IMAGE_AMD64"
  timeout 2m docker buildx imagetools inspect \
    --format '{{json .Image}}' "$MANAGER_REPO@$MANAGER_DIGEST_ARM64" >"$MANAGER_IMAGE_ARM64"
  python3 "$TOOL_ROOT/scripts/verify-manager-manifest.py" registry "$MANAGER_INDEX" \
    --image-amd64 "$MANAGER_IMAGE_AMD64" --image-arm64 "$MANAGER_IMAGE_ARM64" \
    --revision "$COMMIT" --digest "$MANAGER_DIGEST" \
    --version "$MANAGER_VERSION" --channel release
  timeout 2m docker pull "$MANAGER_REF" >/dev/null
  native_require_release_names_absent "$TEMP" "$REPO" "$TAG"
  native_require_manager_public "$TEMP" "$MANAGER_OWNER" "$MANAGER_PACKAGE" "$TAG" "$RELEASE_ROOT"
  mkdir -p "$TEMP/anonymous-docker"
  if ! DOCKER_CONFIG="$TEMP/anonymous-docker" timeout 2m docker pull "$MANAGER_REF" >/dev/null; then
    printf '%s\n' "release: anonymous pull failed for public manager digest $MANAGER_REF" >&2
    exit 1
  fi
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

DIST="$TEMP/dist"
mkdir -p "$DIST"
for pair in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do
  os="${pair%/*}"
  arch="${pair#*/}"
  printf '%s\n' "release: building $os/$arch..." >&2
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -buildvcs=false -trimpath \
    -ldflags "-X main.version=$TAG -X main.commit=$COMMIT -X main.buildDate=$DATE -X main.managerImage=$MANAGER_REF -X main.managerRevision=$COMMIT -X main.managerContract=1" \
    -o "$DIST/leash" ./cmd/leash
  grep -aFq "$COMMIT" "$DIST/leash" || {
    printf '%s\n' "release: $os/$arch archive does not contain the stamped full revision" >&2
    exit 1
  }
  grep -aFq "$MANAGER_REF" "$DIST/leash" || {
    printf '%s\n' "release: $os/$arch archive does not contain the immutable manager default" >&2
    exit 1
  }
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
"$RELEASE_ROOT/scripts/verify-native-release.sh" "$TEMP/leash" "$MANAGER_REF" "$COMMIT"

if ((DRY_RUN)); then
  printf '%s\n' "release: dry-run verified manager $MANAGER_TAG ($MANAGER_REF) and all CLI archives; no release was published" >&2
  exit 0
fi

native_require_release_names_absent "$TEMP" "$REPO" "$TAG"
native_assert_manager_digest "$MANAGER_TAG" "$MANAGER_DIGEST" "$TEMP/manager-final-tag.json"
native_assert_release_source "$RELEASE_ROOT" "$COMMIT"
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
