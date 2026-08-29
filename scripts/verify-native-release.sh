#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git -C "$(dirname "$0")/.." rev-parse --show-toplevel)"
BIN="${1:?usage: verify-native-release.sh <leash-binary> <manager-ref> <revision>}"
MANAGER_REF="${2:?usage: verify-native-release.sh <leash-binary> <manager-ref> <revision>}"
REVISION="${3:?usage: verify-native-release.sh <leash-binary> <manager-ref> <revision>}"
TARGET_IMAGE="${LEASH_RELEASE_TARGET_IMAGE:-leash-release-target:test}"
POLICY="$ROOT/e2e/testdata/walk33-combined.cedar"
CONTAINER="leash-release-parity-$$"
WORKDIR="$(mktemp -d /tmp/leash-release-parity.XXXXXX)"

cleanup() {
  docker rm -f "$CONTAINER" "$CONTAINER-leash" >/dev/null 2>&1 || true
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

test -x "$BIN"
test -s "$POLICY"

VERSION_JSON="$($BIN version --json)"
VERSION_JSON="$VERSION_JSON" REVISION="$REVISION" python3 - <<'PY'
import json
import os

document = json.loads(os.environ["VERSION_JSON"])
reported_revision = document.get("sourceRevision", "")
if reported_revision != os.environ["REVISION"]:
    raise SystemExit(
        f"released CLI revision mismatch: {reported_revision!r} != {os.environ['REVISION']!r}"
    )
PY

HELP="$($BIN --help 2>&1)"
case "$HELP" in
  *"defaults to $MANAGER_REF"*) ;;
  *) printf '%s\n' "released CLI does not advertise immutable default $MANAGER_REF" >&2; exit 1 ;;
esac

LABELS="$(docker image inspect --format '{{json .Config.Labels}}' "$MANAGER_REF")"
LABELS="$LABELS" REVISION="$REVISION" python3 - <<'PY'
import json
import os

labels = json.loads(os.environ["LABELS"])
required = {
    "org.opencontainers.image.revision": os.environ["REVISION"],
    "io.leash.manager.contract.version": "1",
    "io.leash.manager.contract.min-compatible": "1",
}
for key, expected in required.items():
    if labels.get(key) != expected:
        raise SystemExit(f"manager label {key}: {labels.get(key)!r} != {expected!r}")
PY

if [ -z "${LEASH_RELEASE_TARGET_IMAGE:-}" ]; then
  docker build -t "$TARGET_IMAGE" -f "$ROOT/e2e/testdata/release-target/Dockerfile" "$ROOT/e2e/testdata/release-target"
fi

(
  cd "$WORKDIR"
  unset LEASH_IMAGE
  LEASH_HOME="$WORKDIR/home" \
  LEASH_WORK_DIR="$WORKDIR/work" \
  LEASH_LISTEN= \
  timeout 180 "$BIN" --runtime docker --require-lsm --no-interactive \
    --image "$TARGET_IMAGE" --policy "$POLICY" --container-name "$CONTAINER" \
    sh -lc "printf 'LEASH84_USER='; id -un"
) | tee "$WORKDIR/output"

grep -q '^LEASH84_USER=agent$' "$WORKDIR/output"
for name in "$CONTAINER" "$CONTAINER-leash"; do
  if docker inspect "$name" >/dev/null 2>&1; then
    printf '%s\n' "release parity E2E left container $name behind" >&2
    exit 1
  fi
done
