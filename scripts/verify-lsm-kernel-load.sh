#!/usr/bin/env bash
# Ask the host kernel's verifier to load and attach the eBPF LSM objects that
# are currently generated in internal/lsm -- the exact objects `go build`
# embeds into the leash CLI -- with a policy that has open, exec and connect
# rules (issue #110), plus file-policy rules longer than 64 bytes whose permit,
# forbid, mutation and hard-link outcomes are asserted (issues #108/#109).
# Each module is only loaded when the policy has rules for
# it, so a policy without an exec rule never sends lsm_exec to the verifier.
#
# The compiled test binary runs inside a privileged, --cgroupns=host container
# so no host sudo is needed; rootful Docker supplies CAP_BPF/CAP_SYS_ADMIN.
set -euo pipefail

ROOT="$(git -C "$(dirname "$0")/.." rev-parse --show-toplevel)"
IMAGE="${LEASH_KERNEL_LOAD_IMAGE:-debian:bookworm-slim}"
CONTAINER="leash-lsm-kernel-load-$$"
WORKDIR="$(mktemp -d /tmp/leash-lsm-kernel-load.XXXXXX)"

cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

case "$(uname -m)" in
  x86_64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) printf '%s\n' "verify-lsm-kernel-load: unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac

for file in lsmopen lsmexec lsmconnect; do
  for endian in bpfel bpfeb; do
    for ext in go o; do
      [ -s "$ROOT/internal/lsm/${file}_${endian}.${ext}" ] || {
        printf '%s\n' "verify-lsm-kernel-load: internal/lsm/${file}_${endian}.${ext} missing; run make lsm-generate" >&2
        exit 1
      }
    done
  done
done

(
  cd "$ROOT"
  CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go test -buildvcs=false -c \
    -o "$WORKDIR/lsm.test" ./internal/lsm
)

# Expose tracefs so the exec argv tracepoint attaches as it does in a real run.
TRACEFS=()
if [ -d /sys/kernel/tracing ]; then
  TRACEFS=(-v /sys/kernel/tracing:/sys/kernel/tracing)
fi

printf '%s\n' "verify-lsm-kernel-load: loading lsm_open/lsm_exec/lsm_connect on kernel $(uname -r)..." >&2
docker run --rm --name "$CONTAINER" \
  --privileged --cgroupns=host "${TRACEFS[@]}" \
  -e LEASH_LSM_KERNEL_LOAD_VALIDATION=1 \
  -v "$WORKDIR/lsm.test:/lsm.test:ro" \
  "$IMAGE" /lsm.test -test.v -test.count=1 \
  -test.run '^TestKernelLoadAllModulesWithExecRule$' | tee "$WORKDIR/output"

# A renamed or skipped test must not pass the gate vacuously.
grep -q -- '^--- PASS: TestKernelLoadAllModulesWithExecRule' "$WORKDIR/output" || {
  printf '%s\n' "verify-lsm-kernel-load: kernel load validation did not run and pass" >&2
  exit 1
}
