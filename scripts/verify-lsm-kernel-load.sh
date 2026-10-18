#!/usr/bin/env bash
# Ask the host kernel's verifier to load and attach the eBPF LSM objects that
# are currently generated in internal/lsm -- the exact objects `go build`
# embeds into the leash CLI -- with a policy that has open, exec and connect
# rules (issue #110), plus file-policy rules longer than 64 bytes whose permit,
# forbid, mutation and hard-link outcomes are asserted (issues #108/#109), and
# container-mode writes to the container's own overlay rootfs, which must obey
# default deny and forbids like any other path (issues #186/#125).
# Each module is only loaded when the policy has rules for
# it, so a policy without an exec rule never sends lsm_exec to the verifier.
#
# The compiled test binary runs inside a privileged, --cgroupns=host container
# so no host sudo is needed; rootful Docker supplies CAP_BPF/CAP_SYS_ADMIN.
#
# Usage:
#   verify-lsm-kernel-load.sh                      build the test binary, then load
#   verify-lsm-kernel-load.sh --build-only <out>   only build the test binary
#   verify-lsm-kernel-load.sh --test-binary <bin>  only load a binary built by
#                                                  --build-only (release gate on
#                                                  a remote kernel host)
set -euo pipefail

MODE=all
BINARY_ARG=""
case "${1:-}" in
  "") ;;
  --build-only|--test-binary)
    [ "$#" -eq 2 ] && [ -n "$2" ] || { printf '%s\n' "verify-lsm-kernel-load: $1 requires a path" >&2; exit 1; }
    MODE="${1#--}"
    BINARY_ARG="$2"
    ;;
  *) printf '%s\n' "verify-lsm-kernel-load: unknown argument $1" >&2; exit 1 ;;
esac

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

TEST_BINARY="$WORKDIR/lsm.test"
if [ "$MODE" = test-binary ]; then
  [ -f "$BINARY_ARG" ] && [ -s "$BINARY_ARG" ] || {
    printf '%s\n' "verify-lsm-kernel-load: test binary $BINARY_ARG missing" >&2
    exit 1
  }
  cp "$BINARY_ARG" "$TEST_BINARY"
  chmod 0755 "$TEST_BINARY"
else
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
      -o "$TEST_BINARY" ./internal/lsm
  )
  if [ "$MODE" = build-only ]; then
    cp "$TEST_BINARY" "$BINARY_ARG"
    exit 0
  fi
fi

# Expose tracefs so the exec argv tracepoint attaches as it does in a real run.
TRACEFS=()
if [ -d /sys/kernel/tracing ]; then
  TRACEFS=(-v /sys/kernel/tracing:/sys/kernel/tracing)
fi
# Expose securityfs so the test can read the active LSM list.
if [ -r /sys/kernel/security/lsm ]; then
  TRACEFS+=(-v /sys/kernel/security:/sys/kernel/security:ro)
  printf '%s\n' "verify-lsm-kernel-load: active LSMs: $(cat /sys/kernel/security/lsm)" >&2
fi

printf '%s\n' "verify-lsm-kernel-load: loading lsm_open/lsm_exec/lsm_connect on kernel $(uname -r)..." >&2
docker run --rm --name "$CONTAINER" \
  --privileged --cgroupns=host "${TRACEFS[@]}" \
  -e LEASH_LSM_KERNEL_LOAD_VALIDATION=1 \
  -v "$TEST_BINARY:/lsm.test:ro" \
  "$IMAGE" /lsm.test -test.v -test.count=1 \
  -test.run '^TestKernelLoadAllModulesWithExecRule$' | tee "$WORKDIR/output"

# A renamed or skipped test must not pass the gate vacuously.
if grep -q -- '^--- PASS: TestKernelLoadAllModulesWithExecRule' "$WORKDIR/output"; then
  exit 0
fi

# CI only (never the release gate): on a kernel with CONFIG_BPF_LSM but without
# bpf in the active LSM list, the test verifies and attaches every program and
# then skips its enforcement checks with an LSM-INERT marker. Accept exactly
# that skip, and only after the verify and attach lines were logged.
if [ "${LEASH_KERNEL_LOAD_ALLOW_INERT:-}" = 1 ] &&
  grep -q -- '^--- SKIP: TestKernelLoadAllModulesWithExecRule' "$WORKDIR/output" &&
  grep -q -- 'LSM-INERT: verified and attached' "$WORKDIR/output" &&
  grep -q -- 'lsm_open, lsm_exec and lsm_connect loaded and attached' "$WORKDIR/output"; then
  for object in lsm_open lsm_exec lsm_connect; do
    grep -q -- "$object object verified" "$WORKDIR/output" || {
      printf '%s\n' "verify-lsm-kernel-load: $object verification line missing" >&2
      exit 1
    }
  done
  printf '%s\n' "verify-lsm-kernel-load: verified and attached; enforcement not checked (bpf not in the active LSM list)" >&2
  exit 0
fi

printf '%s\n' "verify-lsm-kernel-load: kernel load validation did not run and pass" >&2
exit 1
