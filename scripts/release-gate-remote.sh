#!/usr/bin/env bash
# Remote kernel-gate helpers for scripts/release.sh. This file is sourced;
# callers retain `set -euo pipefail` policy.
#
# The release gates that need a kernel with the BPF LSM active (the host-kernel
# load of the CLI-embedded LSM objects and the archived-CLI fail-closed E2E)
# can run on a separate gate host instead of the build host:
#
#   LEASH_RELEASE_GATE_SSH=[user@]host[:port]   gate host reached over SSH
#   LEASH_RELEASE_GATE_SSH_CONFIG=<file>        optional ssh_config(5) (-F)
#
# Everything else (generation, builds, publication, release creation) stays on
# the build host. The exact artifacts are copied to the gate host, their
# sha256 is re-checked there before use, and the gate scripts come from a
# `git archive` of the release commit, so the gate host verifies exactly what
# is shipped. The gate host needs rootful Docker usable by the SSH user,
# python3, git, tar, sha256sum, timeout, and the same CPU architecture.

RELEASE_GATE_DEST=""
RELEASE_GATE_PORT=""
RELEASE_GATE_DIR=""
RELEASE_GATE_SSH_OPTS=()

release_gate_configure() {
  local spec="$1"
  if [[ ! "$spec" =~ ^([A-Za-z0-9_][A-Za-z0-9._-]*@)?[A-Za-z0-9][A-Za-z0-9._-]*(:[0-9]+)?$ ]]; then
    printf '%s\n' "release: LEASH_RELEASE_GATE_SSH must be [user@]host[:port], got '$spec'" >&2
    return 1
  fi
  RELEASE_GATE_DEST="${spec%%:*}"
  if [[ "$spec" == *:* ]]; then
    RELEASE_GATE_PORT="${spec##*:}"
  fi
  RELEASE_GATE_SSH_OPTS=(-o BatchMode=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=10)
  if [ -n "${LEASH_RELEASE_GATE_SSH_CONFIG:-}" ]; then
    [ -r "$LEASH_RELEASE_GATE_SSH_CONFIG" ] || {
      printf '%s\n' "release: LEASH_RELEASE_GATE_SSH_CONFIG $LEASH_RELEASE_GATE_SSH_CONFIG is not readable" >&2
      return 1
    }
    RELEASE_GATE_SSH_OPTS=(-F "$LEASH_RELEASE_GATE_SSH_CONFIG" "${RELEASE_GATE_SSH_OPTS[@]}")
  fi
  command -v ssh >/dev/null 2>&1 || { printf '%s\n' "release: required command not found: ssh" >&2; return 1; }
  command -v scp >/dev/null 2>&1 || { printf '%s\n' "release: required command not found: scp" >&2; return 1; }
}

release_gate_ssh() {
  ssh "${RELEASE_GATE_SSH_OPTS[@]}" ${RELEASE_GATE_PORT:+-p "$RELEASE_GATE_PORT"} "$RELEASE_GATE_DEST" "$@"
}

release_gate_put() {
  local source="$1" destination="$2"
  scp -q "${RELEASE_GATE_SSH_OPTS[@]}" ${RELEASE_GATE_PORT:+-P "$RELEASE_GATE_PORT"} \
    "$source" "$RELEASE_GATE_DEST:$destination"
}

# Quote every argument for the remote shell.
release_gate_quote() {
  local quoted="" arg
  for arg in "$@"; do
    quoted+="$(printf '%q' "$arg") "
  done
  printf '%s' "${quoted% }"
}

# Prepare a fresh staging directory on the gate host holding the gate scripts
# and fixtures from the release commit, after checking the host's architecture
# and that bpf is in its active LSM list.
release_gate_init() {
  local release_root="$1" commit="$2" host_arch="$3"
  local remote_machine remote_arch remote_lsm
  printf '%s\n' "release: preparing remote kernel gate host $RELEASE_GATE_DEST${RELEASE_GATE_PORT:+ (port $RELEASE_GATE_PORT)}..." >&2
  remote_machine="$(release_gate_ssh uname -m)" || {
    printf '%s\n' "release: cannot reach remote gate host $RELEASE_GATE_DEST" >&2
    return 1
  }
  case "$remote_machine" in
    x86_64) remote_arch=amd64 ;;
    aarch64|arm64) remote_arch=arm64 ;;
    *) remote_arch="$remote_machine" ;;
  esac
  if [ "$remote_arch" != "$host_arch" ]; then
    printf '%s\n' "release: remote gate host is $remote_arch, build host is $host_arch; they must match" >&2
    return 1
  fi
  remote_lsm="$(release_gate_ssh cat /sys/kernel/security/lsm)" || return 1
  printf '%s\n' "release: remote gate kernel $(release_gate_ssh uname -r), active LSMs: $remote_lsm" >&2
  case ",$remote_lsm," in
    *,bpf,*) ;;
    *)
      printf '%s\n' "release: remote gate host does not have the BPF LSM active (boot it with lsm=...,bpf)" >&2
      return 1
      ;;
  esac
  RELEASE_GATE_DIR="$(release_gate_ssh mktemp -d /tmp/leash-release-gate.XXXXXX)" || return 1
  [[ "$RELEASE_GATE_DIR" == /tmp/leash-release-gate.* ]] || {
    printf '%s\n' "release: unexpected remote staging directory '$RELEASE_GATE_DIR'" >&2
    return 1
  }
  # The gate scripts locate their repository root with git, so the staging
  # directory is an (empty) repository holding the release commit's files.
  git -C "$release_root" archive --format=tar "$commit" scripts e2e/testdata |
    release_gate_ssh "$(release_gate_quote tar -x -C "$RELEASE_GATE_DIR") && $(release_gate_quote git init -q "$RELEASE_GATE_DIR")"
}

release_gate_cleanup() {
  if [ -n "$RELEASE_GATE_DIR" ]; then
    release_gate_ssh "$(release_gate_quote rm -rf "$RELEASE_GATE_DIR")" >/dev/null 2>&1 || true
    RELEASE_GATE_DIR=""
  fi
}

# Copy a file to the staging directory and prove it arrived byte-identical.
release_gate_put_verified() {
  local source="$1" name="$2" sum
  sum="$(sha256sum "$source")"
  sum="${sum%% *}"
  release_gate_put "$source" "$RELEASE_GATE_DIR/$name"
  release_gate_ssh "cd $(release_gate_quote "$RELEASE_GATE_DIR") && printf '%s  %s\n' $(release_gate_quote "$sum" "$name") | sha256sum -c --quiet -" || {
    printf '%s\n' "release: $name changed in transit to the remote gate host" >&2
    return 1
  }
}

# Remote host-kernel load of the CLI-embedded LSM objects. The test binary is
# built here from the pinned objects (go:embed stores them verbatim), checked
# to contain each object byte-for-byte, and loaded there with no inert escape.
release_gate_kernel_load() {
  local verify_script="$1" temp="$2"
  shift 2
  local binary="$temp/lsm-kernel-load.test" object checked=0
  "$verify_script" --build-only "$binary"
  for object in "$@"; do
    # bpf2go embeds only the build target's endianness; every release
    # architecture (amd64, arm64) is little-endian.
    [[ "$object" == *_bpfel.o ]] || continue
    checked=$((checked + 1))
    BINARY="$binary" OBJECT="$object" python3 - <<'PY'
import os

with open(os.environ["BINARY"], "rb") as handle:
    binary = handle.read()
with open(os.environ["OBJECT"], "rb") as handle:
    obj = handle.read()
if not obj or obj not in binary:
    raise SystemExit(f"release: kernel-load test binary does not embed {os.environ['OBJECT']} byte-for-byte")
PY
  done
  if [ "$checked" -ne 3 ]; then
    printf '%s\n' "release: expected 3 little-endian LSM objects to check, got $checked" >&2
    return 1
  fi
  release_gate_put_verified "$binary" lsm-kernel-load.test
  release_gate_ssh_timeout 15m \
    "cd $(release_gate_quote "$RELEASE_GATE_DIR") && env -u LEASH_KERNEL_LOAD_ALLOW_INERT timeout 10m scripts/verify-lsm-kernel-load.sh --test-binary $(release_gate_quote "$RELEASE_GATE_DIR/lsm-kernel-load.test")"
}

# Remote archived-CLI E2E. A local-only manager image (dry run or the
# pre-publication load candidate) is copied over and must keep its image ID;
# a registry reference is pulled by digest on the gate host.
release_gate_native_release() {
  local binary="$1" manager_ref="$2" revision="$3" local_image="$4" gate_timeout="$5"
  local name local_id remote_id
  name="leash-$(basename "$binary")"
  release_gate_put_verified "$binary" "$name"
  if [ -n "$local_image" ]; then
    local_id="$(docker image inspect --format '{{.Id}}' "$local_image")"
    printf '%s\n' "release: copying local manager $local_image ($local_id) to the remote gate host..." >&2
    docker save "$local_image" | release_gate_ssh docker load >/dev/null
    remote_id="$(release_gate_ssh "$(release_gate_quote docker image inspect --format '{{.Id}}' "$local_image")")"
    if [ "$remote_id" != "$local_id" ]; then
      printf '%s\n' "release: manager image ID changed on the remote gate host ($local_id -> $remote_id)" >&2
      return 1
    fi
  else
    release_gate_ssh "$(release_gate_quote timeout 5m docker pull "$manager_ref")" >/dev/null
  fi
  release_gate_ssh_timeout 20m \
    "cd $(release_gate_quote "$RELEASE_GATE_DIR") && chmod 0755 $(release_gate_quote "$name") && env -u LEASH_IMAGE -u LEASH_RELEASE_TARGET_IMAGE timeout $(release_gate_quote "$gate_timeout") scripts/verify-native-release.sh $(release_gate_quote "$RELEASE_GATE_DIR/$name" "$manager_ref" "$revision")"
}

# Bound the whole remote call on the build host as well as remotely.
release_gate_ssh_timeout() {
  local limit="$1"
  shift
  timeout "$limit" ssh "${RELEASE_GATE_SSH_OPTS[@]}" ${RELEASE_GATE_PORT:+-p "$RELEASE_GATE_PORT"} "$RELEASE_GATE_DEST" "$@"
}
