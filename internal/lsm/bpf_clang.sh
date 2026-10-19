#!/usr/bin/env bash
# The one clang major leash's eBPF LSM objects are generated with (#227).
#
# Objects from a different clang can fail the kernel verifier even though they
# compile: Debian bookworm's clang 14 (what the golang:1.25 image installs)
# produces lsm_rename_* programs that 6.8 rejects ("verifier bug"), while
# Ubuntu noble's clang 18 -- what the CI and release runners use -- loads.
# `go generate ./internal/lsm` runs this before bpf2go, so every generation
# path (make lsm-generate[-docker], Dockerfile.leash, the release script, CI)
# fails loudly on the wrong toolchain instead of shipping objects that fail
# closed on the host.
#
# Prints the clang for bpf2go after checking it is clang $REQUIRED_MAJOR:
# clang-$REQUIRED_MAJOR when installed, else clang. BPF2GO_CC overrides the
# choice, never the check.
set -euo pipefail

# Keep in step with Dockerfile.leash (bpf-toolchain), .github/workflows/ci.yml
# (BPF_CLANG_MAJOR) and docs/DEVELOPMENT.md.
REQUIRED_MAJOR=18

fail() {
  printf 'bpf_clang: %s\n' "$*" >&2
  printf 'bpf_clang: leash eBPF objects must be generated with clang %s (see docs/DEVELOPMENT.md, "eBPF toolchain").\n' "$REQUIRED_MAJOR" >&2
  exit 1
}

[ "$#" -eq 0 ] || fail "unexpected argument $1"

cc="${BPF2GO_CC:-}"
if [ -z "$cc" ]; then
  if command -v "clang-$REQUIRED_MAJOR" >/dev/null 2>&1; then
    cc="clang-$REQUIRED_MAJOR"
  else
    cc=clang
  fi
fi
command -v "$cc" >/dev/null 2>&1 || fail "$cc not found; install clang-$REQUIRED_MAJOR and llvm-$REQUIRED_MAJOR"
version="$("$cc" --version 2>/dev/null | head -1 || true)"
major="$(printf '%s\n' "$version" | sed -nE 's/.*clang version ([0-9]+)\..*/\1/p')"
[ "$major" = "$REQUIRED_MAJOR" ] || fail "$cc is \"${version:-unknown}\"; install clang-$REQUIRED_MAJOR and llvm-$REQUIRED_MAJOR (or point BPF2GO_CC at it)"
printf '%s\n' "$cc"
