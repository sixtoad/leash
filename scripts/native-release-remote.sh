#!/usr/bin/env bash
# Remote-state and package-visibility helpers for scripts/release.sh.
# This file is sourced; callers retain `set -euo pipefail` policy.

native_require_github_absent() {
  local temp="$1" kind="$2" endpoint="$3" tag="$4"
  local error_file="$temp/github-${kind// /-}.err"
  if timeout 2m gh api "$endpoint" >/dev/null 2>"$error_file"; then
    printf '%s\n' "release: refusing to mutate existing $kind $tag" >&2
    return 1
  fi
  if ! grep -qi 'HTTP 404' "$error_file"; then
    cat "$error_file" >&2
    printf '%s\n' "release: could not prove $kind $tag is absent" >&2
    return 1
  fi
}

native_require_release_names_absent() {
  local temp="$1" repo="$2" tag="$3"
  native_require_github_absent "$temp" "Git tag" "/repos/$repo/git/ref/tags/$tag" "$tag" || return 1
  native_require_github_absent "$temp" "GitHub release" "/repos/$repo/releases/tags/$tag" "$tag" || return 1
}

native_manager_tag_state() {
  local temp="$1" owner="$2" package="$3" tag="$4"
  local error_file="$temp/ghcr-check.err" tags
  if tags="$(timeout 2m gh api --paginate \
    "/user/packages/container/$package/versions?per_page=100" \
    --jq ".[] | .metadata.container.tags[]? | select(. == \"$tag\")" \
    2>"$error_file")"; then
    if [ -n "$tags" ]; then
      printf '%s\n' present
    else
      printf '%s\n' absent
    fi
    return 0
  fi
  if grep -qi 'HTTP 404' "$error_file"; then
    local manager_tag="ghcr.io/$owner/$package:$tag"
    local registry_error="$temp/ghcr-registry-check.err"
    if timeout 2m docker buildx imagetools inspect \
      --format '{{json .Manifest}}' "$manager_tag" \
      >"$temp/ghcr-registry-check.json" 2>"$registry_error"; then
      printf '%s\n' present
      return 0
    fi
    if grep -Eqi 'HTTP 404|manifest unknown|not found' "$registry_error"; then
      printf '%s\n' absent
      return 0
    fi
    cat "$registry_error" >&2
    printf '%s\n' "release: package API returned 404 and registry could not prove $manager_tag absent" >&2
    return 1
  fi
  cat "$error_file" >&2
  printf '%s\n' "release: could not inspect manager package ghcr.io/$owner/$package" >&2
  return 1
}

native_remote_mode() {
  local temp="$1" repo="$2" owner="$3" package="$4" tag="$5" resume="$6"
  native_require_release_names_absent "$temp" "$repo" "$tag" || return 1

  local state
  state="$(native_manager_tag_state "$temp" "$owner" "$package" "$tag")" || return 1
  if [ "$state" = present ]; then
    if [ "$resume" != 1 ]; then
      printf '%s\n' "release: refusing to mutate existing manager tag ghcr.io/$owner/$package:$tag" >&2
      printf '%s\n' "release: after verifying this is a stranded publication, retry explicitly with --resume-existing-manager" >&2
      return 1
    fi
    printf '%s\n' resume
    return 0
  fi

  if [ "$resume" = 1 ]; then
    printf '%s\n' "release: --resume-existing-manager requires existing manager tag ghcr.io/$owner/$package:$tag" >&2
    return 1
  fi
  printf '%s\n' fresh
}

native_require_manager_absent() {
  local temp="$1" owner="$2" package="$3" tag="$4" state
  state="$(native_manager_tag_state "$temp" "$owner" "$package" "$tag")" || return 1
  if [ "$state" != absent ]; then
    printf '%s\n' "release: manager tag appeared before publication: ghcr.io/$owner/$package:$tag" >&2
    return 1
  fi
}

native_execute_manager_mode() {
  local mode="$1" fresh_callback="$2" resume_callback="$3"
  case "$mode" in
    fresh) "$fresh_callback" ;;
    resume) "$resume_callback" ;;
    *) printf '%s\n' "release: invalid manager mode '$mode'" >&2; return 1 ;;
  esac
}

native_resolve_manager_digest() {
  local manager_tag="$1" manifest_file="$2"
  if ! timeout 2m docker buildx imagetools inspect \
    --format '{{json .Manifest}}' "$manager_tag" >"$manifest_file"; then
    printf '%s\n' "release: could not resolve existing manager tag $manager_tag" >&2
    return 1
  fi
  MANIFEST_FILE="$manifest_file" python3 - <<'PY'
import json
import os
import re

with open(os.environ["MANIFEST_FILE"], encoding="utf-8") as handle:
    manifest = json.load(handle)
digest = manifest.get("digest")
if not isinstance(digest, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
    raise SystemExit(f"release: existing manager tag returned invalid digest {digest!r}")
print(digest, end="")
PY
}

native_assert_manager_digest() {
  local manager_tag="$1" expected_digest="$2" manifest_file="$3" observed_digest
  observed_digest="$(native_resolve_manager_digest "$manager_tag" "$manifest_file")" || return 1
  if [ "$observed_digest" != "$expected_digest" ]; then
    printf '%s\n' "release: manager tag drifted from $expected_digest to $observed_digest" >&2
    return 1
  fi
}

native_require_manager_public() {
  local temp="$1" owner="$2" package="$3" tag="$4"
  local endpoint="/user/packages/container/$package"
  local error_file="$temp/ghcr-visibility.err" visibility
  if ! visibility="$(timeout 2m gh api "$endpoint" --jq .visibility 2>"$error_file")"; then
    cat "$error_file" >&2
    printf '%s\n' "release: could not read manager package visibility via GET $endpoint" >&2
    return 1
  fi
  case "$visibility" in
    public)
      return 0
      ;;
    private)
      printf '%s\n' "release: manager package is private; GitHub exposes no supported visibility-update API" >&2
      printf '%s\n' "release: make it public at https://github.com/users/$owner/packages/container/$package/settings" >&2
      printf '%s\n' "release: then retry exactly: scripts/release.sh --resume-existing-manager $tag" >&2
      return 1
      ;;
    *)
      printf '%s\n' "release: manager package has unsupported visibility '$visibility'" >&2
      return 1
      ;;
  esac
}
