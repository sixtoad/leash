#!/usr/bin/env bash
# Rejects unqualified container image references (#172).
#
# Podman's default short-name policy prompts for a registry when an image
# name has no registry host ("debian:bookworm", "leash/build-base:latest"),
# which stalls unattended builds. Every image reference must name its
# registry: docker.io/library/... (or docker.io/<org>/...) for Docker Hub,
# localhost/... for images built locally, ghcr.io/..., etc. Docker accepts the
# qualified forms unchanged.
#
# Checked:
#   - Dockerfiles/Containerfiles: every FROM and COPY --from= that is not a
#     build stage, with global ARG defaults substituted.
#   - Makefiles, shell scripts, GitHub workflows and e2e Go code: well-known
#     Docker Hub library names with a tag (debian:bookworm), bare library
#     names after docker/podman run|pull|create, and leash/<name>:<tag>.
#
# Comment lines (# or //) and lines containing "image-ref-lint: ignore" are
# skipped.
#
# Usage: scripts/check-image-refs.sh [repo-root]   (exit 1 on findings)

set -euo pipefail

root="${1:-$(git rev-parse --show-toplevel)}"
cd "$root"

status=0

# --- Dockerfiles -------------------------------------------------------------

dockerfile_list="$(git ls-files -- 'Dockerfile*' '*/Dockerfile*' 'Containerfile*' '*/Containerfile*' '*.Dockerfile' '*.containerfile')"

check_dockerfile_awk='
function qualified(ref,   n, parts) {
  n = split(ref, parts, "/")
  if (n < 2) return 0
  return parts[1] == "localhost" || index(parts[1], ".") > 0 || index(parts[1], ":") > 0
}
function expand(ref,   name, m) {
  # ${VAR} and $VAR from global ARG defaults; unknown variables stay as-is.
  while (match(ref, /\$\{[A-Za-z_][A-Za-z0-9_]*\}/)) {
    name = substr(ref, RSTART + 2, RLENGTH - 3)
    if (!(name in args)) break
    ref = substr(ref, 1, RSTART - 1) args[name] substr(ref, RSTART + RLENGTH)
  }
  while (match(ref, /\$[A-Za-z_][A-Za-z0-9_]*/)) {
    name = substr(ref, RSTART + 1, RLENGTH - 1)
    if (!(name in args)) break
    ref = substr(ref, 1, RSTART - 1) args[name] substr(ref, RSTART + RLENGTH)
  }
  return ref
}
function check(ref, what,   r) {
  r = expand(ref)
  if (tolower(r) in stages || r == "scratch" || r ~ /^[0-9]+$/) return
  if (r ~ /\$/) {
    printf "%s:%d: %s %s uses a variable without a global ARG default; cannot verify it is qualified\n", FILENAME, FNR, what, ref
    bad = 1
    return
  }
  if (!qualified(r)) {
    printf "%s:%d: unqualified image in %s: %s (use docker.io/library/..., localhost/..., or another registry host)\n", FILENAME, FNR, what, (r == ref ? ref : ref " -> " r)
    bad = 1
  }
}
/image-ref-lint: ignore/ { next }
{
  line = $0
  sub(/^[ \t]+/, "", line)
  n = split(line, f, /[ \t]+/)
  kw = toupper(f[1])
}
kw == "ARG" && !seen_from {
  if (split(f[2], kv, "=") >= 2) { v = substr(f[2], length(kv[1]) + 2); gsub(/^"|"$/, "", v); args[kv[1]] = v }
  next
}
kw == "FROM" {
  seen_from = 1
  i = 2
  while (i <= n && f[i] ~ /^--/) i++
  ref = f[i]
  check(ref, "FROM")
  if (i + 2 <= n && toupper(f[i + 1]) == "AS") stages[tolower(f[i + 2])] = 1
  next
}
kw == "COPY" || kw == "ADD" {
  for (i = 2; i <= n; i++) {
    if (f[i] ~ /^--from=/) check(substr(f[i], 8), "COPY --from")
  }
}
END { exit bad }
'

ndocker=0
while IFS= read -r file; do
  [ -n "$file" ] && [ -f "$file" ] || continue
  ndocker=$((ndocker + 1))
  if ! awk "$check_dockerfile_awk" "$file"; then
    status=1
  fi
done <<<"$dockerfile_list"

# --- Makefiles, scripts, workflows, e2e Go ------------------------------------

other_list="$(git ls-files -- 'Makefile' '*/Makefile' '*.mk' '*.sh' '.github/workflows/*.yml' '.github/workflows/*.yaml' 'e2e/*.go' 'e2e/**/*.go')"

library='(alpine|busybox|debian|ubuntu|golang|node|rockylinux|fedora|centos|python|amazonlinux|archlinux|nginx|redis|postgres)'
# library:tag not preceded by a registry path, a word character or a dash.
tagged="(^|[^A-Za-z0-9._/-]|:-)${library}:[A-Za-z0-9._\${}-]+"
# bare library name as the image of docker/podman run|pull|create.
bare="(docker|podman|DOCKER|RUNTIME)[^#]*[[:space:]](run|pull|create)[[:space:]].*[[:space:]\"']${library}([[:space:]\"']|$)"
# our own locally built images without localhost/.
ours="(^|[^A-Za-z0-9._/-]|:-)leash[/-][a-z0-9._-]+:[A-Za-z0-9._%\${}-]+"

nother=0
while IFS= read -r file; do
  [ -n "$file" ] && [ -f "$file" ] || continue
  [ "$file" = "scripts/check-image-refs.sh" ] && continue
  nother=$((nother + 1))
  hits="$(grep -nE -e "$tagged" -e "$bare" -e "$ours" -- "$file" | grep -v 'image-ref-lint: ignore' | grep -vE '^[0-9]+:[[:space:]]*(#|//)' || true)"
  if [ -n "$hits" ]; then
    while IFS= read -r hit; do
      printf '%s:%s (unqualified image reference; use docker.io/library/..., localhost/..., or another registry host)\n' "$file" "$hit"
    done <<<"$hits"
    status=1
  fi
done <<<"$other_list"

if [ "$status" -eq 0 ]; then
  echo "image references: all qualified ($ndocker Dockerfiles, $nother other files)"
fi
exit "$status"
