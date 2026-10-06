---
title: 'Leash #109 enforce long mutation-policy paths'
type: 'bugfix'
created: '2026-09-03'
status: 'done'
review_loop_iteration: 1
baseline_commit: '94c43fe34a34268d057f016de6278cc2a4160ed7'
context:
  - 'docs/design/CEDAR.md'
  - 'docs/implementation-artifacts/spec-leash-103-declared-directory-mutations.md'
  - 'docs/implementation-artifacts/spec-leash-108-long-policy-paths.md'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** Mutation authorization still indexes only the first 64 policy-path bytes, so a declared writable directory beyond that boundary can permit `file.open:rw` yet deny its `mkdir`, `unlink`, `rmdir`, or rename lifecycle. This blocks the UID-1001 linked-worktree lock discovered after #108.

**Approach:** Replace the legacy mutation prefix scan with generation-scoped full-byte indexes through the public 255-byte policy limit. Use distinct complete-key deny and writable-directory lookup domains plus exact directory-self denial, and linearize each mutation decision with a non-wrapping activation token.

## Boundaries & Constraints

**Always:** Compile every accepted mutation-policy byte through 255 and evaluate resolved mutation targets of at most 255 bytes; preserve deny-over-allow across ancestors, generic-deny prefix behavior including file-rule prefixes, RW-directory deny/allow for descendants, generic directory deny for exact self, default deny, both rename endpoints, audit, overlay correlation, required-hook attachment, and fail-closed verifier/load behavior. Snapshot and recheck a monotonic `u64` mutation token before decision/audit return, use its low bit only for the two generations, reject wrap, and use #108's existing `OpenLsm` writer mutex. Keep #108 file-open behavior and #29 hard-link scope intact.

**Ask First:** Any public policy/ABI change; reduced 255-byte limit; support for runtime mutation targets beyond 255 bytes; new kernel/helper requirement; cross-hook reload transactionality, overlay lifetime, hard-link, Walk, BME, release, extra tail-call, or authority-semantic change.

**Never:** Truncate or partial-prefix match, add application-level hashing or probabilistic matching, let deeper permit mask broader deny, grant mutation from a writable file or generic permit, broaden same-prefix siblings, access credentials, push, PR, merge, or release.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected | Error Handling |
|---|---|---|---|
| Long tree | RW directory >64 bytes; resolved target <=255 | All shared descendant mutations allowed/audited | Missing state denies |
| Deny precedence | Broad deny plus deeper RW allow | Deny wins | Never masked |
| Same-prefix sibling | Long declared tree plus undeclared sibling | Declared succeeds; sibling denied | No truncated authorization |
| Directory self | RW directory or generic-denied directory | RW cannot mutate self; generic deny covers self and descendants | Preserve semantics |
| Runtime overflow | Resolved target >255 bytes | No partial decision | Deny; separate runtime-path defect |
| Dogfood lock | 67-byte gitdir, 78-byte lock, UID 1001 | Create/open/unlink succeeds with host ownership | Always clean containers/state |

</frozen-after-approval>

## Code Map

- `internal/lsm/bpf/lsm_open.bpf.c` -- full-byte maps, token confirmation, shared hooks.
- `internal/lsm/file_open.go` -- Go ABI, compiler, staged generations and token.
- `internal/lsm/directory_mutation_test.go` -- semantics, transitions, audit guards.
- `e2e/boot_test.go` -- real verifier/UID-1001 proof.

## Tasks & Acceptance

**Execution:**
- [x] `internal/lsm/bpf/lsm_open.bpf.c` -- add minimal deny LPM, RW-dir allow LPM, exact generic-dir-self set, and full-token recheck without changing hooks/overlay.
- [x] `internal/lsm/file_open.go` -- compile and replace both generations under the existing mutex with a non-wrapping `u64` token.
- [x] focused tests -- prove 64/65/255 keys, semantics, token ABA/wrap, staging failure, and audit names.
- [x] `e2e/boot_test.go` -- prove long allow/deny/same-prefix and 67/78-byte UID-1001 lock lifecycle on real required LSM.
- [x] generated BPF bindings -- regenerate and pass the real verifier.

**Acceptance Criteria:**
- Given a 1–255-byte policy and resolved target <=255, when a shared mutation hook runs, then all relevant bytes determine the audited decision.
- Given matching deny and allow ancestors, when authorization runs, then deny wins regardless of nesting/order.
- Given reload races a mutation, when the hook reaches audit/return, then full-token equality linearizes; missing, changed, ABA, or exhausted state cannot authorize.
- Given UID 1001 creates/removes the 78-byte lock under its declared gitdir, then it succeeds, same-prefix sibling is denied, ownership is correct, and cleanup is complete.
- Given `--require-lsm`, when the candidate loads, then every required hook verifies or startup fails before workload.

## Spec Change Log

## Design Notes

Use complete bytes. The deny LPM contains generic-deny prefixes (including file rules) and RW-directory deny descendant prefixes; the allow LPM contains only RW-directory descendant prefixes. The exact set handles generic directory-self denial without broadening `/dir` to `/directory`. A one-byte generation domain retains all 255 path bytes in the kernel's 256-byte LPM data limit. Mutation uses its own monotonic `u64` token, low-bit slot, full snapshot/recheck, and wrap rejection. The existing mutex serializes writers, but cross-hook transactionality and >255 runtime paths stay separate and fail closed.

## Verification

- `timeout 5m env GOCACHE=/tmp/leash109-gocache GOOS=linux GOARCH=amd64 go generate ./internal/lsm`
- `timeout 5m env GOCACHE=/tmp/leash109-gocache go test ./internal/lsm -run 'DirectoryMutation|LongMutation|MutationIndex|MutationToken' -count=1`
- real credential-free Docker/Walk UID-1001 `--require-lsm` regression
- `timeout 10m env GOCACHE=/tmp/leash109-gocache go test ./... -count=1`
- `git diff --check`

**Evidence:**
- Pinned `github.com/cilium/ebpf/cmd/bpf2go` v0.19.0 regenerated both endian objects; symbol inspection found the three mutation indexes, `u64` activation map, all five mandatory hook programs, and no register/pointer OR in `check_mutation_policy`.
- Focused mutation tests and the race-enabled LSM regression passed.
- The first two real loads failed closed before workload on LLVM pointer-OR verifier output; genuinely nested map lookups removed that emitted instruction without changing authority.
- `TestRunnerLongDirectoryMutations` passed in 28.254s against `walk33-bmad-codex:v0.2.7` and local `leash109-manager:indexed-v3`: required-LSM load, UID-1001 67/78-byte lock lifecycle, all shared mutations, same-prefix denial, ownership, audit, and cleanup passed.
- Complete `go test ./... -count=1` passed outside the managed socket sandbox; the sandbox-only run failed solely where existing tests could not create local TCP/Unix sockets.
- `git diff --check` passed.
- Independent Blind Hunter and Edge Case Hunter reviews completed on the issue-only tracked and untracked diff. In-scope findings added malformed-directory protection, staged-write/activation/cleanup-debt coverage, same-slot ABA evidence, per-hook deny-chain guards, correlated audit assertions, cleanup-command validation, and exact 255/256-byte runtime boundaries. Cross-hook transactionality and audit-reservation semantics remain explicitly outside this issue's frozen contract.
- The reviewed candidate passed `TestRunnerLongDirectoryMutations` in 17.28s with required LSM enforcement: UID 1001, all correlated shared-mutation audits, same-prefix denials, exact 255-byte allow, 256-byte unresolved fail-closed denial, host ownership, and complete container cleanup.

## Suggested Review Order

**Mutation authorization**

- Start with full-byte deny/self/allow precedence and verifier-safe nested lookups.
  [`lsm_open.bpf.c:464`](../../internal/lsm/bpf/lsm_open.bpf.c#L464)

- Confirm runtime paths preserve 255 bytes and reject unresolved overflow.
  [`lsm_open.bpf.c:536`](../../internal/lsm/bpf/lsm_open.bpf.c#L536)

- Follow token confirmation through audited and silent mutation returns.
  [`lsm_open.bpf.c:580`](../../internal/lsm/bpf/lsm_open.bpf.c#L580)

**Policy publication**

- Review the three minimal indexes and exact directory-self compilation guard.
  [`file_open.go:612`](../../internal/lsm/file_open.go#L612)

- Verify inactive staging, monotonic activation, rollback, and cleanup debt.
  [`file_open.go:755`](../../internal/lsm/file_open.go#L755)

**Regression proof**

- Check token, staging, cleanup, malformed-rule, and 64/65/255 boundary tests.
  [`directory_mutation_test.go:192`](../../internal/lsm/directory_mutation_test.go#L192)

- Finish with real UID-1001 mutation, audit, and 255/256-byte enforcement.
  [`boot_test.go:756`](../../e2e/boot_test.go#L756)
