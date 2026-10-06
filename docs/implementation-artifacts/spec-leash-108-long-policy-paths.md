---
title: 'Leash #108 enforce long file-policy paths'
type: 'bugfix'
created: '2026-09-03'
status: 'done'
review_loop_iteration: 3
baseline_commit: '656c7909c3cbe87627ddd5a36988543e8e660b67'
context:
  - 'docs/design/CEDAR.md'
  - 'docs/implementation-artifacts/spec-leash-105-verifier-budget.md'
  - 'docs/implementation-artifacts/spec-leash-82-nonroot-setgroups-2.md'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** Cedar parsing and the userspace/BPF rule ABI accept file paths through 255 bytes, but `lsm/file_open` silently skips rules longer than 64 bytes. A long permit or forbid can therefore disappear while the manager reports the policy as loaded, allowing Walk #84's governed Git metadata write to bypass its exact forbid.

**Approach:** Keep the public 255-byte maximum and compile file-open authority into generation-scoped full-byte indexes: an exact-path map for files and derived directory-self entries, plus an operation-scoped LPM trie for directory descendants. Validate and stage the userspace-to-BPF contract before atomically selecting a generation; retain specificity/stable-order rank, exact directory semantics, and root defaults; then prove the result on the real BPF-LSM boundary before supplying a local manager image to Walk #84.

## Boundaries & Constraints

**Always:** Accept and enforce file-policy paths of 1–255 bytes consistently through parsing, conversion, map loading, matching, and audit; reject direct `OpenPolicyRule` lengths of zero or greater than 255 before changing live or in-memory policy; compare every declared byte without hashing, truncation, or prefix broadening; preserve longest-path-first stable rule precedence, operation-specific matching, directory-self/descendant behavior, root-derived default policy, default deny, fail-closed tail-call behavior, and existing mutation/hard-link protections; use bounded commands and the real release kernel verifier.

**Ask First:** Any reduction of the documented 255-byte limit; Cedar/public ABI change; new minimum-kernel/helper requirement; change to mutation authorization, hard-link scope, release workflow, Walk, or BME; or a verifier workaround that widens access or adds another tail-call stage.

**Never:** Silently skip an accepted rule; truncate or probabilistically hash a security path; treat a 64-byte prefix as a full match; allow on invalid lengths, unavailable scratch, or verifier/load failure; weaken forbid/permit or read-versus-write decisions; publish, push, open a PR, merge, or access credentials.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|---------------|---------------------------|----------------|
| Legacy boundary | 64-byte permit or forbid | Existing exact and directory matching remains unchanged | Any mismatch fails tests |
| First long path | 65-byte permit or forbid | Every byte participates and the declared operation decides | No fallback to the first 64 bytes |
| Public maximum | 255-byte permit or forbid | Rule loads, enforces, and audits the complete path | A 256-byte path is rejected before attachment/state change |
| Long exact forbid | Broad writable parent plus a >64-byte exact child forbid | Sibling write succeeds; forbidden write is denied and audited | Default or parent permit cannot mask the forbid |
| Long exact permit | Default deny plus one >64-byte exact write permit | Declared write succeeds; same-prefix sibling remains denied and audited | No prefix authorization |

</frozen-after-approval>

## Code Map

- `internal/lsm/bpf/lsm_open.bpf.c` -- generation-scoped exact and directory-LPM indexes, candidate selection, audit, and unchanged legacy hard-link matcher.
- `internal/lsm/file_open.go` -- Go/BPF rule ABI, load-time validation, ordering, and live map updates.
- `internal/lsm/common.go` and focused tests -- public 255-byte parser boundary and conversion contract.
- `internal/lsm/long_path_test.go` -- 64/65/255/256 validation and semantic regression coverage.
- `e2e/boot_test.go` -- credential-free real Docker/BPF-LSM permit and forbid enforcement regression.
- `docs/design/CEDAR.md` -- explicit supported file-policy path limit.

## Tasks & Acceptance

**Execution:**
- [x] `internal/lsm/bpf/lsm_open.bpf.c` -- replace the ordinary file-open scan with exact full-byte and directory-LPM lookups, choose by specificity/stable rank, and preserve the unchanged short hard-link checker.
- [x] `internal/lsm/file_open.go` -- validate lengths, compile generic operations into per-runtime-operation index entries, and stage/flip/clean generations atomically while retaining stable specificity ordering.
- [x] focused parser/loader/matcher tests -- cover permit and forbid at 64, 65, and 255 bytes plus fail-closed 256-byte rejection and state preservation.
- [x] `e2e/boot_test.go` -- run separate real-LSM long-forbid and long-permit cases, assert same-prefix controls, audits, and container cleanup.
- [x] `docs/design/CEDAR.md` -- document the exact 255-byte file path contract.
- [x] local integration artifact -- build a uniquely tagged local manager from the proven commit and rerun Walk #84's UID-1001 linked-worktree boundary against it.
- [x] `internal/lsm/bpf/lsm_open.bpf.c` -- replace the binary generation value with a non-wrapping monotonic 64-bit activation token, retain its snapshot in per-CPU scratch, and re-read it in `lsm_open_policy` immediately before audit submission/result and enforcement return.
- [x] focused read-side consistency regression -- prove the low token bit selects the two map slots, ABA cannot pass equality, every decision branch is guarded at the hook linearization point, and unavailable/changed/exhausted token state denies or rejects.
- [x] bounded reload consistency patches -- publish `OpenLsm` in-memory policy only after a successful live update, clear the legacy rule count on empty reload, and report post-flip cleanup as committed authority with cleanup debt rather than a rejected update.
- [x] concurrent-writer consistency -- serialize every `OpenLsm` policy load, including initial BPF setup and live reload, across staging, token activation, cleanup, and in-memory publication; prove two writers cannot mix entries under one token.
- [x] audit regression precision -- parse E2E audit records and require operation, complete path, and decision on the same line.
- [x] fail-closed Cedar conversion -- propagate normalized paths beyond 255 bytes instead of silently dropping a rule; prove a mixed broad permit and overlength forbid returns no partial policy.
- [x] pre-MCP file validation -- reject overlength File/Dir resources before the MCP-forbid shortcut when a policy also declares a FileOpen action, without changing MCP semantics.
- [x] normalized-directory lint parity -- count the appended directory slash so the linter and compiler both reject a normalized path beyond 255 bytes.

**Acceptance Criteria:**
- Given any accepted 1–255-byte file rule, when its path and operation match, then the kernel applies the complete permit/forbid and emits the complete audited path.
- Given a zero-length or 256-byte direct rule, when policies are loaded or hot-reloaded, then loading fails before prior authority or in-memory state changes.
- Given the real long-path Docker regression, when the manager loads with `--require-lsm`, then all required BPF programs pass the verifier, exact permit/forbid controls behave distinctly from same-prefix siblings, and all containers are removed.
- Given the fixed local manager, when Walk #84 reruns as UID 1001, then its exact long Git metadata forbid is enforced and the run advances without the #108 bypass.

## Spec Change Log

- 2026-09-03 -- The first approved four-region comparison was rejected by the real kernel at exactly 1,000,001 verifier instructions in `lsm_open_policy` (and also exhausted the optional `lsm_link` budget). Human approved replacing it with generation-scoped full-byte exact and operation-specific directory-LPM indexes. Exact directory-self entries and stored specificity/order rank preserve existing winners; complete byte keys avoid truncation or probabilistic path digests; the legacy #29 hard-link reconstruction/check remains unchanged.
- 2026-09-03 -- The first indexed object failed LPM map creation because its 268-byte key exceeded the kernel ABI. Generation and operation were bijectively packed into one domain byte, leaving the full 255-byte accepted path inside the LPM trie's 256-byte searchable-key limit. The maps retain capacity for both overlapping generations at maximum generic-operation expansion.
- 2026-09-03 -- The next object exposed an LLVM verifier-hostile merge of two nullable map-value checks into pointer bitwise OR. Nested pointer branches preserve identical decisions and emit no pointer OR. The real `--require-lsm` verifier/load and both long-path enforcement/audit controls then passed.
- 2026-09-03 -- Review loop 1 found that an in-flight hook could snapshot the old generation, race with post-flip cleanup, miss a specific deny, and return the old default allow. The non-frozen design now requires a second active-generation read after all rule/default lookups and immediately before every result; missing, invalid, or changed state denies. This avoids the known-bad single-snapshot cleanup race. KEEP: full-byte exact/LPM keys, operation domain, specificity/stable-order winners, fail-closed verifier behavior, the legacy hard-link boundary, the passing long permit/forbid E2E, and the passing Walk #84 handoff. Cross-hook reload transactionality and runtime paths longer than 255 bytes remain separate issues and are not changed here.
- 2026-09-03 -- Review loop 2 found the 0/1 confirmation still admitted ABA across two reloads and occurred inside the helper before audit assembly. The design now uses one aligned monotonic 64-bit activation token; its low bit selects the two stored generations, while full-token equality at the `lsm_open_policy` audit/enforcement boundary defines the decision linearization point. Token exhaustion rejects reload rather than wrapping. KEEP: the verified full-byte exact/LPM behavior, operation/specificity/stable-order semantics, two-map capacity, no verifier-hostile pointer OR, legacy hard-link/mutation bounds, and the passing v5 real-kernel controls. Cross-hook transactionality and runtime paths longer than 255 bytes remain separate issues.
- 2026-09-03 -- Review loop 3 found that two concurrent userspace writers could read the same token, interleave staging into the same slot, and publish mixed authority under one valid token. One `OpenLsm`-owned mutex now serializes initial setup and every reload through staging, activation, cleanup, and in-memory publication. KEEP: monotonic full-token hook linearization, full-byte exact/LPM behavior, verified v6 BPF object, legacy hard-link/mutation bounds, and excluded cross-hook/>255-runtime scope. The E2E audit assertion is also tightened so operation, full path, and decision must occur on the same record.
- 2026-09-03 -- Final review found that Cedar conversion still swallowed the existing overlength error, allowing a normalized 256-byte forbid to disappear while another rule survived. The issue-owned patch propagates that specific error through the complete policy-set conversion and returns no partial authority; unrelated legacy conversion-skip behavior is unchanged. The obsolete mutable-state root-policy helper was also removed after transactional publication replaced it.
- 2026-09-03 -- The final Edge pass found two bounded variants of the same accepted contract: a mixed `McpCall`/`FileOpen` forbid reached the MCP shortcut before file conversion, and the linter measured a directory before normalization appended `/`. File resources associated with a FileOpen action are now validated before the MCP shortcut, and lint uses the normalized directory length; MCP conversion behavior is otherwise unchanged.

- 2026-10-06 -- Ported onto `walk-integration` after #110/#114/#124 (kept #110's `barrier_var` guards). Human direction for this port: keep the legacy matcher semantics exactly -- byte-prefix matching, longest rule wins, earlier rule wins a tie -- so FILE rules now go to the LPM trie as byte prefixes (as before #108 for paths <= 64 bytes) instead of the exact map; the exact map holds only directory-self entries. This also keeps file-rule forbids covering every byte-prefixed path (e.g. `config` and `config.lock`), consistent with the #109 mutation deny trie. A randomized model test proves index == uncapped legacy scan beyond 64 bytes. The hard-link guard (#29) now assembles the complete source path (two bounded bulk copies, no per-byte loop) and uses the same full-length matcher and activation-token recheck, so a long forbid can no longer be aliased by hard link; the legacy `check_path_policy` scan is removed. Exec rules keep the 64-byte matcher but the loader now rejects (fail closed) any rule > 64 bytes or > 64 rules. `leash version --json` advertises `policyLimits` (capability `policy-path-limits`). Real-kernel proof moved into `scripts/verify-lsm-kernel-load.sh` (host clang 18 and Docker clang 14, kernel 6.18.7).

## Design Notes

Userspace expands a generic `FileOpen` rule to all three runtime open operations before indexing. Exact and directory candidates retain original specificity and stable sorted order; the kernel selects higher specificity, then earlier order. Keeping operation in both keys prevents an inapplicable deeper rule from hiding an applicable parent. Directory descendants use the full trailing-slash prefix in the LPM trie, while a derived exact key without that slash preserves directory-self matching. The generated object loading on the real host, not source-shape assertions, is the verifier-budget gate.

Each hook snapshots the aligned 64-bit activation token before constructing keys; the token's low bit selects the exact/LPM/default slot and the full value is retained in per-CPU scratch. After exact, directory, and default lookup and audit assembly, `lsm_open_policy` performs a fresh token lookup immediately before submitting the event and returning enforcement. Missing or changed state denies, so a reload concurrent with the hook cannot reuse a 0/1 slot through ABA. The second equality check is the decision linearization point: a later token update is a later policy transition. Userspace rejects the maximum token instead of wrapping it.

All userspace writers share an `OpenLsm` update mutex. The critical section includes initial map setup, live candidate staging, token activation, cleanup reporting, and publication of the corresponding in-memory policy, so a token uniquely identifies one complete writer's index.

## Verification

**Evidence:**
- `timeout 3m env GOCACHE=/tmp/leash108-gocache go test ./internal/lsm -run 'PolicyPathLength|LongPolicyPath|OpenIndex' -count=1` -- pass; 64/65/255 allow+deny, 256 rejection, stable precedence, operation separation, LPM layout/domain/prefix, and atomic generation transitions.
- `timeout 5m env GOCACHE=/tmp/leash108-gocache GOOS=linux GOARCH=amd64 go generate ./internal/lsm` -- pass with only the repository's existing raw-tracepoint visibility warning.
- `llvm-objdump` inspection of `check_open_indexed_policy` -- no pointer bitwise OR emitted after the nested-branch correction.
- emitted-object inspection after review loop 2 -- two distinct `active_open_generation` relocations read aligned `u64` values; low-bit slot selection occurs in the matcher and full-token comparison occurs in the hook before audit result/submit/return; no pointer bitwise OR is emitted.
- focused and race-enabled update tests -- pass after review loop 3; deterministic concurrent writers cannot enter staging together, publish mixed authority, or share one activation token.
- focused Cedar conversion/lint tests -- pass; a 255-byte file is retained, a 256-byte file and directory normalized to 256 bytes fail without partial output, the mixed MCP/file shortcut fails closed, and lint reports normalized directory overflow.
- real Docker test with `LEASH_E2E_MANAGER_IMAGE=leash108-manager:indexed-v9` and `--require-lsm` -- pass in 61.321 seconds; >64 exact forbid and permit, same-prefix controls, per-record complete audits, and cleanup.
- final local manager candidate: `leash108-manager:indexed-v9`, image ID `sha256:2b602bac71d21c17692586183a6a369993c9ad567041a1a324244113081fc058`.
- `timeout 10m env GOCACHE=/tmp/leash108-gocache go test ./... -count=1` -- pass after the final Edge patches outside the managed socket sandbox; all packages green.
- `git diff --check` -- pass.
- Walk #84 UID-1001 linked-worktree dogfood against exact v9 image ID `sha256:2b602bac71d21c17692586183a6a369993c9ad567041a1a324244113081fc058` -- pass in 33.650 seconds at Walk `32cd670...7558`; binary SHA-256 `8828775d...b650`; all isolation, Git mutation, ownership, temporary-view, and container-cleanup assertions passed.
