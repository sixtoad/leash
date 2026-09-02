---
title: 'Leash #105 mutation-hook verifier budget'
type: 'bugfix'
created: '2026-09-02'
status: 'done'
review_loop_iteration: 0
baseline_commit: 'f86f31cbfa2b4211cf92a3ca58d415365fe2767c'
context:
  - 'docs/implementation-artifacts/spec-leash-103-declared-directory-mutations.md'
---

<frozen-after-approval reason="public issue acceptance is approved human-owned intent">

## Intent

**Problem:** The exact `native-v0.3.9` release-parity gate cannot load the required `lsm_mkdir` program because the #103 mutation-hook implementation exceeds the kernel verifier's one-million-instruction budget. The published manager image is therefore unusable with `--require-lsm`, and the GitHub release correctly did not publish.

**Approach:** Reduce verifier state and instruction complexity shared by mkdir, unlink, rmdir, and both rename endpoint programs, while retaining the complete #103 fail-closed policy and audit behavior. Add a release-equivalent load regression so the same failure blocks publication before any future manager tag is pushed.

## Boundaries & Constraints

**Always:** Load every required mutation hook on the real release kernel path; preserve earlier BPF-LSM denial returns, explicit writable-directory authorization, default deny, concrete operation/path audit events, both rename endpoint checks, operation-bounded overlay copy-up correlation, and the exact UID 1001 declared-tree versus undeclared-sibling behavior.

**Ask First:** Any Cedar contract change, relaxation of required enforcement, new kernel capability requirement, release workflow expansion beyond moving the verifier/load gate before remote publication, or change that cannot be proven on the release-equivalent host.

**Never:** Make a hook optional or best-effort; broaden writable paths; skip, mock, or stale-cache the BPF collection load; weaken denial/audit/overlay semantics; overwrite or repoint `native-v0.3.9`; publish a release while implementing this issue; access or expose credentials.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Verifier load | Release-built manager on the release-equivalent Linux host | All required mutation programs load and attach below the verifier limit | Any missing or rejected program fails the gate before remote publication |
| Declared tree | UID 1001 mutates descendants of explicit RW `/home/agent/.npm/` | mkdir, write, rename, unlink, and rmdir succeed with actionable audit data | Any regression fails the exact E2E |
| Undeclared sibling | Same UID mutates an undeclared sibling | Mutation is denied with operation and concrete path | Fail closed; no broad owner/home grant |
| Chained decision | Prior LSM hook or rename source rejects | Existing denial is preserved; destination cannot convert it to allow | Return prior non-zero result unchanged |

</frozen-after-approval>

## Code Map

- `internal/lsm/bpf/lsm_open.bpf.c` -- verifier-sensitive policy, path reconstruction, mutation hooks, audit, and overlay correlation.
- `internal/lsm/file_open.go` -- BPF collection loading and mandatory attachment list.
- `internal/lsm/directory_mutation_test.go` -- focused source/contract guards for all required hooks and fail-closed semantics.
- `e2e/boot_test.go` -- real UID 1001 declared-directory and release-binary parity regressions.
- `scripts/release.sh` -- publication order; the real verifier/load gate must precede immutable remote manager publication.
- `scripts/verify-native-release.sh` -- bounded native release-parity execution under `--require-lsm`.

## Tasks & Acceptance

**Execution:**
- [x] `internal/lsm/bpf/lsm_open.bpf.c` -- simplify verifier-sensitive control flow without changing authorization, audit, rename, or overlay outcomes.
- [x] focused LSM tests -- lock required hook loading and the security invariants affected by the simplification.
- [x] release gate scripts/tests -- ensure a real collection load rejection happens before an immutable GHCR push.
- [x] real E2E -- run the exact UID 1001 mutation regression and full native release-parity workload with `--require-lsm`.

**Acceptance Criteria:**
- Given the exact merged source and release toolchain, when the manager loads enforcement, then every required mutation program is accepted by the kernel verifier.
- Given the #103 declared and undeclared paths, when UID 1001 performs every covered mutation, then all prior allow, denial, audit, cleanup, rename, and overlay assertions still pass.
- Given a verifier rejection, when release preflight runs, then no immutable manager tag or GitHub release is published.

## Spec Change Log

- Implementation replaces the nested 256-rule/64-byte mutation scan with a userspace-derived hash index and at most 64 exact-prefix lookups. Generic and writable-directory denies remain dominant; only explicit RW directory descendants grant mutation authority.
- Fresh releases now run the existing native release verifier against a local host-architecture manager before the immutable manager publication function is reachable. The local preflight image is removed by the release EXIT trap on success or failure.
- Review fix: live mutation-policy reloads now stage a complete inactive generation, atomically flip one active-generation value, and only then clean the old generation; failed staging or activation leaves the prior authority intact. Policy sets above 256 rules are rejected before `OpenLsm` state changes.
- Review fix: the local preflight image tag includes the release temp identity, and cleanup takes ownership only after an explicit collision check proves no pre-existing image uses that tag.

## Design Notes

The verifier result from the exact release-equivalent kernel is authoritative. Source-shape tests may guard invariants but cannot substitute for loading the generated BPF collection.

## Verification

**Commands:**
- `timeout 3m go test ./internal/lsm -run 'DirectoryMutation' -count=1` -- focused mutation policy and hook tests pass.
- bounded real collection-load regression on the release host -- every mandatory mutation program loads under the kernel verifier.
- bounded UID 1001 Docker E2E with `--require-lsm` -- declared operations pass, undeclared sibling fails, audit and cleanup assertions pass.
- bounded dry-run/release-parity script -- verifier/load gate runs before any remote publication and the full native workload passes.
- `git diff --check` -- patch is clean.

**Evidence:** The reviewed, double-buffered manager loaded every mandatory mutation hook on the release host under `--require-lsm` and completed the release-parity workload in 15.37 seconds. `TestRunnerDeclaredDirectoryMutations` passed in 26.87 seconds for UID 1001, including declared operations, sibling/boundary denials, audit assertions, and cleanup. Focused transition tests prove failed staging and failed generation flips preserve the active policy. The full Go suite passed outside the network-restricted sandbox in 16.03 seconds.

## Suggested Review Order

**Mutation enforcement**

- Prefix-indexed decisions remove verifier explosion while keeping fail-closed deny precedence.
  [`lsm_open.bpf.c:391`](../../internal/lsm/bpf/lsm_open.bpf.c#L391)

- Generation switching makes live policy replacement atomic from the kernel's perspective.
  [`file_open.go:373`](../../internal/lsm/file_open.go#L373)

- Early rule-count validation prevents partial kernel or in-memory policy state.
  [`file_open.go:121`](../../internal/lsm/file_open.go#L121)

**Release boundary**

- Real host-kernel enforcement now passes before any immutable manager publication.
  [`release.sh:163`](../../scripts/release.sh#L163)

- Unique local tags and delayed cleanup ownership protect pre-existing images.
  [`release.sh:155`](../../scripts/release.sh#L155)

**Regression evidence**

- Transition and injected-failure tests prove active authority survives reload failures.
  [`directory_mutation_test.go:108`](../../internal/lsm/directory_mutation_test.go#L108)

- Release-contract assertions lock verifier-gate ordering and collision handling.
  [`release_files_test.go:117`](../../internal/releasecontract/release_files_test.go#L117)
