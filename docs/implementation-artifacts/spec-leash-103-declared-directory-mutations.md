---
title: 'Leash #103 declared directory mutations'
type: 'bugfix'
created: '2026-09-01'
status: 'done'
review_loop_iteration: 0
baseline_commit: '05ec988a1ea7b5f7b7cde5b3859d55465128bc9e'
context: []
---

<frozen-after-approval reason="issue acceptance is approved human-owned intent">

## Intent

**Problem:** Linux enforcement only observes `file_open`, so a writable Cedar directory allows file opens but denies directory mutations such as `mkdir` before they reach that hook.

**Approach:** Enforce Linux `path_*` mutation hooks using the existing `FileOpenReadWrite` directory rules and report the concrete operation and path.

## Boundaries & Constraints

**Always:** Preserve default deny, `--require-lsm`, #98 image-root writes, named non-root operation, and cleanup. Authorize only descendants of an explicitly writable directory.

**Ask First:** Any broader Cedar action, whole-home grant, compatibility degradation, or release change.

**Never:** Touch credentials, network, release machinery, or make path mutation hooks best-effort.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Declared tree | RW directory rule | mkdir, write, rename, unlink, rmdir succeed | Action and path are logged |
| Undeclared sibling | Same Unix owner, no rule | mutation denied | EACCES and actionable denial |

</frozen-after-approval>

## Code Map

- `internal/lsm/bpf/lsm_open.bpf.c` -- kernel path policy and mutation hooks
- `internal/lsm/file_open.go` -- required attachments and event naming
- `internal/lsm/directory_mutation_test.go` -- focused mapping/source tests
- `e2e/directory_mutation_test.go` -- opt-in real Docker regression

## Tasks & Acceptance

**Execution:**
- [x] `internal/lsm/bpf/lsm_open.bpf.c` -- add required path hooks sharing RW directory rules.
- [x] `internal/lsm/file_open.go` -- attach hooks fail-closed and name mutation events.
- [x] `internal/lsm/directory_mutation_test.go` -- verify mapping, required attachment, and denial reporting.
- [x] `e2e/boot_test.go` -- prove named UID 1001 allowed operations, sibling denial, and cleanup.

**Acceptance Criteria:**
- Given `/home/agent/.npm/` is RW and its sibling is undeclared, when UID 1001 mutates descendants, then allowed-tree operations succeed and sibling operations fail without broader grants.
- Given a mutation is denied, when its event is consumed, then the log identifies operation and path.

## Spec Change Log

- Step 4 security review: mutation misses now default deny independently of open defaults; directory rules grant descendants, not mutation of the declared directory itself; dentry reads are checked; unresolved paths emit actionable denials. Retained the required hooks, explicit RW authority, operation-bounded overlay correlation, and synthetic UID-1001 regression.
- Final edge review: generic forbids now dominate mutation allows regardless of rule order; io_uring workers cannot retain overlay correlation; correlation installation fails closed; rename source/destination checks are split into ordered required hooks so one success event follows two successful checks. The existing hard-link component read is constant-bounded and helper failure fails closed, keeping all required programs below the kernel verifier limit.

## Design Notes

The `FileOpenReadWrite` directory rule is the authority. Mutation hooks require a directory rule and treat both rename endpoints independently; file rules do not implicitly grant parent mutation.

## Verification

**Commands:**
- `go test ./internal/lsm -run 'DirectoryMutation' -count=1` -- focused unit tests pass.
- opt-in Docker regression -- real fail-closed LSM behavior passes or reports an exact host blocker.
- `git diff --check` -- clean patch.

**Evidence:** The synthetic UID-1001 Docker regression passed under `--require-lsm`: declared mkdir/create/write/rename/unlink/rmdir completed, the undeclared sibling was denied, the exact success sentinel was emitted, and cleanup removed target, manager, and fixture image.

## Suggested Review Order

**Policy and enforcement**

- Writable-directory policy is isolated from ordinary open defaults and forbids still win.
  [`lsm_open.bpf.c:290`](../../internal/lsm/bpf/lsm_open.bpf.c#L290)

- Mutation paths are reconstructed fail-closed before any policy decision or audit event.
  [`lsm_open.bpf.c:388`](../../internal/lsm/bpf/lsm_open.bpf.c#L388)

- Rename uses chained required hooks to enforce both endpoints within verifier limits.
  [`lsm_open.bpf.c:570`](../../internal/lsm/bpf/lsm_open.bpf.c#L570)

- Overlay correlation rejects unsafe worker lifetimes and preserves prior LSM denials.
  [`lsm_open.bpf.c:497`](../../internal/lsm/bpf/lsm_open.bpf.c#L497)

**Loader and audit integration**

- Every mutation hook is mandatory, including both halves of rename enforcement.
  [`file_open.go:161`](../../internal/lsm/file_open.go#L161)

**Regression evidence**

- Real Docker coverage proves UID 1001 behavior, audit output, denial boundaries, and cleanup.
  [`boot_test.go:312`](../../e2e/boot_test.go#L312)

- Focused tests lock source guards, hook requirements, and operation/path naming.
  [`directory_mutation_test.go:15`](../../internal/lsm/directory_mutation_test.go#L15)
