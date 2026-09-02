---
title: 'Leash #82 regression: preserve non-root exec with an idmapped workspace'
type: 'bugfix'
created: '2026-09-02'
status: 'done'
review_loop_iteration: 0
baseline_commit: '82fa1206e606ea30b5c112e7389885c63f3530f7'
context:
  - 'docs/implementation-artifacts/spec-leash-82-nonroot-setgroups.md'
  - 'docs/implementation-artifacts/spec-leash-94-volume-idmap.md'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** Leash #82's procfs path canonicalization works for the original non-root Docker exec, but adding #94's idmapped workspace changes the runtime mount/namespace topology. On the released `native-v0.3.10` stack, runc's post-enforcement `setgroups` reopen is again emitted as `/<pid>/setgroups`, denied by a policy that explicitly permits `/proc/`, and exits 126 before BME starts.

**Approach:** Keep `lsm_open`'s path buffer in a one-entry per-CPU array and use a two-stage tail-call chain: entry path resolution calls a separately verified strict canonicalizer, which calls a separately verified unchanged policy/audit continuation. Two explicit program-array slots are populated by the loader before attach; every scratch lookup, missing slot, or tail-call fallthrough denies. The only rewritten paths are `/<numeric-pid>/setgroups`, `/<numeric-pid>/task/<numeric-tid>/attr/apparmor/exec`, and the exact `/<numeric-pid>/task/<numeric-tid>/fd` directory.

## Boundaries & Constraints

**Always:** Use one map-backed path slot per CPU and deny if its lookup fails; keep the strict matcher `__noinline`; split entry path resolution, strict canonicalization, and unchanged ordinary policy/event evaluation across the entry and two separately verified tail-call targets; populate both explicit program-array slots before attachment and deny on every missing/unpopulated/fallthrough path; identify procfs from kernel filesystem metadata; require one of the three exact approved shapes, with strict numeric components, complete suffixes, exact procfs-root ancestry, and exact mount-relative length; preserve Cedar verdicts/audit, the image's named non-root `Config.User`, HOME, idmapped workspace ownership translation, teardown, and `--require-lsm` behavior; bound every Docker test and remove its containers.

**Ask First:** Any change to the public idmap contract, manager/target trust boundary, Walk or BME, or any namespace-associated procfs canonicalization beyond the three exact approved paths.

**Never:** Change hard-link scope, add public API changes, or tail-call any behavior beyond this file-open continuation; unconditionally allow either control file; special-case a spoofable process name; weaken file policy, LSM, seccomp, or identity enforcement; run the workload as root; remove the existing namespace-detached procfs handling; access or mount credentials; rely only on a mocked regression.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|---------------|----------------------------|----------------|
| Combined released-stack path | Named non-root `Config.User=agent`, idmapped host workspace, `/proc/` permitted, enforcement ready | Numeric-PID `setgroups` and numeric PID/task/TID AppArmor exec controls are evaluated under `/proc/`; post-enforcement command runs as `agent`; idmapped workspace remains usable; both containers are removed | Any setup/exec failure is non-zero and cleans both containers |
| Existing #82 path | Named non-root user without idmap | Existing detached-procfs canonicalization and execution remain unchanged | No regression to prior fix |
| Policy forbids procfs | Same runtime reopen without an applicable `/proc/` permit | Canonical path is denied by normal policy evaluation | Workload does not start; no unconditional runtime exemption |
| runc proc fd handle | Numeric PID/task/TID `fd` directory itself | Exact directory is evaluated as `/proc/<PID>/task/<TID>/fd` by ordinary policy | Descendants and other fd forms are not canonicalized |
| Unrelated procfs path | Namespace-associated procfs path matching neither approved exact shape | Path is not rewritten by the new fallbacks | Existing policy decision remains authoritative |

</frozen-after-approval>

## Code Map

- `internal/lsm/bpf/lsm_open.bpf.c` -- canonicalizes procfs file-open paths before ordered policy evaluation and audit emission.
- `e2e/boot_test.go` -- runs the credential-free named-user Docker regression through the real CLI, manager, LSM, and lifecycle.
- `internal/lsm/` -- generates and loads the eBPF object used by the manager; focused tests guard attach/verifier behavior.

## Tasks & Acceptance

**Execution:**
- [x] `internal/lsm/bpf/lsm_open.bpf.c` -- keep the open path in a fail-closed one-entry per-CPU map; dispatch through two fail-closed program-array slots so strict three-shape canonicalization and unchanged Cedar policy/audit flow are separately verified.
- [x] `internal/lsm/file_open.go` and focused loader tests -- populate both continuation slots before attach, reject either missing program/map resource, and lock both fail-closed fallthroughs without changing hard-link loading.
- [x] `e2e/boot_test.go` -- add a bounded real-Docker case combining named UID 1001, an idmapped host workspace, post-enforcement exec, identity/translated-write assertions, and teardown assertions.
- [x] Generated eBPF artifacts -- regenerate for verification only and commit only source-controlled outputs required by repository convention.

**Acceptance Criteria:**
- Given the exact `native-v0.3.10` failure topology with `Config.User=agent` and an idmapped workspace, when enforcement is ready and Leash performs workload exec, then the harmless command starts as UID 1001, can write through the mapped workspace, and exits zero.
- Given the same reopen but no applicable `/proc/` permission, when the canonical path reaches policy evaluation, then Leash remains fail-closed and the workload does not start.
- Given either approved runtime-control reopen, when it is audited, then the event path uses its `/proc/...` form and the existing policy decision remains authoritative.
- Given success or failure, when the run ends, then target and manager containers are absent.

## Spec Change Log

- 2026-09-02 -- Human approved adding the AppArmor exec control after the first combined Docker regression proved the numeric-PID `setgroups` repair advanced runc to this second procfs denial. Initial wording used runc's logical `/thread-self/attr/apparmor/exec` label.
- 2026-09-02 -- Human approved correcting that ineffective logical form to the kernel-visible `/<numeric-pid>/task/<numeric-tid>/attr/apparmor/exec` path observed by the BPF `file_open` hook. The correction replaces rather than broadens the matcher; these remain the only two namespace-associated shapes, both under ordinary policy evaluation.
- 2026-09-02 -- Human approved replacing `lsm_open`'s stack path with a one-entry per-CPU array after strict inline matching exceeded the verifier instruction budget and strict `__noinline` matching proved runtime-indexed caller-stack reads invalid. Lookup fails closed; the matcher stays `__noinline`; policy and event flow are unchanged. Tail calls and public/loader changes remain excluded.
- 2026-09-02 -- Human approved one same-architecture verifier correction after passing the map pointer into `__noinline` lost bounds provenance: the matcher looks up the per-CPU slot locally and receives only scalar metadata. Its lookup returns a distinct failure that the caller denies; a normal non-match remains separate.
- 2026-09-02 -- Human approved a file-open-only tail-call split after locally map-provenance-bound runtime indexing still failed verification. The per-CPU path scratch remains; a one-entry program array routes to a separately verified canonicalization/policy/audit continuation, is populated before attach, and fails closed on fall-through or missing resources. Hard-link scope is unchanged.
- 2026-09-02 -- Human approved splitting the oversized combined continuation into two separately verified stages: entry path resolution -> strict two-shape canonicalizer -> unchanged policy/audit continuation. The program array now has two explicit slots, the loader must populate both before attachment, and every absent slot or tail-call fallthrough fails closed. No path shape or policy behavior changes.
- 2026-09-02 -- Human approved replacing the verifier-heavy sequential path-string DFA with exact procfs dentry-ancestry recognition inside the existing canonicalizer stage. Literal components use exact kernel qstr lengths/bytes, PID and TID components require 1-10 decimal digits, and the numeric PID parent must be the procfs mount root. The same two paths and policy behavior remain frozen.
- 2026-09-02 -- The approved ancestry representation is constrained by the exact expected mount-relative path length derived from trusted qstr lengths. `/proc` is prefixed only when `bpf_d_path` returns that exact length including NUL; already canonical `/proc/...` and custom visible proc mountpoints are left unchanged. This corrects double-prefixing without adding a path shape.
- 2026-09-02 -- Human approved the third exact kernel-visible runtime directory after the corrected stack advanced to runc's fd-handle reopen: `/<numeric-PID>/task/<numeric-TID>/fd` only. It requires exact literal/numeric procfs-root ancestry and the exact mount-relative length including NUL, then follows ordinary Cedar policy/audit. Descendants and every other fd form remain excluded.

## Design Notes

The reproduced event stream is decisive: before the combined path, `/proc/1158/setgroups` is allowed; the later exec emits `/1165/setgroups` and is denied. After repairing that shape, runc reports a logical `/thread-self/attr/apparmor/exec` denial; successful BPF audit evidence shows that the kernel resolves it to `/proc/<pid>/task/<tid>/attr/apparmor/exec` before `file_open`, making the failing mount-relative form numeric too. #83 already trusts procfs superblock metadata but gates rewriting on a null mount namespace. The extension relaxes that topology assumption only for the two approved exact kernel control paths. The per-CPU map follows existing mutation/hard-link scratch semantics: BPF hook execution is CPU-pinned and non-recursive for the helpers used, so concurrent CPUs cannot collide while runtime indexing is verifier-valid map-value access rather than forbidden variable stack access.

The strict namespace-associated recognition reads the trusted `file->f_path.dentry` ancestry instead of reparsing `bpf_d_path` output. It accepts only `setgroups <- numeric PID <- procfs root` or `exec <- apparmor <- attr <- numeric TID <- task <- numeric PID <- procfs root`; every literal has exact qstr length and bytes and numeric components are bounded to the kernel's sane 1-10 digit PID/TID range. Only then is the already-resolved path prefixed with `/proc` and passed to the unchanged policy continuation.

## Verification

**Commands:**
- `make lsm-generate` -- expected: the changed program compiles and the generated object is accepted by the verifier.
- `go test ./internal/lsm ./internal/runner -count=1 -timeout 5m` -- expected: focused enforcement and runner tests pass.
- `go test ./e2e -run 'NonRoot.*Idmap' -v -count=1 -timeout 4m` with local target/manager image variables -- expected: real Docker command runs as UID 1001, translated write succeeds, and cleanup assertions pass.
- `go test ./... -count=1 -timeout 10m && git diff --check` -- expected: complete suite and patch validation pass.

## Suggested Review Order

**Enforcement architecture**

- Start with the two-stage fail-closed dispatcher and unchanged policy continuation.
  [`lsm_open.bpf.c:802`](../../internal/lsm/bpf/lsm_open.bpf.c#L802)

- Verify exact trusted ancestry, component bounds, and mount-relative length discrimination.
  [`lsm_open.bpf.c:680`](../../internal/lsm/bpf/lsm_open.bpf.c#L680)

- Confirm both continuation slots are validated and populated before attachment.
  [`file_open.go:178`](../../internal/lsm/file_open.go#L178)

**Regression evidence**

- Follow the real UID1001 idmap success, ownership, and cleanup assertions.
  [`boot_test.go:313`](../../e2e/boot_test.go#L313)

- Check the audited proc denial and workload-never-started control.
  [`boot_test.go:400`](../../e2e/boot_test.go#L400)

- Review focused missing-slot, fallthrough, and exact-shape source contracts.
  [`open_tailcall_test.go:12`](../../internal/lsm/open_tailcall_test.go#L12)
