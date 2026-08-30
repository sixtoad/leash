---
title: 'Idmap workspace binds before non-root container workload exec'
type: 'bugfix'
created: '2026-08-30'
status: 'ready-for-dev'
review_loop_iteration: 0
context:
  - '{project-root}/docs/integration-architecture.md'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** A host-owned workspace bind keeps host UID/GID 1000 inside a target image whose configured agent identity is UID/GID 1001. The preserved non-root agent therefore cannot create BME state or edit source during the Walk/Leash/Codex dogfood run.

**Approach:** Add an explicit per-volume idmap option for the container backend. During Leash's existing privileged bootstrap gate, replace only those declared target bind mounts with kernel-idmapped views mapping the host root owner's UID/GID to the unchanged numeric UID/GID behind the image's exact `Config.User`, then run the workload with that original identity.

## Boundaries & Constraints

**Always:** Make the feature opt-in per volume; accept absolute host and container paths only; resolve and validate all declarations before workload execution; preserve the exact `Config.User`, image environment/HOME, credential mounts, policy attachment, and non-root exec path; apply mappings only from the privileged manager bootstrap boundary; return actionable errors for unsupported runtime, kernel, filesystem, identity, path, or conflicting mappings; rely on ordinary container teardown to destroy all temporary namespace/mount state on success, failure, cancellation, and signals.

**Ask First:** Any public syntax other than a repeatable `--idmap-volume <src:dst[:ro]>`, or any requirement to support a non-Linux/non-Docker runtime in this issue.

**Never:** Chown or otherwise mutate host ownership; stage source content elsewhere; run the governed workload as root; rewrite the image's configured identity; alter HOME; grant mount capabilities to the workload; weaken Leash policy/seccomp/LSM enforcement; silently fall back to a normal bind when idmapping fails; scan or modify undeclared mounts.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|---------------|----------------------------|----------------|
| Workspace mismatch | Host directory owned 1000:1000, image user `agent` resolves 1001:1001 | Agent creates/edits through an idmapped view; host files remain 1000:1000 | N/A |
| Named image identity | `Config.User=agent` with image HOME | Workload exec remains `agent`; its image HOME stays writable and unchanged | Fail before agent exec if identity cannot resolve uniquely |
| Read-only mapping | `--idmap-volume host:target:ro` | Ownership is translated but writes remain denied | N/A |
| Unsafe/conflicting declaration | Relative, missing, duplicate, nested, or conflicting target | No workload executes | Report the offending declaration/path |
| Unsupported host | Non-Linux, non-Docker, missing idmapped-mount syscalls, or unsupported backing filesystem | No workload executes and no ordinary-bind fallback occurs | Report the failed prerequisite/syscall |

</frozen-after-approval>

## Code Map

- `internal/runner/runner.go` -- CLI contract, volume validation, target identity capture, Docker launch arguments, and manager bootstrap payload.
- `internal/runner/launcher.go` -- container lifecycle boundary that gates idmap preparation before manager readiness/workload exec.
- `cmd/leash-entry/main.go` -- image-local resolver for named/numeric `Config.User` without changing the workload identity.
- `internal/leashd/runtime.go` -- earliest privileged manager startup gate, before enforcement readiness is published.
- `internal/idmap/` -- Linux mount-namespace/idmapped-mount implementation plus unsupported-platform fail-closed stub.
- `internal/runner/runner_args_test.go`, `internal/runner/target_user_test.go`, `internal/idmap/*_test.go`, `e2e/` -- parser, identity/bootstrap contract, syscall validation, and real Docker/kernel ownership proof.

## Tasks & Acceptance

**Execution:**
- [ ] `internal/runner/runner.go`, `internal/runner/launcher.go` -- add and validate `--idmap-volume`, resolve host owner plus target numeric identity, pass a bounded bootstrap payload, and share the target PID namespace only when required.
- [ ] `cmd/leash-entry/main.go` -- expose a private argv-safe identity resolver using the target image's own passwd/group database.
- [ ] `internal/idmap/`, `cmd/leash/main.go`, `internal/leashd/runtime.go` -- create short-lived mapped user namespaces, enter the target mount namespace, atomically install idmapped mount clones, restore the manager thread namespace, and fail closed.
- [ ] Focused unit and Linux Docker E2E tests -- cover parsing/conflicts, named identity preservation, unsupported paths, UID/GID translation, host ownership, HOME, and read-only behavior.
- [ ] Usage/docs -- document the opt-in contract and unsupported-runtime behavior for Walk #67.

**Acceptance Criteria:**
- Given a host-1000 workspace and an image configured as named user `agent` UID/GID 1001, when Leash runs with that bind declared idmapped, then the agent edits it as 1001 while resulting host files are 1000:1000 and image HOME remains the named user's writable HOME.
- Given any idmap bootstrap failure, when the runner has not yet crossed `WaitReady`, then Leash tears down the containers and never invokes the agent.
- Given no idmapped volumes, when Leash runs, then container arguments and privilege/namespace exposure remain unchanged.

## Spec Change Log

## Design Notes

The target starts temporarily as root in `leash-entry` and remains idle until the manager becomes ready; all governed commands later use the captured exact image identity. For requested mappings only, the privileged manager joins the target PID namespace, temporarily enters PID 1's mount namespace, installs detached idmapped clones with `open_tree`/`mount_setattr(MOUNT_ATTR_IDMAP)`/`move_mount`, restores its own namespace, and publishes readiness. The user-namespace holder exits after the mount takes its own namespace reference, leaving no helper process.

## Verification

**Commands:**
- `go test ./internal/runner ./internal/idmap ./cmd/leash-entry` -- parser, validation, identity, and bootstrap contracts pass.
- `go test ./e2e -run Idmap -v -count=1 -timeout 3m` -- supported Linux Docker host proves translated writes, unchanged host ownership, preserved identity/HOME, and read-only denial; otherwise reports an explicit environment skip.
- `go test ./... -timeout 10m` -- complete Go suite passes.
- `go vet ./... && git diff --check` -- static checks and patch formatting pass.
