---
title: 'Leash #82: preserve non-root container execution after enforcement'
type: 'bugfix'
created: '2026-08-29'
status: 'done'
review_loop_iteration: 0
baseline_commit: '43e8715351acf0483e25b9f195ce623d6fd42f2f'
context:
  - 'docs/design/BOOT.md'
  - 'docs/design/SECURITY-MODEL.md'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** After Leash bootstraps a Docker target and attaches file-open enforcement, an interactive workload using the image's non-root user fails before its command starts. The file-open LSM resolves runc's detached procfs reopen of `proc/self/setgroups` as `/<pid>/setgroups`, so an existing `/proc/` policy does not match and runc exits 126.

**Approach:** Canonicalize only mount-relative procfs paths into the `/proc/...` policy namespace before normal policy evaluation, preserving deny-by-default semantics and the image's configured user. Avoid optional system prompt writes for non-root images and cleanly tear down when the interactive precheck fails.

## Boundaries & Constraints

**Always:** Keep the image `Config.User` as the identity for shell detection, precheck, interactive, and non-interactive commands. Identify procfs using kernel filesystem metadata; send its canonical path through the existing ordered policy evaluator and event log. Keep prompt installation optional. Preserve the workload exit-code contract and bounded cleanup.

**Ask First:** Any solution requiring broader capabilities, privileged workload execution, a policy-wide allow, a change to Walk/BME, or a change to the manager/target trust boundary.

**Never:** Add `sudo` to the target image; execute BME or the workload as root; special-case `runc` by spoofable process name; unconditionally allow `setgroups`; widen `/`, procfs, or file-write policy; read/mount Codex credentials; retain broken containers with an attach command that follows the same failing path.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Non-root interactive command | Docker image `Config.User=agent`; policy permits `/proc/`; runc reopens detached procfs `/<pid>/setgroups` | Path is evaluated/logged as `/proc/<pid>/setgroups`; harmless command runs as `agent` | No privilege widening or identity fallback |
| Procfs remains forbidden | Policy does not permit the canonical procfs path | Existing policy evaluator denies the reopen | Workload does not start; Leash removes both containers and returns an actionable error |
| Ordinary path | Non-procfs file or already absolute `/proc/...` path | Existing path and decision remain unchanged | No aliasing or duplicate prefix |
| Optional prompt | Target image has a non-root configured user | System prompt installation is skipped deterministically | No duplicate warning; command execution continues |

</frozen-after-approval>

## Code Map

- `internal/lsm/bpf/lsm_open.bpf.c` -- resolves file-open paths and applies ordered allow/deny policy in the target cgroup.
- `internal/runner/runner.go` -- preserves target identity, installs optional prompts, performs the interactive precheck, and controls lifecycle cleanup.
- `internal/runner/target_user_test.go` -- unit coverage for configured image identities and all workload exec paths.
- `e2e/boot_test.go` -- Docker-backed bootstrap/lifecycle regression surface.

## Tasks & Acceptance

**Execution:**
- [x] `internal/lsm/bpf/lsm_open.bpf.c` -- recognize mount-relative procfs paths from trusted filesystem metadata and canonicalize them before the unchanged policy check/log emission.
- [x] `internal/runner/runner.go` -- skip system prompt installation for a non-root configured target and let precheck errors follow normal teardown instead of retaining unusable containers.
- [x] `internal/runner/target_user_test.go` -- cover root/non-root prompt behavior, identity preservation, and precheck cleanup/message semantics.
- [x] `e2e/boot_test.go` -- add a Linux Docker regression using a named non-root image user, a `/proc/` allow, and a harmless interactive command; assert identity, exit success, and teardown.
- [x] Regenerate ignored eBPF build artifacts for verification; commit only source-controlled changes.

**Acceptance Criteria:**
- Given released-stack-equivalent Docker inputs with `Config.User=agent`, when Leash attaches enforcement and starts an interactive harmless command, then the command executes as `agent` and both containers are removed afterward.
- Given runc opens mount-relative procfs `setgroups`, when file-open policy is evaluated, then the event and decision use `/proc/<pid>/setgroups` and an explicit `/proc/` rule remains authoritative.
- Given the same image and a policy that forbids the canonical procfs path, when the precheck fails, then Leash returns non-zero, removes its target and manager containers, and does not suggest an equivalent broken attach command.
- Given a non-root configured image user, when optional prompt setup is reached, then Leash skips system-wide profile writes without changing workload identity or emitting duplicate warnings.

## Spec Change Log

## Design Notes

The observed distinction is filesystem attribution, not DAC: earlier ordinary runc opens logged `/proc/1092/setgroups` and passed; the interactive reopen logged `/1112/setgroups` and was denied. Canonicalization must therefore be based on procfs mount metadata and feed the normal path-policy engine. It must not become a runtime-process allowlist.

## Verification

**Commands:**
- `go test ./internal/runner ./internal/lsm` -- expected: focused unit tests pass.
- `make lsm-generate` -- expected: the changed eBPF source compiles and loads through generated bindings.
- Focused `e2e/boot_test.go` Docker test under a 10-minute timeout -- expected: command prints the non-root identity, exits zero, and leaves no test containers.
- `go test ./...` and `git diff --check` -- expected: repository suite and whitespace validation pass.

## Suggested Review Order

**Procfs policy attribution**

- Canonicalizes only namespace-detached procfs PID paths before ordinary policy evaluation.
  [`lsm_open.bpf.c:328`](../../internal/lsm/bpf/lsm_open.bpf.c#L328)

- Applies the canonical path to both enforcement and event emission.
  [`lsm_open.bpf.c:402`](../../internal/lsm/bpf/lsm_open.bpf.c#L402)

**Non-root lifecycle**

- Skips optional system prompt writes for configured non-root workloads.
  [`launcher.go:214`](../../internal/runner/launcher.go#L214)

- Routes failed interactive prechecks through normal container teardown.
  [`runner.go:1674`](../../internal/runner/runner.go#L1674)

**Regression evidence**

- Exercises fail-closed file-open enforcement with the named non-root Docker user.
  [`boot_test.go:254`](../../e2e/boot_test.go#L254)

- Locks prompt identity and failed-precheck cleanup behavior at the runner seam.
  [`target_user_test.go:187`](../../internal/runner/target_user_test.go#L187)
