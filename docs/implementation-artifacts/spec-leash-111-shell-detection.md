---
title: 'Leash #111: bound container shell detection without login profiles'
type: 'bugfix'
created: '2026-09-17'
status: 'done'
review_loop_iteration: 0
baseline_commit: '656c7909c3cbe87627ddd5a36988543e8e660b67'
context:
  - 'docs/architecture-leash-core.md'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** Container shell discovery runs `bash -lc true` and then `sh -lc true`. A login shell reads the target user's profile after enforcement is active; when policy denies that read, the probe can hang indefinitely before the governed command starts.

**Approach:** Probe candidate shells in non-login mode under an independent timeout for each candidate. Preserve the workload exec path, identity, work directory, environment, TTY selection, and enforcement policy, while returning bounded diagnostics that identify failed and timed-out probes.

## Boundaries & Constraints

**Always:** Run each probe as the captured target image user and configured work directory; let parent cancellation terminate the active runtime command; stop probing after cancellation; ensure normal lifecycle cleanup receives a usable context; report the candidate shell and whether it failed or timed out; retain existing bash-before-sh selection and all workload I/O behavior.

**Ask First:** Changing the public CLI, changing the final governed shell's login semantics, changing the launcher interface, or adding runtime-specific behavior beyond Docker-compatible engines.

**Never:** Permit `.profile` or another home path to make detection work; weaken LSM/file/network policy; detach or background a probe; extend readiness timeouts; retain a container after a canceled probe; change the native launcher.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|---------------|---------------------------|----------------|
| Bash available | `bash -c true` succeeds | Select `bash` promptly with target identity and work directory | None |
| Bash unavailable | Bash exits; `sh -c true` succeeds | Select `sh` | Retain bash failure only if all candidates fail |
| Probe hangs | Candidate exceeds its own budget | Terminate it and try the next candidate | Final error identifies the timed-out candidate and duration |
| Parent canceled | Context canceled during an active probe | Terminate the probe, skip remaining candidates, and enter normal cleanup | Return an error wrapping `context.Canceled` |
| No shell works | Both candidates exit or time out | Do not start the workload | Return concise diagnostics for both candidates |

</frozen-after-approval>

## Code Map

- `internal/runner/launcher.go` -- container shell selection and workload command construction.
- `internal/runner/runtime.go` -- Docker-compatible command abstraction used to preserve runtime environment configuration.
- `internal/runner/target_user_test.go` -- exact target identity/work-directory argument coverage for container execution.
- `internal/runner/runner.go` -- lifecycle routing and canceled-context cleanup fallback.
- `e2e/boot_test.go` -- gated real-container non-root runner regressions.

## Tasks & Acceptance

**Execution:**
- [x] `internal/runner/launcher.go` -- add non-login, independently timed shell probes with bounded stderr details and cancellation-aware fallback.
- [x] `internal/runner/target_user_test.go` -- cover exact non-login argv, fallback, both-failed diagnostics, timeout, and active cancellation.
- [x] `internal/runner/target_user_test.go` -- prove canceled detection can still remove target and manager containers with usable cleanup contexts.
- [x] `e2e/boot_test.go` -- assess a gated named-user unreadable-profile regression; do not add it because the preserved final workload intentionally remains a login shell, so the same profile can block after the probe and would not isolate this fix without artificial fixture behavior or widening scope.

**Acceptance Criteria:**
- Given a named non-root target whose `.profile` cannot be read, when container shell discovery runs after enforcement, then no probe sources that profile and the governed command starts.
- Given any shell candidate does not answer, when its probe budget expires, then Leash terminates that probe and either tries the next candidate or returns an error naming the timeout.
- Given the run context is canceled during detection, when detection returns, then no fallback probe starts and ordinary disposable container state is removed.
- Given existing noninteractive and interactive execution modes, when the workload command is built, then target user, work directory, runtime environment, stdin forwarding, and `-it` behavior remain unchanged.

## Spec Change Log

## Design Notes

The probe uses the runtime's `Cmd` construction seam rather than a raw host command so Docker/Podman selection and configured runtime environment remain intact. Probe-only `BASH_ENV` and `ENV` overrides plus Bash's `--noprofile --norc` prevent shells from reaching user startup files; the final workload still receives its original environment. Capturing only a small, sanitized stderr prefix makes failures actionable without allowing unbounded engine output into the final error. Per-candidate contexts distinguish a local deadline from parent cancellation. The local runtime-client timeout is a backstop, not a remote process manager: a normal candidate failure may fall back, but a timeout is terminal so lifecycle cleanup removes the disposable container rather than starting another exec beside a potentially live server-side probe.

## Verification

**Commands:**
- `go test ./internal/runner -run 'TestContainerLauncherDetectShell|TestContainerLauncherWorkloadPathsUseCapturedIdentity' -count=1` -- expected: non-login argv, identity, fallback, timeout, cancellation, and diagnostics pass.
- `go test ./internal/runner -count=1` -- expected: runner behavior remains green.
- `git diff --check` -- expected: no whitespace errors.

**Not run:** A real unreadable-profile container regression was assessed but not added: the intentionally preserved final workload uses a login shell, so that fixture would also affect the workload wrapper and would not isolate probe behavior without artificial profile logic or a broader semantic change.

## Suggested Review Order

**Probe lifecycle**

- Start with candidate fallback, cancellation, and terminal timeout decisions.
  [`launcher.go:212`](../../internal/runner/launcher.go#L212)

- Review bounded non-login execution and capped diagnostics.
  [`launcher.go:243`](../../internal/runner/launcher.go#L243)

- Confirm interactive reachability uses the same protected probe path.
  [`launcher.go:349`](../../internal/runner/launcher.go#L349)

**Argument and cleanup invariants**

- Verify probe-only environment overrides preserve workload execution arguments.
  [`runner.go:3139`](../../internal/runner/runner.go#L3139)

- Confirm canceled lifecycle cleanup replaces unusable contexts before removal.
  [`runner.go:3184`](../../internal/runner/runner.go#L3184)

**Regression coverage**

- Check exact probe, workload, identity, environment, and TTY argv contracts.
  [`target_user_test.go:271`](../../internal/runner/target_user_test.go#L271)

- Check bounded failures, terminal timeouts, cancellation, and cleanup regressions.
  [`target_user_test.go:440`](../../internal/runner/target_user_test.go#L440)
