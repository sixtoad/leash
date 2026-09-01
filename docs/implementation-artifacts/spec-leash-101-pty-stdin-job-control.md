---
title: 'Leash #101: avoid PTY job-control stop in noninteractive container exec'
type: 'bugfix'
created: '2026-08-31'
status: 'done'
review_loop_iteration: 0
baseline_commit: '16b46ac26f3f2e960b327b96a14b6ce8178c4502'
context:
  - 'docs/implementation-artifacts/spec-leash-84-release-parity.md'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** A noninteractive Leash container command always uses `docker exec -i`. When Leash inherits a terminal but runs in a background process group—such as the release verifier's `(...) | tee` pipeline—the Docker client reads that terminal and is stopped by job-control `SIGTTIN`; the workload never appears in the target container and the release gate times out.

**Approach:** Select the container exec input flag from both execution mode and actual stdin kind. Noninteractive execution keeps `-i` for pipe/file stdin, where input forwarding is required, and omits it for terminal stdin, where `--no-interactive` must not read the terminal; interactive execution remains `-it`.

## Boundaries & Constraints

**Always:** Preserve piped and redirected stdin for noninteractive workloads; preserve byte-direct workload stdout/stderr; preserve `-it` interactive behavior; keep one argument-construction boundary for all target workload execs; add a regression that proves the terminal/non-terminal distinction.

**Ask First:** Changing the public CLI contract of `--no-interactive` or `--machine-output`, changing container runtime support, or changing release artifact/version policy.

**Never:** Disable enforcement/readiness, weaken the Cedar policy, add sleeps or longer timeouts, special-case the release script, unconditionally remove `-i`, rebuild or overwrite the partially published `native-v0.3.7` manager tag, or change native-runtime behavior.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|---------------|----------------------------|----------------|
| Terminal, noninteractive | `--no-interactive` or machine mode; stdin is a terminal | Build `docker exec` without `-i`; command starts without reading the background PTY | Return the workload/runtime error normally; never wait for terminal input |
| Pipe or redirected file, noninteractive | stdin is not a terminal | Build `docker exec -i`; forward input unchanged | Preserve existing exit-code and stderr behavior |
| Interactive | interactive mode with terminal | Build `docker exec -it` | Preserve existing precheck and manual-attach diagnostics |
| Native runtime | container-free launcher | No behavior or argument changes | Existing native tests remain green |

</frozen-after-approval>

## Code Map

- `internal/runner/launcher.go` -- container launcher chooses `-i` versus `-it` before constructing workload exec arguments.
- `internal/runner/runner.go` -- execution-mode routing, terminal detection, direct stdio attachment, and centralized `targetWorkloadExecArgs`.
- `internal/runner/target_user_test.go` -- existing exact-argv coverage for container workload execution.
- `internal/runner/machine_output_test.go` -- noninteractive/machine-output command construction and byte-pure output contract.
- `scripts/verify-native-release.sh` -- release pipeline that exposes the background-PTY job-control failure through `(...) | tee`.

## Tasks & Acceptance

**Execution:**
- [x] `internal/runner/launcher.go`, `internal/runner/runner.go` -- make noninteractive container exec input attachment conditional on whether stdin is a terminal, without affecting native or interactive launchers.
- [x] `internal/runner/target_user_test.go` and/or `internal/runner/machine_output_test.go` -- cover terminal noninteractive (no flag), pipe/file noninteractive (`-i`), and interactive (`-it`) exact arguments.
- [x] Focused PTY regression surface -- prove the prior background-PTY shape no longer stops before workload start, using existing test helpers if it can remain deterministic and fast.

**Acceptance Criteria:**
- Given Leash inherits a PTY while its verifier pipeline places it in a background process group, when a noninteractive container workload starts, then Docker does not read that PTY and the workload completes instead of entering stopped state.
- Given non-terminal stdin, when a noninteractive workload reads input, then bytes are still forwarded through `docker exec -i` unchanged.
- Given interactive mode, when a workload starts, then its command still uses `-it`.
- Given the focused runner tests and release parity verification, when they run with bounded timeouts, then they pass without weakening LSM readiness or policy enforcement.

## Spec Change Log

## Design Notes

The regression depends on job-control, not on the eBPF hooks: the exact v0.3.7 binary, manager digest, and policy completed in 5.3 seconds with non-PTY stdin. Under a PTY, `DetectShell` (no IO flag) completed, while the following `docker exec -i` processes entered `STAT=T` and no workload process appeared in `docker top`. Terminal detection therefore belongs at command construction, before Docker is allowed to read stdin.

## Verification

**Commands:**
- `timeout 3m go test ./internal/runner -run 'Test.*(Exec|Machine|Target|Stdin|Terminal)' -count=1` -- expected: exact flag-selection and existing output/identity contracts pass.
- `timeout 5m go test ./internal/runner -count=1` -- expected: complete runner package passes.
- `timeout 4m scripts/verify-native-release.sh <stamped-cli> <immutable-manager-ref> <revision>` -- expected: PTY pipeline prints `LEASH84_USER=agent`, exits, and removes both containers.
- `git diff --check` -- expected: no whitespace errors.

## Suggested Review Order

**Container execution boundary**

- Detect real terminal stdin before selecting Docker input attachment.
  [`launcher.go:212`](../../internal/runner/launcher.go#L212)

- Preserve `-i` for redirected input and `-it` for interactive sessions.
  [`launcher.go:220`](../../internal/runner/launcher.go#L220)

**Regression coverage**

- Lock every terminal, pipe/file, character-device, and interactive flag combination.
  [`target_user_test.go:276`](../../internal/runner/target_user_test.go#L276)
