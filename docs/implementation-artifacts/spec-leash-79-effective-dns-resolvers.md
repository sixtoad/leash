---
title: 'Leash #79: effective DNS resolver contract'
type: 'feature'
created: '2026-08-26'
status: 'done'
review_loop_iteration: 0
baseline_commit: '7e7563a'
context:
  - '{project-root}/docs/api-contracts-leash-core.md'
  - '{project-root}/docs/NATIVE-ENFORCEMENT-RUNBOOK.md'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** An orchestrator must authorize DNS before launching Leash, but native Leash replaces the workload resolver file with its own public resolvers while container engines manage a different resolver file. Leash currently provides no bounded machine contract identifying which side owns discovery, so Walk either authorizes the wrong addresses or duplicates Leash internals.

**Approach:** Add `leash resolvers --runtime <native|docker|podman> --json` and advertise it as the additive `resolver-contract-json` capability. The versioned JSON union reports a canonical resolver list for Leash-managed native runs and explicit runtime-managed delegation for Docker/Podman, with the native document derived from the same resolver source used to write `resolv.conf` and firewall DNS egress.

## Boundaries & Constraints

**Always:** Require an explicit supported runtime; render the complete document before writing stdout; normalize IP literals with `net/netip`; remove IPv4-mapped IPv6 zones, deduplicate, and sort deterministically; cap the resolver count; return a non-zero exit with an empty stdout when validation or rendering fails; write usage and errors only to stderr; preserve the exact resolver set used by native `resolv.conf` and egress rules.

**Ask First:** Changing native resolver addresses, probing a container/image, changing the existing CLI contract-version range, or changing native egress behavior beyond making its resolver source shared and validated.

**Never:** Claim native addresses for container runs; read host `/etc/resolv.conf` as the native answer; launch a workload; require credentials; add #74 reversed-address compatibility; broaden network policy; modify Walk; or fix unrelated defects.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|---------------|----------------------------|----------------|
| Native | `--runtime native --json`; valid source contains IPv4/IPv6 and duplicates | `schemaVersion: 1`, `strategy: "leash-managed"`, canonical sorted unique `resolvers` | Invalid, empty, or over-limit source exits non-zero without stdout |
| Container | `--runtime docker|podman --json` | `strategy: "runtime-managed"`, empty `resolvers`, and an explicit instruction to inspect the target runtime's effective `/etc/resolv.conf` | No native resolver is emitted as fallback |
| Bad invocation | missing/unknown runtime, positional argument, missing `--json`, or contradictory flags | No contract document | Usage/error goes to stderr and exit is non-zero |
| Delivery failure | JSON builds successfully but stdout writer fails | No success exit | Return an internal error without diagnostics on stdout |

</frozen-after-approval>

## Code Map

- `internal/runner/launcher_native.go` -- owns the resolver addresses installed into native workload `resolv.conf` and admitted by native firewall rules.
- `internal/resolvercontract/contract.go` -- new validated, bounded runtime contract and canonical IP normalization.
- `internal/resolvercontract/cli.go` -- new isolated CLI parser/renderer with explicit exit codes and stdout/stderr ownership.
- `cmd/leash/main.go` -- dispatches the new subcommand without entering the workload runner.
- `internal/version/version.go` -- advertises the additive capability to provisioners.
- `docs/api-contracts-leash-core.md` and `docs/DEVELOPMENT.md` -- publish the wire schema, ownership, compatibility, and orchestration sequence.

## Tasks & Acceptance

**Execution:**
- [x] `internal/resolvercontract/contract.go` and tests -- model the schema-versioned union, validate/canonicalize bounded addresses, and derive native results from the runner-owned effective list.
- [x] `internal/resolvercontract/cli.go` and tests -- parse the explicit runtime/JSON request, buffer the document before stdout, and keep help/errors on stderr with fail-closed exit codes.
- [x] `internal/runner/launcher_native.go` and tests -- expose one copy-safe effective resolver source used by both native setup and the contract without changing addresses or egress semantics.
- [x] `cmd/leash/main.go`, `internal/version/version.go`, and tests -- route the command before runner startup and advertise `resolver-contract-json` without changing contract bounds.
- [x] `docs/api-contracts-leash-core.md` and `docs/DEVELOPMENT.md` -- document exact JSON examples and require runtime-managed callers to inspect the target environment rather than consume native values.

**Acceptance Criteria:**
- Given the native launcher resolver source, when the CLI is queried for native, then its canonical addresses equal those written to the workload resolver file and admitted by native DNS firewall rules.
- Given Docker or Podman, when queried, then the document explicitly delegates resolver discovery and contains no native address.
- Given IPv4, IPv6, duplicate, reordered, malformed, empty, or over-limit resolver input, when the contract is built, then valid addresses are canonical and byte-stable while invalid state produces no success document.
- Given any usage, validation, marshal, or writer failure, when invoked as a machine command, then stdout contains no diagnostic or partial JSON and the process exits non-zero.

## Spec Change Log

## Design Notes

The union is distinguished by `strategy`, not by interpreting an empty list. `leash-managed` means `resolvers` is complete and non-empty; `runtime-managed` means the orchestrator must inspect the effective target runtime/image/network resolver state and must not infer any address from Leash. Adding the capability name is additive under contract version 1.

## Verification

**Commands:**
- `timeout 10m go test ./internal/resolvercontract ./internal/runner ./internal/version ./cmd/leash` -- focused contract, native-source, capability, and dispatch tests pass.
- `timeout 10m go test ./...` -- full Go suite passes once after focused verification.
- `timeout 10m go vet ./...` -- static checks pass.
- `timeout 10m make build` -- release-style binaries compile.
- `git diff --check` -- changed files have no whitespace errors.

## Suggested Review Order

**Command and ownership boundary**

- Dispatch the probe before any workload runner path and bind it to the build platform.
  [`main.go:33`](../../cmd/leash/main.go#L33)

- Use an explicit strategy union so containers never inherit native resolver claims.
  [`contract.go:39`](../../internal/resolvercontract/contract.go#L39)

- Keep parsing, errors, JSON buffering, and exit behavior isolated from workload execution.
  [`cli.go:22`](../../internal/resolvercontract/cli.go#L22)

**Single native source**

- Canonicalize the build-owned resolver source before resolv.conf, firewall, or query consumption.
  [`launcher_native.go:756`](../../internal/runner/launcher_native.go#L756)

- Normalize, deduplicate, sort, and bound the exact emitted address set.
  [`contract.go:70`](../../internal/resolvercontract/contract.go#L70)

**Compatibility and documentation**

- Advertise the additive capability without changing the existing contract-version range.
  [`version.go:95`](../../internal/version/version.go#L95)

- Publish native ownership, container delegation, non-Linux rejection, and fail-closed semantics.
  [`api-contracts-leash-core.md:258`](../api-contracts-leash-core.md#resolver-ownership--leash-resolvers-json)

**Boundary regression coverage**

- Exercise IPv4/IPv6 canonicalization, deduplication, limits, and malformed state.
  [`contract_test.go:11`](../../internal/resolvercontract/contract_test.go#L11)

- Protect stdout purity, platform rejection, conflicts, and short-write failures.
  [`cli_test.go:13`](../../internal/resolvercontract/cli_test.go#L13)

- Verify the CLI entry point routes to the contract without claiming sibling commands.
  [`main_test.go:11`](../../cmd/leash/main_test.go#L11)
