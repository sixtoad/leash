---
title: 'Leash #84: release CLI and manager as one compatible unit'
type: 'bugfix'
created: '2026-08-29'
status: 'in-progress'
review_loop_iteration: 0
baseline_commit: 'acfda6452aae8f6c84b42dd6d2b6c506f49736d3'
context:
  - 'docs/RELEASE.md'
  - 'docs/deployment-guide.md'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** The fork's `native-v*` release publishes new host CLIs but no matching manager image, so the released CLI silently defaults to an old floating upstream `latest`. The merged manager fixes therefore never execute in the default container runtime.

**Approach:** Make the native release produce a versioned manager in the public `ghcr.io/sixtoad/leash-manager` repository and host archives from one immutable source revision, embed the published manager digest as the released CLI default, and reject incompatible manager metadata before provisioning a target. Gate release success on parity checks and a released-artifact Docker E2E using the exact combined Walk policy.

## Boundaries & Constraints

**Always:** Build the CLI, manager binary, eBPF objects, and manager image from the same clean commit. Publish `ghcr.io/sixtoad/leash-manager:<native-tag>` publicly and resolve it to a content digest; stamp the digest into the CLI default and record tag, digest, revision, and manager contract in release notes. Validate manager metadata after image pull but before target bootstrap. Preserve `--leash-image` over `LEASH_IMAGE` over the embedded default, accepting an override only when its advertised manager contract is compatible. Keep failures explicit, fail-closed, and credential-free.

**Ask First:** Changing away from the approved public `ghcr.io/sixtoad/leash-manager` registry, mutating an existing release tag, weakening compatibility for legacy unlabeled images, or changing Walk/BME interfaces.

**Never:** Fall back to `latest`; silently continue after missing or incompatible manager metadata; compare mutable local image names as proof of parity; provision or run a target before compatibility succeeds; access Codex authentication; publish a GitHub release before both artifacts and the default-path E2E pass.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Released default | Native-tag CLI, no image override | Pull embedded `repo@sha256:...`; manager revision and contract match | Abort before target `run` on any mismatch |
| Compatible override | Explicit flag or environment image with compatible contract metadata | Use the exact override, without replacing it with the release default | Surface selected ref and contract validation |
| Bad override | Missing labels, malformed range, or incompatible manager contract | No target container is created | Actionable error names expected/observed contract and image |
| Publication | Clean native tag at one commit | Versioned multi-arch manager and four CLI archives prove the same revision; notes include tag/digest | No successful GitHub release if parity or E2E fails |

</frozen-after-approval>

## Code Map

- `scripts/release.sh` -- fork-native publisher; currently builds archives and creates a GitHub release without a manager artifact.
- `build/publish-docker.sh` and `Dockerfile.leash` -- multi-arch manager publication and OCI provenance labels.
- `cmd/leash/main.go` and `internal/runner/runner.go` -- link-time release defaults, override precedence, and pre-provision orchestration.
- `internal/runner/launcher.go` -- image pull boundary immediately before any target provisioning.
- `e2e/boot_test.go` -- fail-closed Docker lifecycle and non-root target regression surface.

## Tasks & Acceptance

**Execution:**
- [ ] `internal/releasecontract/contract.go` (new) -- define the manager compatibility range and strict OCI metadata parsing/comparison shared by release stamping and runtime validation.
- [ ] `cmd/leash/main.go`, `internal/runner/runner.go`, `internal/runner/launcher.go` -- inject the immutable release default, preserve override precedence, inspect the selected manager after pull, and fail before target bootstrap on absent/malformed/incompatible metadata.
- [ ] `Dockerfile.leash`, `build/publish-docker.sh` -- stamp full source revision and manager-contract labels and expose the pushed version tag's immutable digest.
- [ ] `scripts/release.sh` -- publish the versioned manager first, embed its digest into all host CLIs from the same commit, verify archive/image revision parity, run the release E2E, then create release notes containing the paired tag/digest.
- [ ] `e2e/boot_test.go`, `e2e/testdata/walk33-combined.cedar` -- cover compatible/mismatched images and execute an extracted release binary with no override, a named non-root target, fail-closed LSM, and the tracked exact Walk combined policy.
- [ ] `docs/RELEASE.md`, `docs/deployment-guide.md`, `README.md` -- document the coherent artifact contract, immutable default, override validation, registry, and operator diagnostics.

**Acceptance Criteria:**
- Given one clean tagged commit, when the native release is built, then every CLI archive and the versioned multi-arch manager report that same full revision and compatible manager contract.
- Given the released CLI with no override, when container runtime starts, then it selects the matching immutable manager digest rather than any floating tag.
- Given incompatible or unverifiable manager metadata, when startup reaches image readiness, then Leash exits non-zero before any target container is provisioned and identifies the mismatch.
- Given the release artifact, no image override, the combined Walk policy, a named non-root target, and fail-closed LSM, when the release gate runs, then the governed harmless workload executes as that user and both containers are removed.
- Given any failed archive, image, parity, or E2E verification, when publishing runs, then it does not report or create a successful GitHub release.

## Spec Change Log

## Design Notes

The release default must be a digest because a version tag alone can be moved. Revision equality is mandatory for the generated default; explicit custom images may differ in revision but must advertise a compatible manager-contract range. This preserves the documented override escape hatch without allowing an unversioned or structurally incompatible daemon to execute silently.

## Verification

**Commands:**
- `go test ./internal/releasecontract ./internal/runner ./cmd/leash` -- expected: metadata parsing, override precedence, and pre-provision fail-closed tests pass.
- `timeout 10m go test ./e2e -run 'ReleaseParity|ManagerCompatibility' -count=1 -v` -- expected: exact release/default combined-policy path passes and mismatch cases create no target.
- `timeout 10m go test ./...` -- expected: repository suite passes.
- `scripts/release.sh --dry-run native-vX.Y.Z` -- expected: manager plus archives share revision, default resolves by digest, release E2E passes, and no remote release is created.
- `git diff --check` -- expected: no whitespace errors.
