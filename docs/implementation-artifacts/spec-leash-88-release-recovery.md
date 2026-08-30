---
title: 'Leash #88: resume a stranded immutable manager release'
type: 'bugfix'
created: '2026-08-30'
status: 'done'
review_loop_iteration: 1
baseline_commit: 'ea0d7df5ca7b5a9e1265dfe3ef742438d8011d38'
context:
  - 'docs/RELEASE.md'
  - 'docs/implementation-artifacts/spec-leash-84-release-parity.md'
  - 'docs/implementation-artifacts/spec-leash-86-native-build-tools.md'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** The `native-v0.3.4` manager index was published successfully, but the release then used an invalid GitHub Packages visibility request. The retry guard now refuses the immutable tag, leaving no safe way to complete the CLI/GitHub release without overwriting or deleting verified manager content.

**Approach:** Add an explicit `--resume-existing-manager` path and keep GitHub package visibility read-only because GitHub exposes no supported visibility-update API. A private package halts with its exact settings URL and resume command; recovery resolves the existing tag, pins its digest, deeply proves it is the exact manager expected from the current commit/tag/contract, and continues the unchanged anonymous-pull, archive, and release-E2E gates without any manager publication operation.

## Boundaries & Constraints

**Always:** Refuse any existing Git tag or GitHub release before mutation. Keep fresh publication as the default and require explicit recovery selection. Bound and diagnose GitHub/package/registry operations. In recovery, cryptographically verify the raw index digest, exactly the AMD64/ARM64 runnable children with distinct digests and matching architectures, full revision, release version/channel, and manager contract labels before embedding the digest. Require authenticated visibility `public` and an anonymous digest pull before CLI stamping and release creation.

**Ask First:** Changing the public manager registry/owner, deleting or replacing any package/tag/release, weakening #84 compatibility or provenance, or changing Walk/BME interfaces.

**Never:** Call an unsupported package-visibility mutation; push, delete, mutate, or retag the existing manager during recovery; silently turn an ordinary retry into recovery; use `latest`; accept extra runnable platforms, missing/malformed metadata, tag/digest drift, or partial provenance; publish `native-v0.3.4` while implementing or testing this change; access credentials.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Fresh release | Manager/Git tag/release all absent; no resume flag | Build and push manager; if GitHub creates a private package, halt before CLI work with its settings URL and exact resume command | Stop explicitly on publication or non-public visibility |
| Matching recovery | Resume flag; manager tag exists; Git tag/release absent; all manager evidence matches | Reuse resolved digest without manager publication and continue all downstream gates | Report recovery digest and prove anonymous pull |
| Unsafe recovery | Missing flag, absent manager, tag/digest drift, metadata mismatch, or existing Git tag/release | Perform no manager publication or destructive action | Name the mismatched invariant and exit non-zero |

</frozen-after-approval>

## Code Map

- `scripts/release.sh` -- native argument parsing, remote-state guard, publication/recovery branch, visibility, anonymous pull, and downstream release gates.
- `scripts/verify-manager-manifest.py` -- digest/platform/config/label verification shared by fresh and recovery paths.
- `internal/releasecontract/release_files_test.go` -- focused release contract and realistic manifest regression tests.
- `docs/RELEASE.md` -- operator-facing fresh/recovery invocation and immutability guarantees.

## Tasks & Acceptance

**Execution:**
- [x] `scripts/release.sh` -- add explicit recovery parsing and fail-closed remote-state classification; skip every manager build/push operation during recovery while resolving and pinning the existing digest.
- [x] `scripts/release.sh` -- remove unsupported visibility mutation, require bounded read-only public-state verification with exact UI/resume guidance, then preserve anonymous digest pull before archive stamping.
- [x] `scripts/verify-manager-manifest.py` -- bind raw index bytes to the expected digest and validate exact runnable platforms plus revision/version/channel/contract labels.
- [x] `internal/releasecontract/release_files_test.go` -- cover fresh publication, visibility failure, matching recovery, mismatched recovery, and existing Git tag/release refusal with command fakes and manifest fixtures.
- [x] `docs/RELEASE.md` -- document safe recovery eligibility, command, immutable reuse, verification, and refusal cases.

**Acceptance Criteria:**
- Given a matching existing manager tag and no Git tag/release, when explicit recovery runs, then no build/push/delete/tag operation occurs and all provenance, anonymous-pull, archive, and E2E gates execute against its pinned digest.
- Given fresh publication or recovery, when package visibility is private or unverifiable, then the release stops before CLI stamping with the exact settings URL and resume operation diagnosed.
- Given any remote-state or manager-evidence mismatch, when release planning runs, then it exits non-zero before remote mutation.

## Spec Change Log

- Review iteration 1: Official GitHub documentation confirmed there is no supported package-visibility update endpoint. Replaced the PATCH requirement with read-only visibility verification, exact manual settings guidance, and explicit recovery; this avoids repeating the observed 404 while preserving immutable manager reuse and all downstream gates.

## Design Notes

The explicit flag separates two legitimate states that otherwise look identical to automation after a partial failure. Both paths converge only after a content-addressed registry verification boundary; downstream code therefore receives one proven `MANAGER_REF`, regardless of whether its index was just pushed or safely recovered.

## Verification

**Commands:**
- `timeout 10m go test ./internal/releasecontract -count=1` -- expected: all fresh/recovery/visibility and deep-manifest cases pass.
- `timeout 10m go test ./... -count=1` -- expected: full Go suite passes.
- `timeout 10m scripts/release.sh --dry-run native-v0.0.0` -- expected: unchanged local coherent-release E2E passes without remote mutation.
- `git diff --check` -- expected: no whitespace errors.

## Suggested Review Order

**Release orchestration**

- Start here: explicit fresh/resume selection keeps immutable publication recovery intentional.
  [`release.sh:6`](../../scripts/release.sh#L6)

- Fresh publishes only after repeated absence checks; resume only resolves the existing digest.
  [`release.sh:125`](../../scripts/release.sh#L125)

- Remote classification fails closed across GitHub and independently verified registry state.
  [`native-release-remote.sh:25`](../../scripts/native-release-remote.sh#L25)

- Read-only visibility gating gives operators the exact settings and safe resume path.
  [`native-release-remote.sh:132`](../../scripts/native-release-remote.sh#L132)

**Provenance boundary**

- Registry verification binds raw index bytes, exact platforms, labels, revision, version, and channel.
  [`verify-manager-manifest.py:80`](../../scripts/verify-manager-manifest.py#L80)

- Release assembly inspects each child by descriptor digest before anonymous pull and stamping.
  [`release.sh:171`](../../scripts/release.sh#L171)

**Behavioral evidence**

- Command fakes prove resume never reaches the publication callback.
  [`native_release_remote_test.go:119`](../../internal/releasecontract/native_release_remote_test.go#L119)

- Manifest fixtures exercise digest, platform, variant, descriptor, and metadata failures.
  [`release_files_test.go:145`](../../internal/releasecontract/release_files_test.go#L145)

**Operator guidance**

- Recovery eligibility and the immutable-reuse procedure are documented together.
  [`RELEASE.md:45`](../RELEASE.md#L45)
