---
title: 'Leash #86: keep BPF code generation off target-platform QEMU'
type: 'bugfix'
created: '2026-08-29'
status: 'done'
review_loop_iteration: 0
baseline_commit: '154d4cfd90146d6dc27da48acd48f8da9b0ab76b'
context:
  - 'docs/RELEASE.md'
  - 'docs/development-guide.md'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** The native release builds the manager for AMD64 and ARM64, but `Dockerfile.leash` installs and runs `bpf2go` inside each target-platform build. On an AMD64 release host, ARM64 therefore performs build-host-only Go tooling through QEMU and cannot complete inside the ten-minute operational cap.

**Approach:** Generate the architecture-independent eBPF bindings once on the native release host, require the Docker build to consume the complete generated artifact set without regenerating it, and verify the published manager manifest contains both required Linux platforms before release parity checks continue.

## Boundaries & Constraints

**Always:** Preserve all generated BPF Go bindings and embedded object files; fail clearly when any required artifact is absent or empty; keep AMD64 and ARM64 manager functionality, revision labels, manager-contract labels, immutable digest stamping, archive parity, and the default-path Docker E2E unchanged. Cap each verification command at ten minutes and surface any command over two minutes.

**Ask First:** Changing the public manager registry, weakening the #84 compatibility contract, changing release tag immutability, or altering Walk/BME interfaces.

**Never:** Run `go install bpf2go` or `go generate ./internal/lsm` in a target-platform Docker stage; silently build with missing or stale generated assets; publish `native-v0.3.4`; access credentials; delete or mutate an existing tag.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Multi-arch release | Complete host-generated BPF files and an absent immutable tag | Build both Linux manager platforms without target-platform codegen and continue with the existing parity gates | Stop before GitHub release on any build or parity failure |
| Missing generated artifact | Any required generated Go binding or object is absent/empty in the build context | Manager build refuses to compile an incomplete image | Name the missing artifact in the failing Docker layer |
| Incomplete manifest | Published digest lacks Linux AMD64 or Linux ARM64 | Release does not pull/stamp/publish the CLI | Report the missing platform and exit non-zero |

</frozen-after-approval>

## Code Map

- `Dockerfile.leash` -- target-platform manager build currently repeats BPF tooling and consumes its outputs.
- `Makefile` -- host-generation entry point and pinned `bpf2go` version used by release CLI archives.
- `scripts/release.sh` -- native publisher already generates BPF artifacts before manager publication and owns the post-push parity gates.
- `scripts/verify-manager-manifest.py` -- validates local OCI content and post-push registry platform/config parity.
- `build/publish-docker.sh` -- constructs and pushes the required AMD64/ARM64 manifest list.
- `internal/releasecontract/release_files_test.go` -- focused source-level regression for Docker/release boundary invariants.

## Tasks & Acceptance

**Execution:**
- [x] `Dockerfile.leash`, `Makefile` -- generate all BPF outputs once on `BUILDPLATFORM` with pinned `bpf2go`, consume them from native target cross-builds, and keep host release generation deterministic.
- [x] `scripts/release.sh`, `scripts/verify-manager-manifest.py` -- validate a complete local OCI layout before publication, then prove the pushed digest advertises distinct runnable platforms with matching child architectures and labels.
- [x] `internal/releasecontract/release_files_test.go` -- prevent target-stage codegen and regression of generated-artifact/platform gates with realistic OCI fixtures.

**Acceptance Criteria:**
- Given an AMD64 host and complete generated BPF artifacts, when the manager is built for `linux/amd64,linux/arm64`, then `bpf2go` and LSM generation never execute under the ARM64 target stage.
- Given the pushed manager digest, when publication proceeds, then both required manifest platforms and the existing revision/contract labels are proven before CLI archives are stamped.
- Given any missing generated artifact or platform, when the release gate runs, then it exits non-zero before a successful GitHub release exists.
- Given the accepted #84 pipeline, when #86 is applied, then immutable-tag guards, no-`latest` publication, archive linkage, and the release E2E remain intact.

## Spec Change Log

## Design Notes

The BPF programs target the BPF instruction set, not the manager CPU architecture. A pinned generator stage executes once on `BUILDPLATFORM` and emits both endian variants; the native cross-build stages consume those outputs rather than trusting ignored host files or regenerating under each target. The release also regenerates the same pinned set on the host for its CLI archives.

The manager dependency graph has no cgo packages, and the existing host installers and release archives already use `CGO_ENABLED=0`. Building the manager and entry binary on `$BUILDPLATFORM` with explicit target OS/architecture therefore preserves their pure-Go enforcement path while removing the remaining emulated Go compiler work. Only target runtime-image assembly remains target-platform-specific.

## Verification

**Commands:**
- `timeout 10m go test ./internal/releasecontract -count=1` -- expected: focused Dockerfile/release contract regressions pass.
- `timeout 10m go test ./...` -- expected: full Go suite passes with generated LSM bindings.
- `timeout 10m scripts/release.sh --dry-run native-v0.0.0` -- expected: host-generated BPF artifacts build the local manager and all existing parity gates pass without publishing.
- `git diff --check` -- expected: no whitespace errors.

## Suggested Review Order

**Native multi-architecture build boundary**

- Generate pinned BPF assets once on the native platform for clean Docker builds.
  [`Dockerfile.leash:35`](../../Dockerfile.leash#L35)

- Cross-compile both target binaries natively with explicit OS and architecture.
  [`Dockerfile.leash:123`](../../Dockerfile.leash#L123)

**Immutable release safety**

- Prove the full OCI layout before creating an immutable registry tag.
  [`release.sh:110`](../../scripts/release.sh#L110)

- Bound registry reads and compare both published child configs after push.
  [`release.sh:163`](../../scripts/release.sh#L163)

- Validate OCI content digests, architectures, provenance, and contract labels.
  [`verify-manager-manifest.py:148`](../../scripts/verify-manager-manifest.py#L148)

**Supporting guarantees**

- Pin host-side release generation to the same bpf2go version.
  [`Makefile:69`](../../Makefile#L69)

- Guard build-platform execution and realistic multi-platform manifest semantics.
  [`release_files_test.go:30`](../../internal/releasecontract/release_files_test.go#L30)
