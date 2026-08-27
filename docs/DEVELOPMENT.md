# Leash Developers Guide

## Requirements

- [Go](https://go.dev)
- Node.js and npm

## Clone and build Leash

```bash
git clone git@github.com:strongdm/leash.git
cd leash
make docker build

# Prefer Podman? Override the container runtime per invocation:
#   make DOCKER=podman docker build

# See also: make help
```

## Versioning

Version strings are resolved centrally by `build/versionator.py`. The helper looks for:

1. A `vX.Y.Z` git tag on the current commit.
2. Otherwise it falls back to a `dev-<shortSHA>[-dirty]` snapshot identifier.

The Makefile, release scripts, and Docker builds all shell out to this script, so running `./build/versionator.py <part>` shows the exact value those pipelines consume:

```bash
./build/versionator.py bin   # 1.2.3
./build/versionator.py tag   # v1.2.3 or dev-ab12cd3
./build/versionator.py minor # 2
```

### Reporting the version at run time

`leash --version` (and `leash version`) prints the three human lines it always has. `leash version --json` — equivalently `leash version --output json` — prints the same build metadata as a document for tools that provision leash. `leash version --help` prints usage and exits 0; a conflicting or empty format (`--json --output text`, `--output=`) is rejected rather than resolved by last-one-wins.

```json
{
  "version": "v0.2.0",
  "commit": "c686025-dirty",
  "builtAt": "2026-07-21T10:11:12Z",
  "enforcing": true,
  "contractVersion": 1,
  "minCompatibleContract": 0,
  "capabilities": ["policy", "inject-service", "runtime", "user", "require-lsm", "machine-output", "version-json", "resolver-contract-json"],
  "os": "linux",
  "arch": "amd64"
}
```

- `commit` is the abbreviated hash, keeping any `-dirty` suffix the build path stamped, so a build that carries the marker is telling you the tree was modified. The marker is **best-effort and explicitly not guaranteed on all paths**: only the `build` target in the [Makefile](../Makefile) appends it today (and it uses `git status --porcelain`, so an untracked file counts, and it runs after `precommit`'s `goimports -w`). [`scripts/release.sh`](../scripts/release.sh), [`scripts/install-leash.sh`](../scripts/install-leash.sh), [`build/publish-docker.sh`](../build/publish-docker.sh) and [`.goreleaser.yaml`](../.goreleaser.yaml) stamp the bare hash. **A consumer must not read the absence of `-dirty` as proof of a clean tree** — for that, verify provenance out of band. Only the hash component is ever abbreviated: a value that is not a hex hash (a `git describe` string) is reported whole rather than cut into a fragment that names a different build.
- `version` is the literal string `dev` on a plain `go build` with no ldflags (that is the default of `main.version` in `cmd/leash`); `commit` and `builtAt` are the literal string `unknown`. Both are documented sentinels, not errors: parse them, don't choke on them. `scripts/install-leash.sh` stamps `version` from `git describe --tags --always --dirty`, so `version` may carry a `-dirty` suffix independently of `commit`.
- The full value domain of `commit` is therefore: an abbreviated hex hash, optionally suffixed `-dirty`; the literal `dev` (the fallback when `git rev-parse` fails, and the `ARG COMMIT` default in `Dockerfile.leash`); or the literal `unknown` (the ldflag default). A caller validating `commit` against a fixed set must accept all three — `dev` is a legitimate build, not a malformed document.
- `enforcing` reports whether **this binary carries an enforcement path**, derived from the target platform rather than hardcoded. It is `true` on linux (the eBPF LSM programs plus the intercepting MITM proxy) and `true` on darwin (the darwin runtime constructs and drives the same MITM proxy — `internal/darwind/runtime_darwin.go`, `NewMITMProxy` / `applyPolicyToProxy` — alongside the separately installed Endpoint Security and Network Extension components). Any other target reports `false`. This is a statement about the *binary*; whether a given *host* can actually enforce — LSM active in the kernel, the system extension approved, the right capabilities — is a runtime question this build-time document does not answer. That is `leash doctor`'s job.
- `capabilities` names the CLI surface elements a provisioner drives, so a caller can test for the one it needs directly. See below.
- `os` / `arch` are the build's `GOOS` / `GOARCH`.

### The compatibility contract: `contractVersion`, `minCompatibleContract`, `capabilities`

The two integers bound the leash CLI surface external provisioners drive — the `--policy`, `--inject-service`, `--runtime`, `--user`, `--require-lsm` and `--machine-output` flags, plus the shape of this document — so an installer can refuse (or warn) up front instead of failing cryptically on the first real run. **A caller written against contract `C` proceeds iff `minCompatibleContract <= C <= contractVersion`.** `contractVersion >= C` alone is *not* the rule: it also admits a leash whose floor has since risen past `C`, which is exactly the leash that dropped `C`'s surface.

The consumer-facing contract — that rule with both failure directions, the value domains, `capabilities`, contract 0, the probe hazard, and a snippet that decodes an installed binary's stdout — is [`api-contracts-leash-core.md` § CLI build contract](api-contracts-leash-core.md#cli-build-contract--leash-version---json). It is deliberately not duplicated here: that document is the published contract, and there is no package to import.

Maintainer rules:

- **Bump `ContractVersion`** (in [`internal/version`](../internal/version)) when the surface changes in a way an existing caller cannot absorb: a flag is removed or renamed, its argument grammar changes, or its meaning changes. Do **not** bump for additive changes — new flags, new JSON fields, new `capabilities` entries, new accepted flag values — which stay compatible by construction. When a bump *removes* something, raise `MinCompatibleContract` to the first contract that no longer offers it; otherwise leave it alone. Both are decoupled from the release version — leash can ship many releases at the same contract — and both are pinned by tests, so update the docs and those tests in the same change.
- **The emitted JSON is the contract; the Go type is not.** `internal/version` holds all of it — the document type, the bounds, the comparison, the argument parsing, the rendering — and stays `internal` on purpose. Exporting a package would bind this module, already tagged `v1.1.7`, to a permanent v1 Go API with no apidiff gate: removing one `Info` field would force a `/v2` and break every importer, in exchange for saving a consumer three lines. Change the wire document carefully, under the bump policy above; change the Go type freely.

### Machine-readable workload output

Use `leash --machine-output -- <command>` when another program consumes the governed command's stdout. The flag implies non-interactive execution. Leash sends all runner and Docker/Podman/native lifecycle diagnostics to stderr while attaching the workload directly to the host stdin, stdout, and stderr descriptors. No result bytes are inspected or buffered, and numeric workload exit codes continue to propagate exactly after cleanup. Without the flag, the existing interactive prompts, TTY allocation, output destinations, and signal semantics are unchanged.

Provisioners must probe `leash version --json` and require the `machine-output` capability before adding the flag. The capability was added without changing `contractVersion` from 1, so the integer alone cannot distinguish an older contract-1 build that lacks this fd-ownership contract. The full consumer contract and examples are in [`api-contracts-leash-core.md` § Machine-output fd ownership](api-contracts-leash-core.md#machine-output-fd-ownership--leash---machine-output).

### Effective DNS resolvers for orchestrators

Before generating network policy, an orchestrator can run:

```bash
leash resolvers --runtime native --json
leash resolvers --runtime docker --json
```

The command does not launch a workload, read credentials, or probe a container.
For `native`, it reports the complete resolver list Leash installs in the
workload network namespace and admits through its DNS firewall rules. For
`docker` and `podman`, it reports `runtime-managed` and delegates discovery to
the orchestrator, which must inspect the target image/network's effective
`/etc/resolv.conf`. It never substitutes the native list for a container.
Non-Linux builds reject the Linux `native` query instead of claiming its public
resolver set for the separate platform-native backend.

Provisioners must first require the `resolver-contract-json` capability from
`leash version --json`. The exact schema and failure contract are published in
[`api-contracts-leash-core.md` § Resolver ownership](api-contracts-leash-core.md#resolver-ownership--leash-resolvers-json).
