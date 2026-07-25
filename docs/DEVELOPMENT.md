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
  "capabilities": ["policy", "inject-service", "runtime", "user", "require-lsm", "version-json"],
  "os": "linux",
  "arch": "amd64"
}
```

- `commit` is the abbreviated hash, keeping any `-dirty` marker, so a build from a modified tree cannot pass itself off as the commit it was cut from. Every build path that stamps a commit appends the marker when the tree is modified: the `build` target in the [Makefile](../Makefile), [`scripts/release.sh`](../scripts/release.sh), [`scripts/install-leash.sh`](../scripts/install-leash.sh) and [`build/publish-docker.sh`](../build/publish-docker.sh) (which passes it into `Dockerfile.leash` as `--build-arg COMMIT`). The one exception is [`.goreleaser.yaml`](../.goreleaser.yaml), which needs no marker because `goreleaser release` refuses to build from a modified tree at all — see the comment there before adding `--snapshot` or `--skip=validate` to the release workflow. Only the hash is abbreviated — a value that is not a hex hash (a `git describe` string) is reported whole rather than cut into a fragment that names a different build.
  - Those checks use `git diff-index --quiet HEAD --`, not `git status --porcelain`: tracked files only, the same test `git describe --dirty` runs, so `version` and `commit` cannot disagree about one tree because of an untracked file. They also fail **closed** — a git that errors (index lock, corrupt index, ownership refusal) is stamped `-dirty` with a warning rather than read as pristine — and append the marker only when the commit lookup itself succeeded, so the `dev` fallback never becomes `dev-dirty`.
- `version` is the literal string `dev` on a plain `go build` with no ldflags (that is the default of `main.version` in `cmd/leash`); `commit` and `builtAt` are the literal string `unknown`. Both are documented sentinels, not errors: parse them, don't choke on them.
- `enforcing` reports whether **this binary carries an enforcement path**, derived from the target platform rather than hardcoded. It is `true` on linux (the eBPF LSM programs plus the intercepting MITM proxy) and `true` on darwin (the darwin runtime constructs and drives the same MITM proxy — `internal/darwind/runtime_darwin.go`, `NewMITMProxy` / `applyPolicyToProxy` — alongside the separately installed Endpoint Security and Network Extension components). Any other target reports `false`. This is a statement about the *binary*; whether a given *host* can actually enforce — LSM active in the kernel, the system extension approved, the right capabilities — is a runtime question this build-time document does not answer. That is `leash doctor`'s job.
- `capabilities` names the CLI surface elements a provisioner drives, so a caller can test for the one it needs directly. See below.
- `os` / `arch` are the build's `GOOS` / `GOARCH`.

### The compatibility contract: `contractVersion`, `minCompatibleContract`, `capabilities`

The two integers bound the leash CLI surface external provisioners drive: the `--policy`, `--inject-service`, `--runtime`, `--user` and `--require-lsm` flags, plus the shape of this JSON document. An installer reads them once and refuses — or warns — up front, rather than failing cryptically on the first real run.

- `contractVersion` — the current surface.
- `minCompatibleContract` — the oldest caller contract this build still serves.

**A caller written against contract `C` proceeds iff `minCompatibleContract <= C <= contractVersion`.**

The rule is a two-sided range, and `contractVersion >= C` alone is *not* it. That check is necessary but not sufficient: it admits a leash whose `contractVersion` is far above `C` and whose `minCompatibleContract` has since risen past `C` — precisely the leash that dropped the surface `C` was written against. Read the bounds as:

- `C > contractVersion` → **leash-too-old**: this leash predates the surface the caller needs. Upgrade leash.
- `C < minCompatibleContract` → **leash-too-new**: this leash has removed something the caller was written against. Upgrade the caller.
- otherwise → **compatible**.

Go callers import [`pkg/leashversion`](../pkg/leashversion) — a non-`internal` package, so a consumer in another module (walk is `github.com/sixto/walk`) can actually use it — and decode the **installed binary's** output:

```go
import "github.com/strongdm/leash/pkg/leashversion"

const walkContract = 1 // the contract this provisioner was written against

out, err := exec.Command(leashPath, "version", "--json").Output()
if err != nil {
    // Not an install failure: this leash is contract 0. See the probe hazard below.
    return errContractZero
}
info, err := leashversion.Parse(out) // == json.Unmarshal into leashversion.Info
if err != nil {
    return errContractZero
}
if !info.SupportsCaller(walkContract) {
    return fmt.Errorf("incompatible leash: %s", info.CheckCaller(walkContract)) // "leash-too-old" | "leash-too-new"
}
```

Note what that does **not** do: it never calls a function that returns the calling program's own compiled-in constants (`version.Describe` and friends do exactly that). A provisioner that compares leash against its own constants is comparing itself to itself, and the check can only ever pass. The only thing that can disagree with the caller is the installed binary's stdout, so that is what must be decoded.

**`capabilities`** exists because the integer is coarse. Raising `minCompatibleContract` for a removal over-refuses: it turns away *every* caller below the new floor, including ones that never touched the removed flag. A caller that depends on one specific surface element can ask for it instead:

```go
if info.HasCapability(leashversion.CapabilityInjectService) { /* drive --inject-service */ }
```

Adding a name to `capabilities` is additive and does **not** bump `contractVersion`; removing one is a break and does. A document from a leash that predates the field decodes with it empty, so fall back to the contract range when it is.

**Contract 0** is a leash with no `version --json` subcommand at all — any build from before this feature shipped. A caller that gets a non-zero exit, an unknown-subcommand error, or unparseable output from `leash version --json` must treat the installed leash as contract 0 rather than as a broken install. `minCompatibleContract` is `0` today because contract 1 only *added* the document; nothing a pre-document caller drives has been removed. That also makes the field's absence safe to interpret: a document decoded into a typed struct without the field yields `0`, which is exactly "nothing has been removed".

> **Probe hazard.** On a pre-feature leash, `version` is *not* a subcommand: the argument falls through to the workload CLI (`internal/runner`), which configures telemetry and can begin runtime provisioning. So `leash version --json` is a side-effect-free probe only from contract 1 onward — running it at a binary that might predate the feature is not. Prefer to establish contract 0 without that argv: `leash --version` has been handled by the argument switch in every build and only prints three lines, so a provisioner that knows which leash release it installed can map that release to contract 0 vs ≥ 1 with no other invocation. If you must probe an unknown binary, run it with `LEASH_DISABLE_TELEMETRY=1` in a disposable working directory and treat anything that is not a parseable document as contract 0.

Bump `ContractVersion` (in [`pkg/leashversion`](../pkg/leashversion)) when the surface changes in a way an existing caller cannot absorb: a flag is removed or renamed, its argument grammar changes, or its meaning changes. Do **not** bump for additive changes — new flags, new JSON fields, new `capabilities` entries, new accepted flag values — which stay compatible by construction. When a bump *removes* something, raise `MinCompatibleContract` to the first contract that no longer offers it; otherwise leave it alone. Both are deliberately decoupled from the release version: leash can ship many releases at the same contract.

`internal/version` remains the CLI side — argument parsing, the human lines, the JSON rendering. It is internal on purpose: nothing outside leash needs it, and nothing outside leash *could* import it.
