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
  "os": "linux",
  "arch": "amd64"
}
```

- `commit` is the abbreviated hash, keeping any `-dirty` marker, so a build from a modified tree cannot pass itself off as the commit it was cut from. Every build path that stamps a commit appends the marker: the `build` target in the Makefile, [`scripts/release.sh`](../scripts/release.sh) and [`scripts/install-leash.sh`](../scripts/install-leash.sh). Only the hash is abbreviated — a value that is not a hex hash (a `git describe` string) is reported whole rather than cut into a fragment that names a different build.
- `version` and `builtAt` are the literal string `unknown` on a plain `go build` with no ldflags. That is a documented sentinel, not an error: parse it, don't choke on it.
- `enforcing` is **derived from the target platform**, not a constant. It is `true` only on the Linux build, which is the one that ships the in-binary enforcement path (eBPF LSM hooks plus the intercepting MITM proxy). The darwin binary is the CLI for an installed `Leash.app`, whose enforcement lives in separate Endpoint Security and Network Extension components, so it reports `false`. This is a statement about the *binary*; whether a given *host* can actually enforce is a runtime question this build-time document does not answer.
- `os` / `arch` are the build's `GOOS` / `GOARCH`.

### The compatibility contract: `contractVersion` and `minCompatibleContract`

The two integers bound the leash CLI surface external provisioners drive: the `--policy`, `--inject-service`, `--runtime` and `--user` flags, plus the shape of this JSON document. An installer reads them once and refuses — or warns — up front, rather than failing cryptically on the first real run.

- `contractVersion` — the current surface.
- `minCompatibleContract` — the oldest caller contract this build still serves.

**A caller written against contract `C` proceeds iff `minCompatibleContract <= C <= contractVersion`.**

Both bounds matter, which is why a lone `contractVersion >= C` check is wrong: the number is bumped precisely when the surface *loses* something, so a leash whose `contractVersion` is strictly greater than `C` may have dropped what `C` depends on. The upper bound catches a leash that is **too old** (it predates the surface the caller needs — upgrade leash); the lower bound catches a leash that is **too new** (it dropped the surface the caller was written against — upgrade the caller). Go callers should use the helpers rather than hand-rolling the comparison:

```go
info := version.Describe(build) // or json.Unmarshal into version.Info
if !info.SupportsCaller(myContract) {
    return fmt.Errorf("incompatible leash: %s", info.CheckCaller(myContract)) // "leash-too-old" | "leash-too-new"
}
```

**Contract 0** is a leash with no `version --json` subcommand at all — any build from before this feature shipped. A caller that gets a non-zero exit, an unknown-subcommand error, or unparseable output from `leash version --json` must treat the installed leash as contract 0 rather than as a broken install. `minCompatibleContract` is `0` today because contract 1 only *added* the document; nothing a pre-document caller drives has been removed. That also makes the field's absence safe to interpret: a document decoded into a typed struct without the field yields `0`, which is exactly "nothing has been removed".

Bump `ContractVersion` (in `internal/version`) when the surface changes in a way an existing caller cannot absorb: a flag is removed or renamed, its argument grammar changes, or its meaning changes. Do **not** bump for additive changes — new flags, new JSON fields, new accepted flag values — which stay compatible by construction. When a bump *removes* something, raise `MinCompatibleContract` to the first contract that no longer offers it; otherwise leave it alone. Both are deliberately decoupled from the release version: leash can ship many releases at the same contract.
