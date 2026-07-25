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

`leash --version` (and `leash version`) prints the three human lines it always has. `leash version --json` — equivalently `leash version --output json` — prints the same build metadata as a document for tools that provision leash:

```json
{
  "version": "v0.2.0",
  "commit": "c686025",
  "builtAt": "2026-07-21T10:11:12Z",
  "enforcing": true,
  "contractVersion": 1,
  "os": "linux",
  "arch": "amd64"
}
```

`commit` is the short hash, keeping any `-dirty` marker so a build from a modified tree cannot pass itself off as the commit it was cut from. `enforcing` says this build ships the enforcement path (LSM hooks plus the intercepting proxy) rather than only observing.

### The `contractVersion` compatibility contract

`contractVersion` is a monotonic integer naming the leash CLI surface that external provisioners drive: the `--policy`, `--inject-service`, `--runtime` and `--user` flags, plus the shape of this JSON document. An installer can read it once and refuse — or warn — up front rather than failing cryptically on the first real run. Callers proceed when leash's `contractVersion` is **at least** the minimum they were written against.

Bump it (in `internal/version`, `ContractVersion`) when that surface changes in a way an existing caller cannot absorb: a flag is removed or renamed, its argument grammar changes, or its meaning changes. Do **not** bump it for additive changes — new flags, new JSON fields, new accepted flag values — which stay compatible by construction. It is deliberately decoupled from the release version: leash can ship many releases at the same contract.
