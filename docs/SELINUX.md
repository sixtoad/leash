# SELinux hosts (Fedora, RHEL)

Leash's enforcement does not depend on SELinux: the eBPF LSM programs (Layer 1)
and the MITM proxy (Layer 2) enforce the policy whatever the other LSMs are.
On Fedora the kernel's default LSM list already contains both
(`lockdown,capability,yama,selinux,bpf,...`), so no `lsm=` change is needed;
on RHEL-family hosts append `bpf` and keep `selinux` (see
[NATIVE-ENFORCEMENT-RUNBOOK.md](NATIVE-ENFORCEMENT-RUNBOOK.md)).

What SELinux does change is which host files a container may touch. A
container process runs as `container_t` and can only read files with a
container type (`container_file_t`, ...). This page lists how each mount is
labelled.

## Mounts

| Mount | Containers | Label handling |
|---|---|---|
| leash share dir (`/leash`), log, cfg dirs | target + leash | `:z` (leash owns them; shared label, both containers read them) |
| leash private dir | leash only | `:z`; the leash container is `--privileged`, so SELinux separation is already off for it |
| project directory (the caller's working directory) | target | see `--selinux` below; never `:Z` |
| auto-mounted agent config (`~/.claude`, `~/.claude.json`, `~/.codex`, ...) | target | see `--selinux` below |
| `-v` volumes you pass | target | exactly as you wrote them; add `:z` yourself if needed |
| enforcer-daemon socket dir (rootless) | leash only | none needed (privileged container) |

`:Z` (a private MCS label) is never used on your files: it locks the path to a
single container's category pair, so the next run (a new container) could not
read the project any more.

## `--selinux` (or `LEASH_SELINUX`)

Your project usually lives under `$HOME` (`user_home_t`), which containers
cannot read. Leash does not relabel it silently:

- `auto` (default). If SELinux is enforcing, the engine labels containers
  (podman always; Docker when its daemon runs with `selinux-enabled`), and the
  project or a config mount is not container-readable, the run is refused
  before anything starts, naming the paths and the two choices below.
  Otherwise the run is unchanged.
- `relabel`: adds `:z` to the project and config mounts. The engine relabels
  them `container_file_t` (shared level `s0`); the change persists on the host
  and the paths stay usable by your own tools. Refused for `/`, top-level
  system directories and your home directory itself.
- `disable`: runs the agent container with `--security-opt label=disable`.
  Nothing on the host changes. Leash's eBPF LSM and proxy enforce the policy
  exactly as before (they are scoped to the container's cgroup, not to its
  SELinux label), but SELinux no longer confines the container's processes.
  That is a real reduction in defence in depth, which is why leash only does it
  when you ask. The run prints a notice saying so.

You can also label the paths yourself (`chcon -R -t container_file_t <dir>`,
or a persistent `semanage fcontext` rule), and `auto` then runs unchanged.

The native runtime has no container and needs none of this.

## Verified (Fedora 44, kernel 6.19, podman 5.8, moby-engine 29, SELinux enforcing)

The standard enforcement matrix (forbidden read/write/create/append denied,
permitted read/write, forbidden exec denied, TCP/UDP to non-permitted
addresses denied, HTTPS allowed and denied by the proxy, MCP tool call allowed
and denied) passes for native, rootful podman, rootful Docker and rootless
podman through the enforcer daemon, including rootless with
`userns = "keep-id"` and rootless storage on fuse-overlayfs, with no AVC
denials from leash.

- The OCI runtime labels each `exec`'d process by writing
  `/proc/self/attr/{exec,keycreate}` (runc) or
  `/proc/thread-self/attr/exec` (crun). Those writes are evaluated by the file
  policy under `/proc/`, like AppArmor's `attr/apparmor/exec`.
- The enforcer daemon's socket (`/run/leash/enforcerd.sock`, `var_run_t`)
  needs no policy module: the leash container that connects to it is
  privileged. The daemon itself runs in `init_t`, because its binary in
  `/usr/local/lib` is labelled `lib_t`; no AVC denials result.
- Build targets that bind-mount the checkout (`make docker-ui`,
  `make lsm-generate-docker`) run their throwaway build containers with
  `--security-opt label=disable` rather than relabelling the repository
  (override with `BUILD_CONTAINER_SECURITY_OPTS=`).
- Rootful podman and Docker on one host: Docker sets the iptables `FORWARD`
  policy to `DROP`, which breaks podman's netavark networking while Docker
  runs. That is a host conflict, not a leash one.
