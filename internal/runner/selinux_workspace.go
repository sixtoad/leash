package runner

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
)

// SELinux handling for the caller's project directory and the auto-mounted
// agent config (~/.claude, ~/.claude.json, ...) in the target container (#175).
//
// On an SELinux-enforcing host a container process runs as container_t and
// can only read files labelled with a container type (container_file_t, ...).
// A project under $HOME is user_home_t, so the agent could not read or exec
// anything in its own workspace. Leash-owned directories (the share, log,
// config and private dirs under the work dir) are relabelled with :z as
// before; the user's own paths are never relabelled silently:
//
//   - auto (default): run unchanged when the paths are already readable by
//     containers (or SELinux is not enforcing, or the engine does not label
//     containers); otherwise refuse before starting anything and name both
//     explicit choices.
//   - relabel: add :z to the project and config mounts. The engine relabels
//     them container_file_t with the shared (s0) level, which persists on the
//     host. Never :Z, which would lock the project to one container's MCS
//     pair and break it for the next run.
//   - disable: run the target container with --security-opt label=disable.
//     Nothing on the host changes. Leash's own enforcement (the eBPF LSM on
//     the target cgroup and the MITM proxy) is unchanged: it does not depend
//     on SELinux. What is lost is SELinux's MAC confinement of the container
//     processes, which is why leash never chooses it on its own.
const (
	selinuxModeAuto    = "auto"
	selinuxModeRelabel = "relabel"
	selinuxModeDisable = "disable"
)

func parseSELinuxMode(raw string) (string, error) {
	switch mode := strings.ToLower(strings.TrimSpace(raw)); mode {
	case "", selinuxModeAuto:
		return selinuxModeAuto, nil
	case selinuxModeRelabel, selinuxModeDisable:
		return mode, nil
	default:
		return "", fmt.Errorf("invalid SELinux mode %q (--selinux / LEASH_SELINUX): want auto, relabel or disable", strings.TrimSpace(raw))
	}
}

// selinuxEnforcing reports whether SELinux is in enforcing mode. A variable so
// tests can simulate an SELinux host.
var selinuxEnforcing = func() bool {
	data, err := os.ReadFile("/sys/fs/selinux/enforce")
	return err == nil && strings.TrimSpace(string(data)) == "1"
}

// selinuxFileType returns the SELinux type of path (the third field of its
// security.selinux label). A variable so tests can supply labels.
var selinuxFileType = func(path string) (string, error) {
	label, err := getSELinuxLabel(path)
	if err != nil {
		return "", err
	}
	parts := strings.Split(strings.TrimRight(label, "\x00"), ":")
	if len(parts) < 3 {
		return "", fmt.Errorf("unexpected SELinux label %q", label)
	}
	return parts[2], nil
}

// containerReadableSELinuxTypes are the file types container_t may read and
// write under container-selinux.
var containerReadableSELinuxTypes = map[string]bool{
	"container_file_t":     true,
	"container_ro_file_t":  true,
	"container_share_t":    true,
	"svirt_sandbox_file_t": true, // pre-container-selinux alias of container_file_t
}

// engineLabelsContainers reports whether the container engine confines its
// containers with SELinux labels. Podman always does on an SELinux host;
// Docker only when its daemon runs with selinux-enabled. An engine that cannot
// be queried is assumed to label (the check then errs towards a clear refusal
// rather than an unreadable workspace).
func (r *runner) engineLabelsContainers(ctx context.Context) bool {
	switch r.rt().Name() {
	case "docker":
		out, err := r.rt().Output(ctx, "info", "--format", "{{json .SecurityOptions}}")
		if err != nil {
			return true
		}
		return strings.Contains(out, "selinux")
	case "podman":
		out, err := r.rt().Output(ctx, "info", "--format", "{{.Host.Security.SELinuxEnabled}}")
		if err != nil {
			return true
		}
		return strings.TrimSpace(out) != "false"
	default:
		return true
	}
}

// selinuxTargetMode decides how the target container's user-owned mounts are
// handled on this host: "" (nothing to do), selinuxModeRelabel or
// selinuxModeDisable. In auto mode it refuses, with the choices, when the
// project or a config mount is not readable by containers. hostPaths are the
// caller-owned host paths the target container will bind.
func (r *runner) selinuxTargetMode(ctx context.Context, hostPaths []string) (string, error) {
	if r.cfg.hostOS != "linux" || !selinuxEnforcing() {
		return "", nil
	}
	mode, err := parseSELinuxMode(r.cfg.selinuxMode)
	if err != nil {
		return "", err
	}
	switch mode {
	case selinuxModeDisable:
		r.diagnosticf("leash: SELinux: the agent container runs with label=disable (--selinux disable): leash's eBPF LSM and proxy enforce the policy unchanged; SELinux does not confine the container.\n")
		return selinuxModeDisable, nil
	case selinuxModeRelabel:
		for _, host := range hostPaths {
			if reason := refuseRelabel(host); reason != "" {
				return "", fmt.Errorf("--selinux relabel would relabel %s (%s); move the project, label it yourself (chcon -R -t container_file_t <path>), or use --selinux disable", host, reason)
			}
		}
		r.diagnosticf("leash: SELinux: relabelling the project and agent config mounts container_file_t (:z, --selinux relabel)\n")
		return selinuxModeRelabel, nil
	}
	if !r.engineLabelsContainers(ctx) {
		return "", nil
	}
	var blocked []string
	for _, host := range hostPaths {
		typ, err := selinuxFileType(host)
		if err != nil {
			blocked = append(blocked, fmt.Sprintf("  %s (label unreadable: %v)", host, err))
			continue
		}
		if !containerReadableSELinuxTypes[typ] {
			blocked = append(blocked, fmt.Sprintf("  %s (%s)", host, typ))
		}
	}
	if len(blocked) == 0 {
		return "", nil
	}
	return "", fmt.Errorf(`SELinux is enforcing and the agent container cannot read these host paths (not labelled for container access):
%s
leash will not start an agent that cannot see its workspace. Choose one (flag, or LEASH_SELINUX=<mode>):
  --selinux relabel   relabel them container_file_t with :z (shared label; the change persists on the host)
  --selinux disable   run the agent container with --security-opt label=disable: nothing on the host changes and
                      leash's eBPF LSM and proxy enforce the policy unchanged, but SELinux no longer confines the container
Or label them yourself: chcon -R -t container_file_t <path>`, strings.Join(blocked, "\n"))
}

// refuseRelabel names why a recursive relabel of host would be unsafe, or "".
// Relabelling the filesystem root, a top-level system directory or a whole
// home directory would change labels far beyond the project.
func refuseRelabel(host string) string {
	clean := filepath.Clean(host)
	if systemTopLevelDirs[clean] {
		return "a system directory"
	}
	if filepath.Dir(clean) == "/home" {
		return "a home directory"
	}
	for _, home := range candidateHomes() {
		if home != "" && clean == filepath.Clean(home) {
			return "a home directory"
		}
	}
	return ""
}

var systemTopLevelDirs = map[string]bool{
	"/": true, "/bin": true, "/boot": true, "/dev": true, "/etc": true, "/home": true,
	"/lib": true, "/lib64": true, "/media": true, "/mnt": true, "/opt": true, "/proc": true,
	"/root": true, "/run": true, "/sbin": true, "/srv": true, "/sys": true, "/tmp": true,
	"/usr": true, "/var": true,
}

// candidateHomes are the invoking user's home directories, including the
// sudo caller's (a rootful run is usually `sudo leash` from the user's tree).
func candidateHomes() []string {
	homes := []string{os.Getenv("HOME")}
	if h, err := os.UserHomeDir(); err == nil {
		homes = append(homes, h)
	}
	if name := strings.TrimSpace(os.Getenv("SUDO_USER")); name != "" {
		if u, err := user.Lookup(name); err == nil {
			homes = append(homes, u.HomeDir)
		}
	}
	return homes
}
