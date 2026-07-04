package runner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/strongdm/leash/internal/entrypoint"
)

// nativeLauncher implements launcher without a container runtime: the workload
// runs in a delegated systemd cgroup-v2 scope (Layer-1 attach point) plus a
// named network namespace (Layer-2 intercept point). StartEnforcement runs
// leashd host mode against the box; enforcement requires root (gated by
// preflightNativeRuntime). See docs/{RUNTIME-NATIVE-POC,LAUNCHER-ABSTRACTION,
// LEASHD-HOST-MODE,NATIVE-ENFORCEMENT-RUNBOOK}.md.
//
// It holds *runner like containerLauncher and derives all unit/netns names
// deterministically from runner state, so a fresh value from r.launcher() agrees
// with a prior Provision (no stored state needed across calls).
// nativeLayer2Enabled gates native's Layer-2 path: a dedicated workload netns
// with egress (veth + host NAT + DNS) plus the leashd MITM proxy / netfilter
// REDIRECT. When enabled, Provision wires the netns egress; if that setup fails
// at runtime the box falls back to LSM-only (see layer2Active). LSM-only keeps
// file/exec/network-connect enforcement (eBPF LSM on the cgroup) but drops the
// L7 HTTP MITM.
const nativeLayer2Enabled = true

type nativeLauncher struct {
	r *runner
}

// layer2Active reports whether the Layer-2 proxy path is in effect for this run:
// compiled in AND root (netns needs privilege) AND egress setup didn't fail
// during Provision. Every netns/nsenter/proxy decision routes through here so a
// failed egress cleanly degrades the whole run to LSM-only.
func (n nativeLauncher) layer2Active() bool {
	return nativeLayer2Enabled && !n.useUserManager() && !n.r.nativeEgressFailed
}

func (n nativeLauncher) Name() string { return "native" }

// useUserManager runs against the per-user systemd manager when unprivileged, so
// the box forms without root (a real enforcing run uses the system manager — see
// LEASHD-HOST-MODE.md "system vs user scope").
func (n nativeLauncher) useUserManager() bool { return os.Geteuid() != 0 }

func (n nativeLauncher) userFlag() []string {
	if n.useUserManager() {
		return []string{"--user"}
	}
	return nil
}

// boxBaseName is a filesystem/unit-safe identity for this session's box.
func (n nativeLauncher) boxBaseName() string {
	base := sanitizeNativeName(n.r.cfg.targetContainer)
	if base == "" {
		base = "session"
	}
	return "leash-native-" + base
}

func (n nativeLauncher) unitName() string  { return n.boxBaseName() + ".service" }
func (n nativeLauncher) netnsName() string { return n.boxBaseName() }

func sanitizeNativeName(raw string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(raw)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_':
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

// PullImages is a no-op: native runs the workload from the host filesystem, with
// no image to fetch.
func (n nativeLauncher) PullImages(ctx context.Context) error {
	n.r.debugf("native runtime: no image to pull (workload runs from the host filesystem)")
	return nil
}

// Provision builds the box: a detached, delegated cgroup-v2 holder unit (keeps
// the cgroup alive for the session) and, when privileged, a named netns. It
// returns the holder's cgroup path — the same kind of path leashd attaches the
// eBPF LSM to.
func (n nativeLauncher) Provision(ctx context.Context, stopSignal string) (string, error) {
	unit := n.unitName()
	// Clear any stale unit from a crashed prior run (best-effort).
	n.stopUnit(ctx, unit)

	// A transient *service* (not --scope) is the right systemd primitive for a
	// holder systemd itself starts: it is detached and managed, and Delegate=yes
	// still yields a delegated cgroup-v2 subtree we own. "sleep infinity" just
	// holds the box open until Remove.
	runArgs := append(n.userFlag(),
		"--quiet", "--collect", "--property=Delegate=yes",
		"--unit="+unit, "--", "sleep", "infinity")
	if out, err := hostOutput(ctx, "systemd-run", runArgs...); err != nil {
		return "", fmt.Errorf("native: start cgroup holder %q: %w (%s)", unit, err, strings.TrimSpace(out))
	}

	rel, err := hostOutput(ctx, "systemctl", append(n.userFlag(), "show", "-p", "ControlGroup", "--value", unit)...)
	rel = strings.TrimSpace(rel)
	if err != nil || rel == "" {
		n.stopUnit(ctx, unit)
		return "", fmt.Errorf("native: read holder cgroup for %q: %w", unit, err)
	}
	cgroupPath := filepath.Join("/sys/fs/cgroup", rel)

	if nativeLayer2Enabled && !n.useUserManager() {
		if err := n.addNetns(ctx); err != nil {
			// Egress setup failed — degrade this run to LSM-only rather than trap
			// the workload in a netns with no route out. Clean up any partial state.
			n.r.nativeEgressFailed = true
			n.teardownEgress(ctx)
			_, _ = hostOutput(ctx, "ip", "netns", "del", n.netnsName())
			n.r.logger.Printf("leash: native Layer-2 egress setup failed (%v); falling back to LSM-only (no L7 proxy).", err)
		}
	} else {
		n.r.debugf("native box: LSM-only (rootless or Layer 2 disabled)")
	}

	n.r.debugf("native box ready: unit=%s cgroup=%s", unit, cgroupPath)
	return cgroupPath, nil
}

// StartEnforcement runs leashd host mode (leash --daemon --host) inside the
// workload's network namespace via nsenter, re-execing this same binary —
// leashd attaches the eBPF LSM to cgroupPath and applies the netns-scoped
// netfilter + proxy (see docs/LEASHD-HOST-MODE.md). It runs only when the
// prerequisites hold (root for the named netns + netfilter); otherwise it
// returns an actionable error that names the blocker and the exact command it
// would run, rather than failing opaquely. (Enforcement also needs an active
// bpf LSM — the lsm=…,bpf reboot — which leashd reports when it attempts attach.)
func (n nativeLauncher) StartEnforcement(ctx context.Context, cgroupPath string) error {
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("native: locate leash binary: %w", err)
	}
	netnsPath := n.netnsRunPath()
	argv := n.hostLeashdArgv(self, netnsPath, cgroupPath)

	if blocker := n.enforcementBlocker(netnsPath); blocker != "" {
		return fmt.Errorf(
			"native enforcement not startable: %s. The container-free box is provisioned; "+
				"would run: %s (see docs/LEASHD-HOST-MODE.md)",
			blocker, strings.Join(argv, " "))
	}

	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = append(os.Environ(), n.leashdEnv()...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Start()
}

// leashdEnv passes the runner's host directories to the spawned leashd so it
// reads/writes them instead of the container defaults (/leash, /cfg, /log).
func (n nativeLauncher) leashdEnv() []string {
	env := []string{"LEASH_HOST=1"}
	if v := strings.TrimSpace(n.r.cfg.shareDir); v != "" {
		env = append(env, "LEASH_DIR="+v)
	}
	if v := strings.TrimSpace(n.r.cfg.privateDir); v != "" {
		env = append(env, "LEASH_PRIVATE_DIR="+v)
	}
	if v := strings.TrimSpace(n.r.cfg.logDir); v != "" {
		env = append(env, "LEASH_LOG="+filepath.Join(v, "events.log"))
	}
	return env
}

// netnsRunPath is the iproute2 named-netns path Provision creates (when root).
func (n nativeLauncher) netnsRunPath() string {
	return filepath.Join("/run/netns", n.netnsName())
}

// hostLeashdArgv builds the command that launches leashd host mode. With Layer 2
// active it runs inside the workload netns with a private resolv.conf bind (the
// proxy needs DNS to reach upstreams); LSM-only it runs in the host netns with
// --lsm-only (no proxy/netfilter). Unit-tested via the LSM-only path.
func (n nativeLauncher) hostLeashdArgv(self, netnsPath, cgroupPath string) []string {
	leashd := []string{self, "--daemon", "--host"}
	if !n.layer2Active() {
		leashd = append(leashd, "--lsm-only")
	}
	leashd = append(leashd, "--cgroup", cgroupPath)
	if cfgDir := strings.TrimSpace(n.r.cfg.cfgDir); cfgDir != "" {
		leashd = append(leashd, "--policy", filepath.Join(cfgDir, "leash.cedar"))
	}
	if port := strings.TrimSpace(n.r.cfg.proxyPort); port != "" {
		leashd = append(leashd, "--proxy-port", port)
	}
	if !n.r.cfg.listenCfg.Disable {
		// Skip an unresolved address (zero-value Config yields ":"); a real run
		// has a concrete host:port here.
		if addr := strings.TrimSpace(n.r.cfg.listenCfg.Address()); addr != "" && addr != ":" {
			leashd = append(leashd, "--listen", addr)
		}
	}
	if !n.layer2Active() {
		return leashd // host netns, run directly
	}
	// Layer 2: run leashd in the netns with the DNS bind (see layer2Wrap).
	return n.layer2Wrap("exec " + shellJoin(leashd))
}

// shellJoin renders argv as a shell-safe single string for `sh -c`.
func shellJoin(argv []string) string {
	parts := make([]string, len(argv))
	for i, a := range argv {
		parts[i] = quoteShellArg(a)
	}
	return strings.Join(parts, " ")
}

// enforcementBlocker reports why enforcement can't start here, or "" if it can.
// Native enforcement needs root to attach the eBPF LSM (and, with Layer 2, to
// create the netns + apply netfilter).
func (n nativeLauncher) enforcementBlocker(netnsPath string) string {
	if n.useUserManager() {
		return "requires root to attach the eBPF LSM (the box ran rootless). Re-run with sudo, or use --runtime docker"
	}
	if n.layer2Active() {
		if _, err := os.Stat(netnsPath); err != nil {
			return fmt.Sprintf("network namespace %s not found", netnsPath)
		}
	}
	return ""
}

// WaitReady drives the bootstrap handshake (option A, LEASHD-HOST-MODE.md §4):
// the launcher plays the role the container's leash-entry plays — it writes the
// bootstrap marker so leashd proceeds to attach the LSM — then waits for leashd
// to publish its CA cert, the same readiness signal the container path waits on.
// This preserves the fail-closed ordering: the workload is not exec'd until this
// returns nil. A no-op when enforcement wasn't started (degraded box).
func (n nativeLauncher) WaitReady(ctx context.Context) error {
	shareDir := strings.TrimSpace(n.r.cfg.shareDir)
	if shareDir == "" {
		return nil
	}
	marker := filepath.Join(shareDir, entrypoint.BootstrapReadyFileName)
	ready := filepath.Join(shareDir, entrypoint.EnforcementReadyFileName)
	// leashd clears the bootstrap marker once at startup, then waits for it.
	// StartEnforcement spawned leashd asynchronously, so re-assert the marker on
	// each poll to win that race. Crucially, wait for the *enforcement-ready*
	// marker — leashd writes it AFTER attaching the eBPF LSM — not the CA cert,
	// which is published earlier: the workload must not run until Layer 1 is live
	// (fail-closed).
	for i := 0; i < caCertWaitAttempts; i++ {
		// leashd reads the bootstrap marker as JSON metadata; write a valid object.
		_ = os.WriteFile(marker, []byte(`{"source":"native"}`+"\n"), 0o644)
		if _, err := os.Stat(ready); err == nil {
			// Layer 2 MITMs TLS: publish leash's CA where the dropped-privilege
			// workload can read it (leashd's share dir is a 0700 root tree).
			if n.layer2Active() {
				n.exportCACert(shareDir)
			}
			return nil
		}
		time.Sleep(caCertWaitDelay)
	}
	n.r.logger.Println("Warning: native enforcement was not confirmed ready after waiting; the workload may run before Layer 1 is active.")
	return nil
}

// userReadableCACert is a world-readable copy of leash's CA under /tmp (which
// the confinement policy already allows), so the workload — running as the
// invoking user — can load it via NODE_EXTRA_CA_CERTS. leashd's own ca-cert.pem
// sits in a 0700 root-owned share tree the dropped user can't traverse.
func (n nativeLauncher) userReadableCACert() string {
	// /tmp explicitly (not os.TempDir, which may inherit a TMPDIR outside the
	// confinement allow-list): world-traversable and policy-allowed by default.
	return filepath.Join("/tmp", "leash-native-ca-"+n.netnsName()+".pem")
}

// exportCACert copies leashd's CA to userReadableCACert (0644). Best-effort: a
// failure only means the workload won't trust the MITM (TLS errors), not a crash.
func (n nativeLauncher) exportCACert(shareDir string) {
	data, err := os.ReadFile(caCertPath(shareDir))
	if err != nil {
		n.r.debugf("native L2: read CA: %v", err)
		return
	}
	if err := os.WriteFile(n.userReadableCACert(), data, 0o644); err != nil {
		n.r.debugf("native L2: publish CA: %v", err)
	}
}

// Remove tears the box down: undo the netns egress (veth + host NAT + DNS),
// delete the netns, and stop the holder unit. Gated on the attempt (root +
// compiled), not layer2Active, so a run that fell back to LSM-only after a
// partial egress setup still cleans up.
func (n nativeLauncher) Remove(ctx context.Context) {
	if nativeLayer2Enabled && !n.useUserManager() {
		n.teardownEgress(ctx)
		_, _ = hostOutput(ctx, "ip", "netns", "del", n.netnsName())
		_ = os.Remove(n.userReadableCACert())
	}
	n.stopUnit(ctx, n.unitName())
}

func (n nativeLauncher) addNetns(ctx context.Context) error {
	if out, err := hostOutput(ctx, "ip", "netns", "add", n.netnsName()); err != nil {
		return fmt.Errorf("%w (%s)", err, strings.TrimSpace(out))
	}
	// A fresh netns has loopback DOWN; leashd binds the proxy/Control UI on
	// 127.0.0.1 inside it, so bring lo up.
	if out, err := hostOutput(ctx, "ip", "-n", n.netnsName(), "link", "set", "lo", "up"); err != nil {
		return fmt.Errorf("bring up lo in netns: %w (%s)", err, strings.TrimSpace(out))
	}
	// Give the netns a route out (veth + host NAT + DNS) so the proxy can forward
	// and the agent can reach the network. Without this the netns has only lo.
	if err := n.setupEgress(ctx); err != nil {
		return fmt.Errorf("egress: %w", err)
	}
	return nil
}

// nativeEgressResolvConf is the resolv.conf bind-mounted into the workload's
// mount ns. Pop!_OS points /etc/resolv.conf at systemd-resolved's 127.0.0.53
// stub, which is meaningless inside the netns; use public resolvers reachable
// via the NAT. (TODO: optionally forward the host's real upstream for split-horizon/LAN DNS.)
const nativeEgressResolvConf = "nameserver 1.1.1.1\nnameserver 8.8.8.8\n"

// egressNet holds the per-box network parameters, derived deterministically from
// the netns name so a fresh launcher value agrees with a prior Provision and
// concurrent boxes get distinct subnets/veth names.
type egressNet struct {
	ns, vethHost, vethNS, subnet, hostIP, nsIP string
	prefix                                     int
}

func fnv32(s string) uint32 {
	var h uint32 = 2166136261
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return h
}

func (n nativeLauncher) egress() egressNet {
	ns := n.netnsName()
	h := fnv32(ns)
	// 10.<100..199>.<0..253>.0/30 → ~25k distinct /30s, collision-unlikely.
	subnet := fmt.Sprintf("10.%d.%d", 100+int(h%100), int((h/100)%254))
	short := fmt.Sprintf("%06x", h&0xFFFFFF) // 6 hex → veth name ≤ 8 chars (< 15 limit)
	return egressNet{
		ns:       ns,
		vethHost: "lh" + short,
		vethNS:   "ln" + short,
		subnet:   subnet,
		hostIP:   subnet + ".1",
		nsIP:     subnet + ".2",
		prefix:   30,
	}
}

// setupEgress wires veth + addressing + default route + DNS + host NAT so the
// netns reaches the internet. Mirrors the recipe verified in netns-egress.sh.
func (n nativeLauncher) setupEgress(ctx context.Context) error {
	e := n.egress()
	cidr := func(ip string) string { return ip + "/" + strconv.Itoa(e.prefix) }
	steps := [][]string{
		{"ip", "link", "add", e.vethHost, "type", "veth", "peer", "name", e.vethNS},
		{"ip", "link", "set", e.vethNS, "netns", e.ns},
		{"ip", "addr", "add", cidr(e.hostIP), "dev", e.vethHost},
		{"ip", "-n", e.ns, "addr", "add", cidr(e.nsIP), "dev", e.vethNS},
		{"ip", "link", "set", e.vethHost, "up"},
		{"ip", "-n", e.ns, "link", "set", e.vethNS, "up"},
		{"ip", "-n", e.ns, "route", "add", "default", "via", e.hostIP},
		{"sysctl", "-q", "-w", "net.ipv4.ip_forward=1"},
		{"iptables", "-t", "nat", "-A", "POSTROUTING", "-s", cidr(e.subnet + ".0"), "-j", "MASQUERADE"},
		{"iptables", "-A", "FORWARD", "-i", e.vethHost, "-j", "ACCEPT"},
		{"iptables", "-A", "FORWARD", "-o", e.vethHost, "-j", "ACCEPT"},
	}
	for _, s := range steps {
		if out, err := hostOutput(ctx, s[0], s[1:]...); err != nil {
			return fmt.Errorf("%v: %w (%s)", s, err, strings.TrimSpace(out))
		}
	}
	dir := filepath.Join("/etc/netns", e.ns)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("resolv.conf dir: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "resolv.conf"), []byte(nativeEgressResolvConf), 0o644); err != nil {
		return fmt.Errorf("resolv.conf: %w", err)
	}
	return nil
}

// teardownEgress reverses setupEgress, best-effort (each step ignores errors so a
// partial setup still cleans up). Deleting vethHost removes its netns peer.
func (n nativeLauncher) teardownEgress(ctx context.Context) {
	e := n.egress()
	cidr := e.subnet + ".0/" + strconv.Itoa(e.prefix)
	_, _ = hostOutput(ctx, "iptables", "-t", "nat", "-D", "POSTROUTING", "-s", cidr, "-j", "MASQUERADE")
	_, _ = hostOutput(ctx, "iptables", "-D", "FORWARD", "-i", e.vethHost, "-j", "ACCEPT")
	_, _ = hostOutput(ctx, "iptables", "-D", "FORWARD", "-o", e.vethHost, "-j", "ACCEPT")
	_, _ = hostOutput(ctx, "ip", "link", "del", e.vethHost)
	_ = os.RemoveAll(filepath.Join("/etc/netns", e.ns))
}

// layer2Wrap wraps an inner shell command to run in the workload netns with the
// netns resolv.conf bind-mounted in a PRIVATE mount ns (so the host's is
// untouched), entering via nsenter --net — which preserves /sys/fs/{cgroup,bpf}
// that the LSM and cgroup placement need (ip netns exec would remount /sys). This
// is the exact chain verified in netns-launch.sh.
func (n nativeLauncher) layer2Wrap(inner string) []string {
	resolv := quoteShellArg(filepath.Join("/etc/netns", n.egress().ns, "resolv.conf"))
	bind := fmt.Sprintf("mount --bind %s /etc/resolv.conf 2>/dev/null || mount --bind %s \"$(readlink -f /etc/resolv.conf)\" 2>/dev/null; ", resolv, resolv)
	return []string{
		"nsenter", "--net=" + n.netnsRunPath(), "--",
		"unshare", "--mount", "--propagation", "private", "--",
		"sh", "-c", bind + inner,
	}
}

func (n nativeLauncher) stopUnit(ctx context.Context, unit string) {
	_, _ = hostOutput(ctx, "systemctl", append(n.userFlag(), "stop", unit)...)
	_, _ = hostOutput(ctx, "systemctl", append(n.userFlag(), "reset-failed", unit)...)
}

// execInBox builds a command that runs argv inside the box's cgroup. Rootless
// placement: under cgroup-v2 delegation the holder's cgroup.procs is writable by
// the owner, so the shell writes its own PID into it and then execs argv — argv
// inherits the LSM-scoped cgroup. (A future enforcing path also joins the netns
// via nsenter; not needed while StartEnforcement is stubbed.)
func (n nativeLauncher) execInBox(ctx context.Context, cgroupPath string, argv ...string) *exec.Cmd {
	procs := quoteShellArg(filepath.Join(cgroupPath, "cgroup.procs"))
	script := fmt.Sprintf("echo $$ > %s && exec \"$@\"", procs)
	args := append([]string{"-c", script, "leash-native"}, argv...)
	return exec.CommandContext(ctx, "sh", args...)
}

// Preflight validates that native can enforce here (Linux + systemd + root),
// failing with actionable advice otherwise — never a silent docker fallback.
func (n nativeLauncher) Preflight() error {
	return decideNativeRuntime(classifyNativeRuntime(goos(), hostHasSystemd(), os.Geteuid()))
}

func (n nativeLauncher) RequiredCommands() []string { return []string{"systemd-run", "systemctl"} }

// EnsureNotRunning is a no-op: Provision clears any stale box (systemd unit).
func (n nativeLauncher) EnsureNotRunning(ctx context.Context) error { return nil }

// AssignNames takes the base names directly — the box is a systemd unit derived
// from them; there is no registry to probe for collisions.
func (n nativeLauncher) AssignNames(ctx context.Context, baseTarget, baseLeash string) error {
	n.r.cfg.targetContainer = baseTarget
	n.r.cfg.leashContainer = baseLeash
	return nil
}

// StopSignal: the holder is stopped via systemctl, not a signal.
func (n nativeLauncher) StopSignal(ctx context.Context) (string, error) { return "SIGTERM", nil }

// PublishesPorts: native runs on the host and maps no container ports.
func (n nativeLauncher) PublishesPorts() bool { return false }

func (n nativeLauncher) DetectShell(ctx context.Context) (string, error) {
	// The workload runs on the host; pick the host's shell.
	if _, err := exec.LookPath("bash"); err == nil {
		return "bash", nil
	}
	if _, err := exec.LookPath("sh"); err == nil {
		return "sh", nil
	}
	return "", fmt.Errorf("failed to locate a usable shell (bash or sh) on the host")
}

func (n nativeLauncher) ExecCommand(ctx context.Context, shellBin, cmd string, interactive bool) *exec.Cmd {
	return n.workloadCommand(ctx, n.r.cgroupPath, n.r.cfg.callerDir, shellBin, cmd)
}

// Precheck: the container setns/tty precheck is not a native concern.
func (n nativeLauncher) Precheck(ctx context.Context, shellBin, cmd string) error { return nil }

// InstallPromptAssets: no-op — native runs on the host filesystem and must not
// write to the host's /etc/profile.d.
func (n nativeLauncher) InstallPromptAssets(ctx context.Context) error { return nil }

// workloadCommand builds the user's command to run inside the box: placed in
// the LSM-scoped cgroup, in workdir, via `shellBin -lc "exec <cmd>"`. When
// privileged it is wrapped in `nsenter --net=<ns>` so the workload also runs in
// the enforced network namespace (Layer 2); rootless (degraded/unenforced) it
// runs in the user-scope cgroup without a netns.
func (n nativeLauncher) workloadCommand(ctx context.Context, cgroupPath, workdir, shellBin, cmd string) *exec.Cmd {
	// Under Layer 2 the proxy MITMs TLS, so the agent must trust leash's CA. The
	// container path installs it via the entrypoint; native has none, so point
	// Node (Claude Code is Node) at the CA additively via NODE_EXTRA_CA_CERTS
	// (leaves the system roots intact). Only meaningful with the proxy active.
	caCert := ""
	if n.layer2Active() {
		caCert = n.userReadableCACert() // world-readable copy WaitReady published
	}
	inner := nativeWorkloadScript(cgroupPath, workdir, shellBin, cmd, n.workloadUser(), caCert)
	if n.layer2Active() {
		argv := n.layer2Wrap(inner)
		return exec.CommandContext(ctx, argv[0], argv[1:]...)
	}
	return exec.CommandContext(ctx, "sh", "-c", inner)
}

// workloadUser returns the non-root user the workload should run as, or "" to
// keep the current uid. The eBPF LSM enforces on the cgroup regardless of uid,
// so when leash runs as root (typical: `sudo leash`) the agent need not — and
// many agents refuse to (e.g. Claude Code blocks --dangerously-skip-permissions
// as root). We drop to the invoking user ($SUDO_USER); leash and leashd keep
// root only for enforcement. Non-root leash (rootless box) needs no drop.
func (n nativeLauncher) workloadUser() string {
	if os.Geteuid() != 0 {
		return ""
	}
	u := strings.TrimSpace(os.Getenv("SUDO_USER"))
	if u == "" || u == "root" {
		return ""
	}
	return u
}

// nativeWorkloadScript builds the shell placed in the box: join the LSM-scoped
// cgroup, cd to workdir, then exec the command — dropping to dropUser via runuser
// when set, and exporting NODE_EXTRA_CA_CERTS (for the L2 MITM) when caCert is
// set. The export goes in the innermost shell so it survives the runuser hop.
// Pure, so it is unit-tested.
func nativeWorkloadScript(cgroupPath, workdir, shellBin, cmd, dropUser, caCert string) string {
	procs := quoteShellArg(filepath.Join(cgroupPath, "cgroup.procs"))
	innerCmd := "exec " + cmd
	if caCert != "" {
		innerCmd = "export NODE_EXTRA_CA_CERTS=" + quoteShellArg(caCert) + "; " + innerCmd
	}
	run := fmt.Sprintf("exec %s -lc %s", quoteShellArg(shellBin), quoteShellArg(innerCmd))
	if dropUser != "" {
		run = fmt.Sprintf("exec runuser -u %s -- %s -lc %s",
			quoteShellArg(dropUser), quoteShellArg(shellBin), quoteShellArg(innerCmd))
	}
	return fmt.Sprintf("echo $$ > %s && cd %s && %s", procs, quoteShellArg(workdir), run)
}

// hostOutput runs a host command (systemd-run/systemctl/ip), capturing combined
// output. Native uses host tooling directly, independent of the container
// Runtime command wrappers.
func hostOutput(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}
