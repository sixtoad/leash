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
	"github.com/strongdm/leash/internal/leashd/listen"
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

// boxBaseName is a filesystem/unit-safe identity for this session's box. It
// carries a per-run suffix (this leash process's PID) so that CONCURRENT native
// runs — even in the same project — get distinct netns/unit/subnet/CA/log names
// and don't collide. Container backends get that isolation for free (a fresh
// netns per container); native shares the host, so the box identity must be
// unique. os.Getpid() is stable across this process's launcher calls (so a fresh
// launcher value still agrees with Provision) and unique among live processes (so
// no probe/race is needed). Stale same-named state from a crashed run whose PID
// is later reused is cleared defensively in Provision/addNetns.
func (n nativeLauncher) boxBaseName() string {
	base := sanitizeNativeName(n.r.cfg.targetContainer)
	if base == "" {
		base = "session"
	}
	return fmt.Sprintf("leash-native-%s-%d", base, os.Getpid())
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
	// Native runs leashd in the same TTY as the (interactive) workload, so its
	// ongoing proxy/LSM logs would corrupt the agent's TUI. Send them to a file
	// instead — the container path sends leashd logs to the runtime, not the
	// workload's terminal. On failure, leave stdout/stderr nil (discarded) rather
	// than fall back to the TTY.
	var logf *os.File
	if f, err := os.Create(n.leashdLogPath()); err == nil {
		logf = f
		cmd.Stdout, cmd.Stderr = f, f
	} else {
		n.r.debugf("native: leashd log file %s: %v (discarding leashd output)", n.leashdLogPath(), err)
	}
	if err := cmd.Start(); err != nil {
		if logf != nil {
			logf.Close()
		}
		return err
	}
	// Reap leashd and signal its exit so WaitReady can fail fast if it dies before
	// enforcement is ready (e.g. leashd os.Exit(1)s on an LSM attach abort under
	// --require-lsm) instead of blocking for the whole readiness timeout.
	exited := make(chan struct{})
	n.r.leashdExited = exited
	go func() {
		_ = cmd.Wait()
		if logf != nil {
			logf.Close()
		}
		close(exited)
	}()
	if err := n.injectServices(ctx); err != nil {
		return err
	}
	return nil
}

// injectSocketEnv and injectConfigFileEnv carry a plugin's listen socket and its
// opaque config to the helper via the environment (not argv, so the config stays
// out of `ps`).
const (
	injectSocketEnv = "LEASH_INJECT_SOCKET"
	// injectConfigFileEnv points the plugin at a 0600 file holding the opaque
	// config instead of passing it inline: on the `runuser -- env KEY=VAL` path an
	// inline value shows in /proc/<pid>/cmdline (visible in `ps`), so the config
	// travels via a file the plugin reads.
	injectConfigFileEnv = "LEASH_INJECT_CONFIG_FILE"
)

// injectServices spawns each --inject-service helper plugin: leash knows only the
// plugin name, an env var, a socket path, and an opaque config payload it never
// interprets — never the plugin's protocol. Each plugin runs as the invoking user
// (root can't reach the user's session resources); leash records the socket→env
// mapping for the workload and fails the run if any plugin can't start
// (fail-closed).
func (n nativeLauncher) injectServices(ctx context.Context) error {
	// Reject duplicate socket paths / env keys across specs BEFORE spawning anything:
	// two plugins binding the same socket, or two env vars colliding, is always a
	// misconfiguration — catch it up front rather than after starting some plugins.
	if err := n.r.checkInjectDuplicates("native"); err != nil {
		return err
	}
	for _, svc := range n.r.opts.injectServices {
		if err := n.injectOne(ctx, svc); err != nil {
			return err
		}
	}
	return nil
}

// injectOne spawns one native inject-service plugin (via the shared, hardened
// r.spawnInjectService) and records the socket→env mapping the native workload
// script consumes. Container backends bind the socket into the container instead
// of setting the workload env directly (see spawnInjectServicesContainer).
func (n nativeLauncher) injectOne(ctx context.Context, svc injectService) error {
	if err := n.r.spawnInjectService(ctx, svc); err != nil {
		return err
	}
	// The workload reaches the plugin via a generic unix-domain-socket address;
	// leash sets only the mapped env var and stays protocol-agnostic.
	n.r.injectedEnv = append(n.r.injectedEnv, svc.env+"=unix:path="+svc.socket)
	return nil
}

// checkInjectDuplicates rejects duplicate socket paths / env keys across the
// --inject-service specs BEFORE anything is spawned: two plugins binding the same
// socket, or two env vars colliding, is always a misconfiguration. backend names
// the launcher for the error message ("native"/"container").
func (r *runner) checkInjectDuplicates(backend string) error {
	seenSocket := make(map[string]bool, len(r.opts.injectServices))
	seenEnv := make(map[string]bool, len(r.opts.injectServices))
	for _, svc := range r.opts.injectServices {
		if seenSocket[svc.socket] {
			return fmt.Errorf("%s: duplicate --inject-service socket %q", backend, svc.socket)
		}
		if seenEnv[svc.env] {
			return fmt.Errorf("%s: duplicate --inject-service env %q", backend, svc.env)
		}
		seenSocket[svc.socket] = true
		seenEnv[svc.env] = true
	}
	return nil
}

// spawnInjectService spawns one --inject-service helper plugin and blocks until it
// is ready (fail-closed), shared verbatim by the native and container launchers so
// both get identical hardening. It resolves the plugin, creates+chowns the socket
// dir (only when it created it), re-checks the symlink-resolved socket path against
// the protected roots, clears a stale socket, writes the opaque config to a 0600
// file out of argv, spawns the plugin AS the invoking user (runuser when euid==0
// with a SUDO_USER, else as self — so it works for the rootless container path
// where leash already runs as the user), records the process/cleanup paths, and
// waits up to 2s for the socket to appear. It does NOT map the socket to the
// workload env / docker args — the caller does that (native sets injectedEnv;
// container builds injectedDockerArgs).
func (r *runner) spawnInjectService(ctx context.Context, svc injectService) error {
	pluginPath, err := r.resolvePlugin(svc.plugin)
	if err != nil {
		return fmt.Errorf("native: locate inject-service plugin %q: %w", svc.plugin, err)
	}
	parent := filepath.Dir(svc.socket)
	// Note whether we create the parent: only a dir WE create may be chowned to the
	// dropped user (P2) — never a pre-existing dir like /tmp.
	parentPreexisted := true
	if _, err := os.Stat(parent); os.IsNotExist(err) {
		parentPreexisted = false
	}
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return fmt.Errorf("native: inject-service socket dir: %w", err)
	}
	// When we spawn the plugin as the invoking user, a root-owned socket dir we just
	// created isn't writable by that user; chown the created dir so the dropped
	// plugin can bind. Only for a dir we created — never chown a pre-existing one.
	if r.workloadUser() != "" && !parentPreexisted {
		if uid, gid := r.workloadUIDGID(); uid >= 0 {
			if err := os.Chown(parent, uid, gid); err != nil {
				return fmt.Errorf("native: chown inject-service socket dir %q: %w", parent, err)
			}
		}
	}
	// A symlinked parent could redirect the real socket path under a protected root
	// (e.g. /tmp/x -> /run/user/1000) after the parse-time check passed; re-check the
	// symlink-resolved path and abort if it now lands in a protected location.
	if realParent, err := filepath.EvalSymlinks(parent); err == nil {
		realSocket := filepath.Clean(filepath.Join(realParent, filepath.Base(svc.socket)))
		if root := socketUnderProtectedRoot(realSocket); root != "" {
			return fmt.Errorf("native: inject-service socket %q resolves to %q inside protected host location %q", svc.socket, realSocket, root)
		}
	}
	// Clear any stale socket so the plugin can bind fresh — but only if it is in fact
	// a socket (fail-closed rather than clobber a planted file/dir/symlink).
	if err := removeStaleSocket(svc.socket); err != nil {
		return err
	}

	// Opaque config (svc.config): when supplied, write it verbatim to a 0600 file
	// (chowned to the dropped user when we spawn as them) and pass the file PATH via
	// env, so the config never appears in `ps`/cmdline on the `runuser -- env
	// KEY=VAL` path. The socket path also travels via env. leash never interprets the
	// config. When no config is supplied, no file is written.
	configFile, err := r.writeInjectConfig(svc)
	if err != nil {
		return err
	}
	injectEnv := []string{
		injectSocketEnv + "=" + svc.socket,
	}
	if configFile != "" {
		injectEnv = append(injectEnv, injectConfigFileEnv+"="+configFile)
	}

	// Run AS the invoking user, with that user's runtime env so the plugin can
	// reach the user's own session resources (root can't).
	argv := []string{pluginPath}
	var cmdEnv []string
	if user := r.workloadUser(); user != "" {
		argv = append([]string{"runuser", "-u", user, "--", "env"}, r.invokingUserEnv()...)
		argv = append(argv, injectEnv...)
		argv = append(argv, pluginPath)
	} else {
		cmdEnv = append(os.Environ(), r.invokingUserEnv()...)
		cmdEnv = append(cmdEnv, injectEnv...)
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	if cmdEnv != nil {
		cmd.Env = cmdEnv
	}
	if logf, err := os.Create(r.injectLogPath(svc)); err == nil {
		cmd.Stdout, cmd.Stderr = logf, logf
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("native: start inject-service plugin %q: %w", svc.plugin, err)
	}
	r.injectedPlugins = append(r.injectedPlugins, cmd)
	r.injectedCleanup = append(r.injectedCleanup, svc.socket)
	if configFile != "" {
		r.injectedCleanup = append(r.injectedCleanup, configFile)
	}
	// Fail-closed: wait for the plugin to create its socket; if it never does the
	// run aborts rather than launch the workload expecting a service it won't get.
	for i := 0; i < 100; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := os.Stat(svc.socket); err == nil {
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return fmt.Errorf("native: inject-service plugin %q socket %s did not appear (see %s)", svc.plugin, svc.socket, r.injectLogPath(svc))
}

// spawnInjectServicesContainer spawns every --inject-service plugin ONCE for the
// container backend (before the launch retry loop, so a port-conflict retry does
// not respawn them) and builds r.injectedDockerArgs: for each plugin, bind its
// socket's dir into the workload container at the identical path and set the
// workload env var to the in-container socket address. Fail-closed: any spawn
// failure aborts before the workload container is launched.
func (r *runner) spawnInjectServicesContainer(ctx context.Context) error {
	if err := r.checkInjectDuplicates("container"); err != nil {
		return err
	}
	for _, svc := range r.opts.injectServices {
		if err := r.spawnInjectService(ctx, svc); err != nil {
			return err
		}
		// Bind the socket's dir to the identical path in the container so the
		// in-container socket path == the host path the plugin bound.
		dir := filepath.Dir(svc.socket)
		r.injectedDockerArgs = append(r.injectedDockerArgs,
			"-v", dir+":"+dir,
			"-e", svc.env+"=unix:path="+svc.socket,
		)
	}
	return nil
}

// teardownInjectedPlugins stops every injected plugin and removes its socket/config
// files. Shared by the native and container launchers' Remove. Each plugin is
// signalled (SIGINT) for a clean teardown, then force-killed after a grace period
// so teardown can't hang.
func (r *runner) teardownInjectedPlugins() {
	for _, cmd := range r.injectedPlugins {
		if cmd == nil || cmd.Process == nil {
			continue
		}
		// Signal (not kill) so the plugin can tear down cleanly, but don't wait
		// forever: give it a grace period, then force-kill so teardown can't hang.
		_ = cmd.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func(c *exec.Cmd) {
			_ = c.Wait()
			close(done)
		}(cmd)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	}
	// Remove every injected socket / config file regardless of wait outcome.
	for _, sock := range r.injectedCleanup {
		_ = os.Remove(sock)
	}
}

// removeStaleSocket removes a leftover plugin socket so the plugin can bind fresh.
// It removes the path ONLY when it exists and is a socket; it refuses (errors) on
// any existing non-socket (regular file, dir, symlink) rather than clobber it, and
// treats a missing path as success.
func removeStaleSocket(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("native: stat inject-service socket %q: %w", path, err)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("native: refusing to remove %q: exists and is not a socket", path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("native: remove stale inject-service socket %q: %w", path, err)
	}
	return nil
}

// resolvePlugin locates a helper binary: an absolute path is used directly (when
// it exists and isn't a dir), otherwise alongside the running leash binary first
// (release layout ships them together), then on PATH.
func (r *runner) resolvePlugin(name string) (string, error) {
	if filepath.IsAbs(name) {
		if st, err := os.Stat(name); err == nil && !st.IsDir() {
			return name, nil
		}
	}
	if self, err := os.Executable(); err == nil {
		cand := filepath.Join(filepath.Dir(self), name)
		if st, err := os.Stat(cand); err == nil && !st.IsDir() {
			return cand, nil
		}
	}
	return exec.LookPath(name)
}

// invokingUserEnv is the invoking user's generic runtime context (XDG base dir),
// passed to injected plugins so a plugin can find the user's own session
// resources. leash forwards only XDG_RUNTIME_DIR and leaves any protocol-specific
// derivation (e.g. a session bus address) to the plugin, staying agnostic.
func (r *runner) invokingUserEnv() []string {
	var env []string
	if uid := r.workloadUID(); uid != "" {
		env = append(env, "XDG_RUNTIME_DIR=/run/user/"+uid)
	}
	return env
}

// injectBoxName is the per-run identity used to name an injected plugin's temp
// log/config files uniquely (target-container base + this leash PID). It matches
// nativeLauncher.netnsName() so native's file paths are unchanged, and works for
// the container backend too (which has no netns).
func (r *runner) injectBoxName() string {
	base := sanitizeNativeName(r.cfg.targetContainer)
	if base == "" {
		base = "session"
	}
	return fmt.Sprintf("leash-native-%s-%d", base, os.Getpid())
}

func (r *runner) injectLogPath(svc injectService) string {
	// leashd's own log dir (root-owned) rather than a predictable /tmp path an
	// attacker could pre-plant a symlink at to redirect this root-owned create.
	return filepath.Join(r.cfg.logDir, "inject-"+sanitizeNativeName(svc.plugin)+"-"+r.injectBoxName()+".log")
}

// writeInjectConfig writes the opaque config payload (svc.config) verbatim to a
// 0600 file whose PATH is handed to the plugin via injectConfigFileEnv, keeping the
// config out of `ps`/cmdline. The file is chowned to the dropped user when we spawn
// the plugin as them, so the plugin can read it. Returns the file path, or "" (no
// file written) when no config was supplied. leash never interprets the payload.
func (r *runner) writeInjectConfig(svc injectService) (string, error) {
	if svc.config == "" {
		return "", nil
	}
	// os.CreateTemp opens with a random name + O_EXCL, so a pre-planted symlink at a
	// predictable /tmp path can't redirect this root-owned write (0600 like before).
	f, err := os.CreateTemp("", "leash-native-injectcfg-"+sanitizeNativeName(svc.plugin)+"-*")
	if err != nil {
		return "", fmt.Errorf("native: create inject-service config: %w", err)
	}
	path := f.Name()
	if _, err := f.WriteString(svc.config); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return "", fmt.Errorf("native: write inject-service config: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("native: close inject-service config: %w", err)
	}
	if r.workloadUser() != "" {
		if uid, gid := r.workloadUIDGID(); uid >= 0 {
			if err := os.Chown(path, uid, gid); err != nil {
				_ = os.Remove(path)
				return "", fmt.Errorf("native: chown inject-service config %q: %w", path, err)
			}
		}
	}
	return path, nil
}

// leashdDied reports whether the reaped leashd process has already exited.
func (n nativeLauncher) leashdDied() bool {
	ch := n.r.leashdExited
	if ch == nil {
		return false
	}
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// leashdLogPath is where native tees leashd's stdout/stderr, off the workload's
// TTY. Truncated per run; tail it to watch enforcement/proxy activity.
func (n nativeLauncher) leashdLogPath() string {
	return filepath.Join("/tmp", "leash-native-leashd-"+n.netnsName()+".log")
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
	if n.r.opts.requireLSM {
		leashd = append(leashd, "--require-lsm")
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
		// Fast path: if leashd already exited it will never publish the marker, so
		// stop waiting now (fail-closed below decides the verdict).
		if n.leashdDied() {
			return n.notReady("native leashd exited before enforcement was ready")
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		time.Sleep(caCertWaitDelay)
	}
	return n.notReady(fmt.Sprintf("native enforcement was not confirmed ready after %s", time.Duration(caCertWaitAttempts)*caCertWaitDelay))
}

// notReady resolves an unconfirmed-enforcement situation: fail closed when the
// operator passed --require-lsm (refuse to run the workload unenforced), else
// preserve the historical behavior — warn and proceed (degrade to whatever
// enforcement did attach). The leashd log has the specifics either way.
func (n nativeLauncher) notReady(reason string) error {
	if n.r.opts.requireLSM {
		return fmt.Errorf("%s; refusing to run the workload unenforced (--require-lsm). See %s", reason, n.leashdLogPath())
	}
	n.r.logger.Printf("Warning: %s; the workload may run before Layer 1 is active. See %s", reason, n.leashdLogPath())
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
	n.r.teardownInjectedPlugins()
	if nativeLayer2Enabled && !n.useUserManager() {
		n.teardownEgress(ctx)
		_, _ = hostOutput(ctx, "ip", "netns", "del", n.netnsName())
		_ = os.Remove(n.userReadableCACert())
	}
	n.stopUnit(ctx, n.unitName())
}

func (n nativeLauncher) addNetns(ctx context.Context) error {
	// Clear same-named stale state from a crashed prior run whose PID we've
	// reused (best-effort). A live run can't share our name — PIDs are unique
	// among live processes — so deleting a colliding netns/egress here is safe.
	n.teardownEgress(ctx)
	_, _ = hostOutput(ctx, "ip", "netns", "del", n.netnsName())

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

// nativeEgressResolvers are the only DNS servers the workload netns may reach on
// :53 — both advertised via resolv.conf AND the sole :53 destinations the egress
// firewall permits (so the box can't query an arbitrary DNS server).
var nativeEgressResolvers = []string{"1.1.1.1", "8.8.8.8"}

// nativeEgressResolvConf is the resolv.conf bind-mounted into the workload's
// mount ns. Pop!_OS points /etc/resolv.conf at systemd-resolved's 127.0.0.53
// stub, which is meaningless inside the netns; use public resolvers reachable
// via the NAT. (TODO: optionally forward the host's real upstream for split-horizon/LAN DNS.)
var nativeEgressResolvConf = func() string {
	var b strings.Builder
	for _, r := range nativeEgressResolvers {
		b.WriteString("nameserver " + r + "\n")
	}
	return b.String()
}()

// egressNATRules returns the host netfilter rules (iptables args, sans the leading
// "iptables") that govern the box's egress. The FORWARD policy is DEFAULT-DENY:
// only DNS to the configured resolvers and the proxy's HTTP/S egress (:80/:443)
// are permitted; everything else out of the box is dropped. The workload's own
// :80/:443 are REDIRECTed to the in-netns MITM proxy before they reach FORWARD,
// so this cannot be used to bypass SNI filtering — it closes the non-proxied
// channels (SSH :22, arbitrary TCP, DNS to non-resolvers) a workload could
// otherwise tunnel out on. Order matters: ACCEPTs precede the trailing DROP.
func egressNATRules(e egressNet) [][]string {
	v := e.vethHost
	src := e.subnet + ".0/" + strconv.Itoa(e.prefix)
	rules := [][]string{
		{"-t", "nat", "-A", "POSTROUTING", "-s", src, "-j", "MASQUERADE"},
		// Return path for anything we allowed out.
		{"-A", "FORWARD", "-o", v, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
	}
	for _, dns := range nativeEgressResolvers {
		rules = append(rules,
			[]string{"-A", "FORWARD", "-i", v, "-p", "udp", "-d", dns, "--dport", "53", "-j", "ACCEPT"},
			[]string{"-A", "FORWARD", "-i", v, "-p", "tcp", "-d", dns, "--dport", "53", "-j", "ACCEPT"},
		)
	}
	rules = append(rules,
		// The in-netns proxy's own upstream HTTP/S (the workload's 80/443 are
		// REDIRECTed to it before FORWARD, so these only carry proxied traffic).
		[]string{"-A", "FORWARD", "-i", v, "-p", "tcp", "--dport", "80", "-j", "ACCEPT"},
		[]string{"-A", "FORWARD", "-i", v, "-p", "tcp", "--dport", "443", "-j", "ACCEPT"},
		// Default-deny: drop every other egress from the box.
		[]string{"-A", "FORWARD", "-i", v, "-j", "DROP"},
	)
	return rules
}

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
	}
	// NAT + the default-deny egress firewall (see egressNATRules).
	for _, r := range egressNATRules(e) {
		steps = append(steps, append([]string{"iptables"}, r...))
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
	// Delete each rule setupEgress added (-A → -D), best-effort.
	for _, r := range egressNATRules(e) {
		del := make([]string, len(r))
		copy(del, r)
		for i, a := range del {
			if a == "-A" {
				del[i] = "-D"
			}
		}
		_, _ = hostOutput(ctx, "iptables", del...)
	}
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

// ControlUIURL: under Layer 2 leashd runs inside the workload's netns, so the UI
// is reachable at the netns veth IP (not localhost); LSM-only runs in the host
// netns, so localhost is correct.
func (n nativeLauncher) ControlUIURL(cfg listen.Config) string {
	if cfg.Disable {
		return ""
	}
	if n.layer2Active() {
		return fmt.Sprintf("http://%s:%s/", n.egress().nsIP, cfg.Port)
	}
	return cfg.DisplayURL()
}

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
	// Harden (fresh PID/IPC ns + keyring/GUI socket masks) only when root — the
	// namespace/mount ops need privilege, and rootless is the degraded/unenforced
	// path anyway. Granular flags relax it for GUI/desktop workloads.
	h := hardenOpts{}
	if !n.useUserManager() {
		h = hardenOpts{
			enabled:         true,
			uid:             n.r.workloadUID(),
			shareIPC:        n.r.opts.shareIPC,
			allowDisplay:    n.r.opts.allowDisplay,
			allowDBus:       n.r.opts.allowDBus,
			allowNamespaces: n.r.opts.allowNamespaces,
			injectedEnv:     n.r.injectedEnv,
		}
	}
	// The leash binary re-execs itself as `--harden-exec` to seccomp the workload;
	// resolve its path now (empty disables hardening rather than failing the run).
	self, err := os.Executable()
	if err != nil {
		self = ""
	}
	inner := nativeWorkloadScript(cgroupPath, workdir, shellBin, cmd, n.r.workloadUser(), caCert, self, h)
	if n.layer2Active() {
		argv := n.layer2Wrap(inner) // nsenter --net + private mount ns (resolv bind)
		return exec.CommandContext(ctx, argv[0], argv[1:]...)
	}
	if h.enabled {
		// LSM-only but root: the masks need a private mount ns of their own.
		return exec.CommandContext(ctx, "unshare", "--mount", "--propagation", "private", "--", "sh", "-c", inner)
	}
	return exec.CommandContext(ctx, "sh", "-c", inner)
}

// workloadUID returns the invoking user's numeric uid ($SUDO_UID) for the
// keyring-dir mask, or "" if unavailable/non-numeric.
func (r *runner) workloadUID() string {
	u := strings.TrimSpace(os.Getenv("SUDO_UID"))
	if u == "" {
		return ""
	}
	for _, c := range u {
		if c < '0' || c > '9' {
			return ""
		}
	}
	return u
}

// workloadUIDGID returns the invoking user's numeric uid/gid ($SUDO_UID/$SUDO_GID)
// for chowning dirs/files the dropped-privilege plugin must own, or (-1, -1) when
// the uid is unavailable. The gid falls back to the uid when $SUDO_GID is unset.
func (r *runner) workloadUIDGID() (int, int) {
	u := r.workloadUID()
	if u == "" {
		return -1, -1
	}
	uid, err := strconv.Atoi(u)
	if err != nil {
		return -1, -1
	}
	gid := uid
	if g := strings.TrimSpace(os.Getenv("SUDO_GID")); g != "" {
		if v, err := strconv.Atoi(g); err == nil {
			gid = v
		}
	}
	return uid, gid
}

// workloadUser returns the non-root user the workload should run as, or "" to
// keep the current uid. The eBPF LSM enforces on the cgroup regardless of uid,
// so when leash runs as root (typical: `sudo leash`) the agent need not — and
// many agents refuse to (e.g. Claude Code blocks --dangerously-skip-permissions
// as root). We drop to the invoking user ($SUDO_USER); leash and leashd keep
// root only for enforcement. Non-root leash (rootless box) needs no drop.
func (r *runner) workloadUser() string {
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
// hardenOpts controls the workload's session isolation. Default (enabled, no
// opt-outs): fresh PID+IPC ns, keyring/GUI socket masks, and a scrubbed env.
// The allow*/share* flags relax it for GUI/desktop workloads — leash is
// agnostic, so a container-shaped default must be opt-out-able.
type hardenOpts struct {
	enabled         bool     // master (root only); false = rootless/unenforced, no isolation
	uid             string   // validated-numeric $SUDO_UID for the keyring-dir mask
	shareIPC        bool     // --share-ipc: no IPC ns (X MIT-SHM etc.)
	allowDisplay    bool     // --allow-display: keep DISPLAY/XAUTHORITY + the X11 socket
	allowDBus       bool     // --allow-dbus: keep DBUS_SESSION_BUS_ADDRESS + /run/user
	allowNamespaces bool     // --allow-namespaces: skip the seccomp mount/unshare block
	injectedEnv     []string // --inject-service: "VAR=value" pairs pointing the workload at each plugin socket
}

// hasEnvKey reports whether env (a slice of "KEY=VALUE" strings) sets key.
func hasEnvKey(env []string, key string) bool {
	for _, e := range env {
		if k, _, ok := strings.Cut(e, "="); ok && k == key {
			return true
		}
	}
	return false
}

func nativeWorkloadScript(cgroupPath, workdir, shellBin, cmd, dropUser, caCert, self string, h hardenOpts) string {
	procs := quoteShellArg(filepath.Join(cgroupPath, "cgroup.procs"))
	innerCmd := "exec " + cmd
	if caCert != "" {
		// Trust leash's L2 MITM CA across runtimes, not just Node: Go and
		// OpenSSL/curl read SSL_CERT_FILE, curl also CURL_CA_BUNDLE, Python-requests
		// REQUESTS_CA_BUNDLE, git GIT_SSL_CAINFO, Node NODE_EXTRA_CA_CERTS. In the
		// box all allowed egress is proxied through the MITM, so every cert is
		// signed by this CA. (Go binaries like agy failed x509 with Node-only.)
		q := quoteShellArg(caCert)
		innerCmd = "export NODE_EXTRA_CA_CERTS=" + q +
			" SSL_CERT_FILE=" + q +
			" CURL_CA_BUNDLE=" + q +
			" REQUESTS_CA_BUNDLE=" + q +
			" GIT_SSL_CAINFO=" + q + "; " + innerCmd
	}
	shellRun := fmt.Sprintf("%s -lc %s", quoteShellArg(shellBin), quoteShellArg(innerCmd))

	// Scrub the session env vars that leak the keyring/GUI location — unless the
	// matching allow flag keeps them.
	scrub := ""
	if h.enabled {
		var unset, set []string
		// Injected-service env (e.g. a plugin socket address) is set unconditionally
		// — this is how the workload reaches an --inject-service helper instead of
		// the real host service, whose /run/user socket stays masked.
		set = append(set, h.injectedEnv...)
		// Scrub the real session bus address unless --allow-dbus keeps it, or an
		// injected variable already overrides it.
		if !h.allowDBus && !hasEnvKey(h.injectedEnv, "DBUS_SESSION_BUS_ADDRESS") {
			unset = append(unset, "DBUS_SESSION_BUS_ADDRESS")
		}
		if !h.allowDisplay {
			unset = append(unset, "DISPLAY", "XAUTHORITY")
		}
		if len(unset) > 0 || len(set) > 0 {
			scrub = "env"
			for _, v := range unset {
				scrub += " -u " + v
			}
			for _, kv := range set {
				scrub += " " + quoteShellArg(kv)
			}
			scrub += " "
		}
	}

	// Seccomp-harden the workload just before it execs the agent: re-exec through
	// `leash --harden-exec`, which installs the mount/unshare-denying filter and
	// then execs onward. Placed INSIDE runuser (so it runs as the dropped user) but
	// AFTER leash's own `unshare --mount-proc` below — leash's namespace setup
	// completes first, then the filter blocks the agent from creating its own
	// user+mount namespace to bind-mount a denied path under an allowed prefix
	// (the path-LSM bypass). Inherited across exec → covers every subprocess.
	// --allow-namespaces opts out for workloads that legitimately need unshare/
	// mount (nested containers, sandbox tools) — at the cost of reopening the
	// bypass, so it is off by default.
	payload := scrub + shellRun
	if h.enabled && !h.allowNamespaces && self != "" {
		payload = quoteShellArg(self) + " --harden-exec -- " + scrub + shellRun
	}

	// Drop privileges (runuser), keeping the harden+scrub in the innermost exec.
	userRun := payload
	if dropUser != "" {
		userRun = "runuser -u " + quoteShellArg(dropUser) + " -- " + payload
	}

	// Fresh PID (+ IPC unless shared) namespaces with own /proc (--mount-proc), so
	// the workload can't read host processes' /proc (env/secrets) or share IPC.
	// Placed AFTER the cgroup write below, which must run in the host PID ns so the
	// pid resolves (the LSM is cgroup-scoped, unaffected by the PID ns).
	run := "exec " + userRun
	if h.enabled {
		ns := "--pid --fork --mount-proc"
		if !h.shareIPC {
			ns = "--ipc " + ns
		}
		run = "exec unshare " + ns + " -- " + userRun
	}

	// Mask the session sockets reachable via the filesystem (keyring/D-Bus, X11) —
	// unless the matching allow flag keeps them. Runs in the caller's PRIVATE mount
	// ns (layer2Wrap or the lsm-only `unshare --mount`), so the host's are untouched.
	masks := ""
	if h.enabled {
		if !h.allowDisplay {
			masks += "[ -d /tmp/.X11-unix ] && mount -t tmpfs -o mode=0755 tmpfs /tmp/.X11-unix 2>/dev/null || true; "
		}
		if !h.allowDBus && h.uid != "" { // uid is validated-numeric; safe to interpolate
			masks = fmt.Sprintf("mount -t tmpfs -o uid=%s,mode=0700 tmpfs /run/user/%s 2>/dev/null || true; ", h.uid, h.uid) + masks
		}
	}
	return fmt.Sprintf("%secho $$ > %s && cd %s && %s", masks, procs, quoteShellArg(workdir), run)
}

// hostOutput runs a host command (systemd-run/systemctl/ip), capturing combined
// output. Native uses host tooling directly, independent of the container
// Runtime command wrappers.
func hostOutput(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}
