package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// A container run's target and leash sidecar are detached objects of the
// container engine: nothing ties them to the leash client that created them.
// A leash that is SIGKILLed (or dies any other way that skips its teardown)
// used to leave both running, with the workload going on unattended, plus the
// temp work dir (#201). Two mechanisms bind them to the client's lifetime:
//
//   - A watcher. Before the first container is created, leash starts a small
//     detached process (`leash --container-watch`, its own session, so a Ctrl-C
//     on the terminal does not reach it) holding the read end of a pipe whose
//     write end only leash holds. The pipe reads EOF the moment leash exits,
//     however it exits. Unless leash disarmed it first (its own teardown
//     finished, or the containers are deliberately kept), the watcher then
//     removes every container carrying this run's session label and the temp
//     work dir. Removing the target also removes its cgroup, which ends a
//     rootless run's enforcer-daemon session.
//
//   - Owner labels. Every container records its owner (PID, start time, boot
//     ID, machine ID, PID namespace) and, when leash created it, the temp work
//     dir. The next container run and `leash doctor --reap` remove the
//     containers of runs whose owner is provably gone, in case the watcher
//     itself was killed. A container whose owner cannot be judged (another
//     machine sharing the engine, another PID namespace) is never touched.

const (
	containerOwnerPIDLabel     = "dev.leash.owner-pid"
	containerOwnerStartLabel   = "dev.leash.owner-start"
	containerOwnerBootLabel    = "dev.leash.boot-id"
	containerOwnerMachineLabel = "dev.leash.machine-id"
	containerOwnerPidNSLabel   = "dev.leash.pid-ns"
	containerWorkDirLabel      = "dev.leash.work-dir"
	// containerRoleLabel is "leash" on the sidecar, "target" on the workload's
	// container. The sidecar joins the target's network namespace, and podman
	// refuses to remove a container another one depends on, so the sidecar is
	// always removed first.
	containerRoleLabel = "dev.leash.role"
)

// ownerIdentity identifies a leash process across PID reuse and reboots, and
// the machine/PID namespace in which its PID means something.
type ownerIdentity struct {
	PID     int
	Start   uint64
	BootID  string
	Machine string
	PidNS   string
}

// selfOwnerIdentity describes the running leash. Variable for tests.
var selfOwnerIdentity = func() ownerIdentity {
	start, _ := ownerProcStart(os.Getpid())
	return ownerIdentity{
		PID:     os.Getpid(),
		Start:   start,
		BootID:  ownerBootID(),
		Machine: ownerMachineID(),
		PidNS:   ownerPidNamespace(),
	}
}

// ownerProcessAlive reports whether pid is still the process that started at
// start. When the start time cannot be read (e.g. another user's process
// hidden by hidepid), only a definite "no such process" counts as dead.
// Variable for tests.
var ownerProcessAlive = func(pid int, start uint64) bool {
	if pid <= 0 {
		return false
	}
	if got, err := ownerProcStart(pid); err == nil {
		return start == 0 || got == start
	}
	return !errors.Is(syscall.Kill(pid, 0), syscall.ESRCH)
}

// ownerLabelArgs are the `--label` flags recording this run's owner on each
// container it creates.
func (r *runner) ownerLabelArgs(name string) []string {
	id := selfOwnerIdentity()
	role := "target"
	if name == r.cfg.leashContainer {
		role = "leash"
	}
	labels := []string{
		containerRoleLabel + "=" + role,
		containerOwnerPIDLabel + "=" + strconv.Itoa(id.PID),
		containerOwnerStartLabel + "=" + strconv.FormatUint(id.Start, 10),
		containerOwnerBootLabel + "=" + id.BootID,
		containerOwnerMachineLabel + "=" + id.Machine,
		containerOwnerPidNSLabel + "=" + id.PidNS,
	}
	if wd := r.reapableWorkDir(); wd != "" {
		labels = append(labels, containerWorkDirLabel+"="+wd)
	}
	args := make([]string, 0, 2*len(labels))
	for _, l := range labels {
		args = append(args, "--label", l)
	}
	return args
}

// reapableWorkDir is the work dir a reaper may remove: only a temp dir leash
// created itself, never a user-provided LEASH_WORK_DIR.
func (r *runner) reapableWorkDir() string {
	if !r.cfg.workDirIsTemp || !isLeashTempWorkDir(r.cfg.workDir) {
		return ""
	}
	return r.cfg.workDir
}

// isLeashTempWorkDir accepts only a per-run temp dir as createTempWorkDir makes
// it: "leash.<name>.<random>" directly under the system temp dir or the
// per-user run dir. A label is data from the engine; nothing else is removed.
func isLeashTempWorkDir(p string) bool {
	if !safeReapPath(p) || !strings.HasPrefix(filepath.Base(p), "leash.") {
		return false
	}
	parent := filepath.Dir(p)
	for _, base := range []string{os.TempDir(), "/tmp", defaultWorkDirBase()} {
		if base != "" && filepath.Clean(base) == parent {
			return true
		}
	}
	return false
}

// --- the watcher ---------------------------------------------------------

// containerWatchFlag is the internal subcommand that runs the watcher.
const containerWatchFlag = "--container-watch"

// containerWatchCommand builds the watcher command (args after the binary).
// Variable so tests re-exec the test binary instead.
var containerWatchCommand = func(args []string) (*exec.Cmd, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	return exec.Command(exe, append([]string{containerWatchFlag}, args...)...), nil
}

// startContainerWatcher starts the watcher for this run's containers. It is a
// variable so unit tests that drive launchContainer with fake runtimes do not
// spawn processes.
var startContainerWatcher = (*runner).startContainerWatch

// startContainerWatch starts the detached watcher (once per run). A watcher
// that cannot start is reported but does not stop the run: the owner labels
// still let the next run and `leash doctor --reap` clean up.
func (r *runner) startContainerWatch() {
	if r.containerWatchStarted {
		return
	}
	r.containerWatchStarted = true
	workDir := r.reapableWorkDir()
	if workDir == "" {
		workDir = "-"
	}
	cmd, err := containerWatchCommand([]string{r.rt().Name(), r.containerSession, workDir})
	if err == nil {
		err = r.spawnContainerWatch(cmd)
	}
	if err != nil {
		r.diagnosticf("Warning: could not start the container watcher (%v); if leash is killed, its containers are removed by the next run or `leash doctor --reap`.\n", err)
	}
}

func (r *runner) spawnContainerWatch(cmd *exec.Cmd) error {
	rd, wr, err := os.Pipe()
	if err != nil {
		return err
	}
	cmd.ExtraFiles = []*os.File{rd} // fd 3 in the watcher
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, nil, nil
	// Its own session: no controlling terminal, so neither a terminal Ctrl-C
	// (sent to leash's foreground process group) nor a hangup reaches it.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		rd.Close()
		wr.Close()
		return err
	}
	rd.Close() // leash keeps only the write end: its exit is the watcher's EOF
	go func() { _ = cmd.Wait() }()
	r.containerWatch = wr
	return nil
}

// disarmContainerWatch tells the watcher that leash's own teardown is done, or
// that the containers are kept on purpose: it exits without touching them.
func (r *runner) disarmContainerWatch() {
	if r.containerWatch == nil {
		return
	}
	_, _ = r.containerWatch.Write([]byte{'d'})
	_ = r.containerWatch.Close()
	r.containerWatch = nil
}

// containerWatchSweepWindow bounds how long the watcher keeps sweeping: a
// `run -d` the dead leash had in flight can still create its container after
// the first sweep. Variables for tests.
var (
	containerWatchSweepWindow   = 15 * time.Second
	containerWatchSweepInterval = time.Second
)

// ContainerWatchMain implements `leash --container-watch <runtime> <session>
// <work-dir|->` with the lifeline pipe on fd 3.
func ContainerWatchMain(args []string) int {
	if len(args) != 3 || !validContainerSession(args[1]) {
		fmt.Fprintln(os.Stderr, "usage: leash --container-watch <runtime> <session> <work-dir|->")
		return 2
	}
	rtName, session, workDir := args[0], args[1], args[2]
	if !isSupportedRuntime(rtName) {
		fmt.Fprintf(os.Stderr, "leash --container-watch: unsupported runtime %q\n", rtName)
		return 2
	}
	signal.Ignore(syscall.SIGINT, syscall.SIGHUP, syscall.SIGPIPE)
	lifeline := os.NewFile(3, "leash-lifeline")
	if lifeline == nil {
		return 2
	}
	return containerWatch(lifeline, cliRuntime{bin: rtName}, session, workDir)
}

// containerWatch blocks until the owner exits (EOF) or disarms (a byte), and
// on an armed EOF removes the session's containers and the temp work dir.
func containerWatch(lifeline *os.File, rt Runtime, session, workDir string) int {
	buf := make([]byte, 1)
	for {
		n, err := lifeline.Read(buf)
		if n > 0 {
			return 0 // disarmed
		}
		if err != nil {
			break // EOF: the owning leash is gone
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), containerWatchSweepWindow+15*time.Second)
	defer cancel()
	sweepContainerSession(ctx, rt, session)
	if workDir != "-" && isLeashTempWorkDir(workDir) {
		_ = os.RemoveAll(workDir)
	}
	return 0
}

// sweepContainerSession removes every container labelled with session, and
// keeps sweeping until two consecutive sweeps find nothing (or the window
// ends), so a create that was in flight when leash died is caught too.
func sweepContainerSession(ctx context.Context, rt Runtime, session string) {
	deadline := time.Now().Add(containerWatchSweepWindow)
	empty := 0
	filter := "label=" + containerSessionLabel + "=" + session
	for {
		if out, _ := rt.Output(ctx, "ps", "-a", "-q", "--filter", filter, "--filter", "label="+containerRoleLabel+"=leash"); strings.TrimSpace(out) != "" {
			_, _ = rt.Output(ctx, forceRemoveArgs(rt, strings.Fields(out))...)
		}
		out, err := rt.Output(ctx, "ps", "-a", "-q", "--filter", filter)
		ids := strings.Fields(out)
		if err == nil && len(ids) == 0 {
			empty++
		} else {
			empty = 0
		}
		if len(ids) > 0 {
			_, _ = rt.Output(ctx, forceRemoveArgs(rt, ids)...)
		}
		if empty >= 2 || !time.Now().Before(deadline) || ctx.Err() != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(containerWatchSweepInterval):
		}
	}
}

// forceRemoveArgs removes containers at once. The owner is gone, so there is
// no orderly stop to wait for: docker's `rm -f` kills immediately, podman's
// waits out the stop timeout (10s) unless told not to.
func forceRemoveArgs(rt Runtime, ids []string) []string {
	args := []string{"rm", "-f"}
	if rt.Name() == "podman" {
		args = append(args, "--time", "0")
	}
	return append(args, ids...)
}

func validContainerSession(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func isSupportedRuntime(name string) bool {
	for _, s := range supportedRuntimes {
		if s == name {
			return true
		}
	}
	return false
}

// --- kept containers -------------------------------------------------------

// containerStateDirOverride lets tests point the kept-run markers elsewhere.
var containerStateDirOverride string

// containerStateDir holds markers for runs whose containers were kept on
// purpose (an interactive exec failure keeps them for inspection), so the
// reapers leave them alone: /run/leash/container for root,
// $XDG_RUNTIME_DIR/leash/container otherwise, else ~/.leash/state/container.
func containerStateDir() string {
	if containerStateDirOverride != "" {
		return containerStateDirOverride
	}
	if os.Geteuid() == 0 && goos() == "linux" {
		return "/run/leash/container"
	}
	if xdg := strings.TrimSpace(os.Getenv("XDG_RUNTIME_DIR")); xdg != "" && filepath.IsAbs(xdg) {
		return filepath.Join(xdg, "leash", "container")
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".leash", "state", "container")
	}
	return ""
}

func keptMarkerPath(dir, engine, session string) string {
	return filepath.Join(dir, engine+"-"+session+".kept")
}

// pruneKeptMarkers removes the markers of kept runs whose containers are all
// gone from engine (the user removed them).
func pruneKeptMarkers(dir, engine string, live map[string]bool) {
	if dir == "" {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	prefix := engine + "-"
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".kept") {
			continue
		}
		session := strings.TrimSuffix(strings.TrimPrefix(name, prefix), ".kept")
		if validContainerSession(session) && !live[session] {
			_ = os.Remove(filepath.Join(dir, name))
		}
	}
}

// markContainersKept records that this run's containers are kept on purpose.
func (r *runner) markContainersKept() {
	dir := containerStateDir()
	if dir == "" || !validContainerSession(r.containerSession) {
		return
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	_ = os.WriteFile(keptMarkerPath(dir, r.rt().Name(), r.containerSession), []byte(strings.Join([]string{r.cfg.targetContainer, r.cfg.leashContainer}, "\n")+"\n"), 0o600)
}

// --- reaping stale runs ------------------------------------------------------

// staleContainerRun is one dead run's containers.
type staleContainerRun struct {
	Session string
	// Sidecars are the leash containers (removed first), IDs the rest.
	Sidecars []string
	IDs      []string
	Names    []string
	WorkDir  string
}

// labelledContainer is what the reaper reads back from the engine.
type labelledContainer struct {
	ID     string
	Name   string
	Labels map[string]string
}

// listOwnedContainers returns every container carrying leash owner labels.
func listOwnedContainers(ctx context.Context, rt Runtime) ([]labelledContainer, error) {
	out, err := rt.Output(ctx, "ps", "-a", "-q", "--no-trunc", "--filter", "label="+containerOwnerPIDLabel)
	if err != nil {
		return nil, err
	}
	ids := strings.Fields(out)
	if len(ids) == 0 {
		return nil, nil
	}
	out, err = rt.Output(ctx, append([]string{"inspect", "--format", "{{.Id}}\t{{.Name}}\t{{json .Config.Labels}}"}, ids...)...)
	if err != nil && strings.TrimSpace(out) == "" {
		return nil, err // a container removed in between fails inspect; keep the rest
	}
	var cs []labelledContainer
	for _, line := range strings.Split(out, "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), "\t", 3)
		if len(parts) != 3 {
			continue
		}
		var labels map[string]string
		if json.Unmarshal([]byte(parts[2]), &labels) != nil {
			continue
		}
		cs = append(cs, labelledContainer{ID: parts[0], Name: strings.TrimPrefix(parts[1], "/"), Labels: labels})
	}
	return cs, nil
}

// containerOwnerGone decides from a container's labels whether its owning
// leash is provably dead. Anything it cannot judge is "not gone".
func containerOwnerGone(labels map[string]string, self ownerIdentity) bool {
	if !validContainerSession(labels[containerSessionLabel]) {
		return false
	}
	machine := labels[containerOwnerMachineLabel]
	if machine == "" || self.Machine == "" || machine != self.Machine {
		return false // another machine sharing the engine (or unknown)
	}
	boot := labels[containerOwnerBootLabel]
	if boot == "" || self.BootID == "" {
		return false
	}
	if boot != self.BootID {
		return true // this machine rebooted since: the owner is gone
	}
	if labels[containerOwnerPidNSLabel] != self.PidNS {
		return false // its PID means nothing in our PID namespace
	}
	pid, err := strconv.Atoi(labels[containerOwnerPIDLabel])
	if err != nil || pid <= 0 {
		return false
	}
	start, err := strconv.ParseUint(labels[containerOwnerStartLabel], 10, 64)
	if err != nil {
		return false
	}
	return !ownerProcessAlive(pid, start)
}

// staleContainerRuns groups the engine's leash containers by run and returns
// the runs whose owner is gone and that were not kept on purpose.
func staleContainerRuns(ctx context.Context, rt Runtime) ([]staleContainerRun, error) {
	runs, _, err := staleContainerRunsWithSessions(ctx, rt)
	return runs, err
}

// staleContainerRunsWithSessions also returns every session the engine still
// has containers for.
func staleContainerRunsWithSessions(ctx context.Context, rt Runtime) ([]staleContainerRun, map[string]bool, error) {
	cs, err := listOwnedContainers(ctx, rt)
	if err != nil {
		return nil, nil, err
	}
	sessions := map[string]bool{}
	for _, c := range cs {
		sessions[c.Labels[containerSessionLabel]] = true
	}
	self := selfOwnerIdentity()
	keptDir := containerStateDir()
	runs := map[string]*staleContainerRun{}
	var order []string
	for _, c := range cs {
		session := c.Labels[containerSessionLabel]
		if !containerOwnerGone(c.Labels, self) {
			continue
		}
		if keptDir != "" {
			if _, err := os.Stat(keptMarkerPath(keptDir, rt.Name(), session)); err == nil {
				continue
			}
		}
		run := runs[session]
		if run == nil {
			run = &staleContainerRun{Session: session}
			runs[session] = run
			order = append(order, session)
		}
		if c.Labels[containerRoleLabel] == "leash" {
			run.Sidecars = append(run.Sidecars, c.ID)
		} else {
			run.IDs = append(run.IDs, c.ID)
		}
		run.Names = append(run.Names, c.Name)
		if wd := c.Labels[containerWorkDirLabel]; wd != "" && isLeashTempWorkDir(wd) {
			run.WorkDir = wd
		}
	}
	out := make([]staleContainerRun, 0, len(order))
	for _, s := range order {
		sort.Strings(runs[s].Names)
		out = append(out, *runs[s])
	}
	return out, sessions, nil
}

// reapStaleContainerRuns removes the containers (and temp work dirs) of runs
// whose owner is gone and returns the removed container names.
func reapStaleContainerRuns(ctx context.Context, rt Runtime) []string {
	runs, sessions, err := staleContainerRunsWithSessions(ctx, rt)
	if err != nil {
		return nil
	}
	pruneKeptMarkers(containerStateDir(), rt.Name(), sessions)
	var names []string
	for _, run := range runs {
		failed := false
		for _, ids := range [][]string{run.Sidecars, run.IDs} {
			if len(ids) == 0 {
				continue
			}
			if _, err := rt.Output(ctx, forceRemoveArgs(rt, ids)...); err != nil && !isNoSuchObjectError(err) {
				failed = true
			}
		}
		if failed {
			continue
		}
		if run.WorkDir != "" {
			_ = os.RemoveAll(run.WorkDir)
		}
		names = append(names, run.Names...)
	}
	return names
}

// reapStaleContainersOnStart is the next run's reaping, before it creates its
// own containers. Variable so unit tests with scripted runtimes skip it.
var reapStaleContainersOnStart = func(r *runner, ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if names := reapStaleContainerRuns(ctx, r.rt()); len(names) > 0 {
		r.diagnosticf("Removed containers left by a leash run that is gone: %s\n", strings.Join(names, ", "))
	}
}

// containerEnginesOnPath are the engines `leash doctor` inspects for stale runs.
func containerEnginesOnPath() []Runtime {
	var rts []Runtime
	for _, name := range supportedRuntimes {
		if _, err := exec.LookPath(name); err == nil {
			rts = append(rts, cliRuntime{bin: name})
		}
	}
	return rts
}

// StaleContainerRuns lists (engine: container names) the containers left by
// leash runs whose owner is gone, for `leash doctor`.
func StaleContainerRuns(ctx context.Context) []string {
	var out []string
	for _, rt := range containerEnginesOnPath() {
		cctx, cancel := context.WithTimeout(ctx, containerEngineProbeTimeout)
		runs, err := staleContainerRuns(cctx, rt)
		cancel()
		if err != nil {
			continue
		}
		for _, run := range runs {
			for _, n := range run.Names {
				out = append(out, rt.Name()+":"+n)
			}
		}
	}
	return out
}

// ReapStaleContainerRuns removes them (`leash doctor --reap`).
func ReapStaleContainerRuns(ctx context.Context) []string {
	var out []string
	for _, rt := range containerEnginesOnPath() {
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		names := reapStaleContainerRuns(cctx, rt)
		cancel()
		for _, n := range names {
			out = append(out, rt.Name()+":"+n)
		}
	}
	return out
}
