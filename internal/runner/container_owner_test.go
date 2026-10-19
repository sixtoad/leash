package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Unit tests drive launchContainer and startContainers with scripted runtimes:
// they must neither spawn the watcher nor sweep the engine for stale runs. The
// tests below that exercise those paths restore the real implementations.
var (
	realStartContainerWatcher      = startContainerWatcher
	realReapStaleContainersOnStart = reapStaleContainersOnStart
)

func init() {
	startContainerWatcher = func(*runner) {}
	reapStaleContainersOnStart = func(*runner, context.Context) {}
}

const testSession = "0123456789abcdef0123456789abcdef"

func testOwnerLabels(self ownerIdentity, pid int, start uint64) map[string]string {
	return map[string]string{
		containerSessionLabel:      testSession,
		containerOwnerPIDLabel:     strconv.Itoa(pid),
		containerOwnerStartLabel:   strconv.FormatUint(start, 10),
		containerOwnerBootLabel:    self.BootID,
		containerOwnerMachineLabel: self.Machine,
		containerOwnerPidNSLabel:   self.PidNS,
	}
}

// Only a provably dead owner on this machine and in this PID namespace makes a
// container stale; anything that cannot be judged is left alone.
func TestContainerOwnerGone(t *testing.T) {
	origAlive := ownerProcessAlive
	t.Cleanup(func() { ownerProcessAlive = origAlive })
	ownerProcessAlive = func(pid int, start uint64) bool { return pid == 100 && start == 7 }
	self := ownerIdentity{PID: 1, Start: 1, BootID: "boot-a", Machine: "m1", PidNS: "pid:[1]"}

	with := func(mod func(map[string]string)) map[string]string {
		l := testOwnerLabels(self, 100, 7)
		mod(l)
		return l
	}
	cases := []struct {
		name   string
		labels map[string]string
		gone   bool
	}{
		{"live owner", with(func(map[string]string) {}), false},
		{"dead pid", with(func(l map[string]string) { l[containerOwnerPIDLabel] = "200" }), true},
		{"reused pid", with(func(l map[string]string) { l[containerOwnerStartLabel] = "8" }), true},
		{"rebooted", with(func(l map[string]string) { l[containerOwnerBootLabel] = "boot-b" }), true},
		{"other machine", with(func(l map[string]string) { l[containerOwnerMachineLabel] = "m2"; l[containerOwnerPIDLabel] = "200" }), false},
		{"other pid namespace", with(func(l map[string]string) { l[containerOwnerPidNSLabel] = "pid:[2]"; l[containerOwnerPIDLabel] = "200" }), false},
		{"no session", with(func(l map[string]string) { delete(l, containerSessionLabel); l[containerOwnerPIDLabel] = "200" }), false},
		{"bad pid", with(func(l map[string]string) { l[containerOwnerPIDLabel] = "x" }), false},
		{"no machine", with(func(l map[string]string) { l[containerOwnerMachineLabel] = ""; l[containerOwnerPIDLabel] = "200" }), false},
	}
	for _, tc := range cases {
		if got := containerOwnerGone(tc.labels, self); got != tc.gone {
			t.Errorf("%s: gone=%v, want %v", tc.name, got, tc.gone)
		}
	}
}

// The real liveness check: this process is alive, a reaped child is not, and
// a wrong start time means a reused PID.
func TestOwnerProcessAliveReal(t *testing.T) {
	self := selfOwnerIdentity()
	if !ownerProcessAlive(self.PID, self.Start) {
		t.Fatal("this process reported dead")
	}
	if self.Start != 0 && ownerProcessAlive(self.PID, self.Start+1) {
		t.Fatal("start-time mismatch reported alive")
	}
	cmd := exec.Command("true")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	if ownerProcessAlive(cmd.Process.Pid, 0) {
		t.Fatal("reaped child reported alive")
	}
	if self.BootID == "" || self.Machine == "" || self.PidNS == "" {
		t.Fatalf("incomplete identity %+v", self)
	}
}

// scriptedEngine is a Go fake of the engine's ps/inspect/rm for the reaper.
type scriptedEngine struct {
	mu         sync.Mutex
	containers []labelledContainer
	removed    []string
}

func (e *scriptedEngine) Run(ctx context.Context, args ...string) error {
	_, err := e.Output(ctx, args...)
	return err
}

func (e *scriptedEngine) Output(ctx context.Context, args ...string) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	switch args[0] {
	case "ps":
		var ids []string
		for _, c := range e.containers {
			ids = append(ids, c.ID)
		}
		return strings.Join(ids, "\n"), nil
	case "inspect":
		var lines []string
		for _, id := range args[3:] {
			for _, c := range e.containers {
				if c.ID == id {
					b, _ := json.Marshal(c.Labels)
					lines = append(lines, c.ID+"\t/"+c.Name+"\t"+string(b))
				}
			}
		}
		return strings.Join(lines, "\n"), nil
	case "rm":
		for _, id := range args[2:] {
			e.removed = append(e.removed, id)
			for i, c := range e.containers {
				if c.ID == id {
					e.containers = append(e.containers[:i], e.containers[i+1:]...)
					break
				}
			}
		}
		return "", nil
	}
	return "", fmt.Errorf("unexpected %v", args)
}

func (e *scriptedEngine) ExecWithInput(context.Context, string, string, io.Reader) error { return nil }
func (e *scriptedEngine) Cmd(ctx context.Context, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, "true")
}
func (e *scriptedEngine) Name() string { return "docker" }

// The next run (and doctor --reap) removes a dead run's containers and its
// temp work dir; a live run, a kept run and another machine's run stay.
func TestReapStaleContainerRuns(t *testing.T) {
	origAlive, origSelf, origDir := ownerProcessAlive, selfOwnerIdentity, containerStateDirOverride
	t.Cleanup(func() { ownerProcessAlive, selfOwnerIdentity, containerStateDirOverride = origAlive, origSelf, origDir })
	self := ownerIdentity{PID: 1, Start: 1, BootID: "boot-a", Machine: "m1", PidNS: "pid:[1]"}
	selfOwnerIdentity = func() ownerIdentity { return self }
	ownerProcessAlive = func(pid int, start uint64) bool { return pid == 100 }
	containerStateDirOverride = t.TempDir()

	deadWork, err := os.MkdirTemp("", "leash.reaptest.")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(deadWork) })
	userWork := t.TempDir() // not a leash temp dir: never removed

	label := func(session string, pid int, mod func(map[string]string)) map[string]string {
		l := testOwnerLabels(self, pid, 5)
		l[containerSessionLabel] = session
		if mod != nil {
			mod(l)
		}
		return l
	}
	dead := strings.Repeat("a", 32)
	live := strings.Repeat("b", 32)
	kept := strings.Repeat("c", 32)
	other := strings.Repeat("d", 32)
	user := strings.Repeat("e", 32)
	gone := strings.Repeat("f", 32) // a kept run whose containers were removed
	eng := &scriptedEngine{containers: []labelledContainer{
		{ID: "t1", Name: "agent", Labels: label(dead, 200, func(l map[string]string) { l[containerWorkDirLabel] = deadWork })},
		{ID: "l1", Name: "agent-leash", Labels: label(dead, 200, func(l map[string]string) { l[containerRoleLabel] = "leash" })},
		{ID: "t2", Name: "live", Labels: label(live, 100, nil)},
		{ID: "t3", Name: "kept", Labels: label(kept, 201, nil)},
		{ID: "t4", Name: "remote", Labels: label(other, 202, func(l map[string]string) { l[containerOwnerMachineLabel] = "m2" })},
		{ID: "t5", Name: "userwd", Labels: label(user, 203, func(l map[string]string) { l[containerWorkDirLabel] = userWork })},
	}}
	for _, s := range []string{kept, gone} {
		if err := os.WriteFile(keptMarkerPath(containerStateDirOverride, "docker", s), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	runs, err := staleContainerRuns(context.Background(), eng)
	if err != nil || len(runs) != 2 || runs[0].Session != dead || strings.Join(runs[0].Names, ",") != "agent,agent-leash" {
		t.Fatalf("stale runs = %+v, %v", runs, err)
	}
	names := reapStaleContainerRuns(context.Background(), eng)
	if strings.Join(names, ",") != "agent,agent-leash,userwd" {
		t.Fatalf("reaped %v", names)
	}
	if strings.Join(eng.removed, ",") != "l1,t1,t5" { // sidecar first
		t.Fatalf("removed ids %v", eng.removed)
	}
	if _, err := os.Stat(deadWork); !os.IsNotExist(err) {
		t.Fatal("dead run's temp work dir not removed")
	}
	if _, err := os.Stat(userWork); err != nil {
		t.Fatal("a work dir that is not a leash temp dir was removed")
	}
	if _, err := os.Stat(keptMarkerPath(containerStateDirOverride, "docker", kept)); err != nil {
		t.Fatal("marker of a kept run that still has containers was pruned")
	}
	if _, err := os.Stat(keptMarkerPath(containerStateDirOverride, "docker", gone)); !os.IsNotExist(err) {
		t.Fatal("marker of a kept run without containers not pruned")
	}
}

// Every container a run creates carries its session and owner labels.
func TestLaunchContainerLabelsOwner(t *testing.T) {
	var mu sync.Mutex
	var runs []string
	r := &runner{runtime: runRecorder{mu: &mu, runs: &runs}, logger: log.New(io.Discard, "", 0), verbose: true}
	r.cfg.workDir = filepath.Join(os.TempDir(), "leash.labels.x")
	r.cfg.workDirIsTemp = true
	if err := r.launchContainer(context.Background(), "agent", "run", "-d", "--name", "agent", "img"); err != nil {
		t.Fatal(err)
	}
	self := selfOwnerIdentity()
	for _, want := range []string{
		"--label " + containerSessionLabel + "=" + r.containerSession,
		"--label " + containerOwnerPIDLabel + "=" + strconv.Itoa(self.PID),
		"--label " + containerOwnerStartLabel + "=" + strconv.FormatUint(self.Start, 10),
		"--label " + containerOwnerBootLabel + "=" + self.BootID,
		"--label " + containerWorkDirLabel + "=" + r.cfg.workDir,
		"--label " + containerRoleLabel + "=target",
	} {
		if len(runs) != 1 || !strings.Contains(runs[0], want) {
			t.Fatalf("runs=%v, missing %q", runs, want)
		}
	}
	if !strings.HasPrefix(runs[0], "run --label") || !strings.HasSuffix(runs[0], "-d --name agent img") {
		t.Fatalf("labels not inserted after the verb: %q", runs[0])
	}
}

// finishLifecycle disarms the watcher after a complete teardown, and on the
// keep path records the run as kept so no reaper removes its containers.
func TestFinishLifecycleDisarmsWatcher(t *testing.T) {
	origDir := containerStateDirOverride
	t.Cleanup(func() { containerStateDirOverride = origDir })
	containerStateDirOverride = t.TempDir()

	for _, keep := range []bool{false, true} {
		var mu sync.Mutex
		var runs []string
		r := &runner{runtime: runRecorder{mu: &mu, runs: &runs}, logger: log.New(io.Discard, "", 0)}
		r.containerSession = testSession
		r.keepContainers = keep
		rd, wr, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		r.containerWatch = wr
		_ = r.finishLifecycle(context.Background(), 0, nil)
		buf := make([]byte, 2)
		n, _ := io.ReadFull(rd, buf[:1])
		rd.Close()
		if n != 1 || r.containerWatch != nil {
			t.Fatalf("keep=%v: watcher not disarmed (n=%d)", keep, n)
		}
		_, err = os.Stat(keptMarkerPath(containerStateDirOverride, "docker", testSession))
		if keep != (err == nil) {
			t.Fatalf("keep=%v: kept marker present=%v", keep, err == nil)
		}
	}
}

// fakeEngineScript is a docker-compatible CLI good enough for the watcher:
// `run --name N` records N, `ps` lists them, `rm -f ids` drops them.
const fakeEngineScript = `#!/bin/sh
d="$FAKE_ENGINE_DIR"
echo "$*" >> "$d/log"
case "$1" in
run)
  prev=""; name=""
  for a in "$@"; do [ "$prev" = "--name" ] && name="$a"; prev="$a"; done
  echo "$name" >> "$d/containers"; echo "$name";;
ps)
  [ -f "$d/containers" ] || exit 0
  case "$*" in *dev.leash.role=leash*) grep -- '-leash$' "$d/containers"; exit 0;; esac
  cat "$d/containers"; exit 0;;
rm)
  shift; [ "$1" = "-f" ] && shift
  for id in "$@"; do grep -vx "$id" "$d/containers" > "$d/c.tmp"; mv "$d/c.tmp" "$d/containers"; done;;
esac
exit 0
`

// TestContainerWatchHelper is the re-exec'd watcher (`leash --container-watch`).
func TestContainerWatchHelper(t *testing.T) {
	args := os.Getenv("LEASH_TEST_CONTAINER_WATCH_ARGS")
	if args == "" {
		t.Skip("helper process for TestContainerKill9")
	}
	containerWatchSweepInterval = 100 * time.Millisecond
	parts := strings.Split(args, "\x1f")
	lifeline := os.NewFile(3, "lifeline")
	os.Exit(containerWatch(lifeline, cliRuntime{bin: parts[0]}, parts[1], parts[2]))
}

// TestContainerKill9FakeLeash is the re-exec'd "leash": it starts the real
// watcher and launches two containers through the fake engine, then blocks
// until the parent SIGKILLs it.
func TestContainerKill9FakeLeash(t *testing.T) {
	dir := os.Getenv("FAKE_ENGINE_DIR")
	if dir == "" || os.Getenv("LEASH_TEST_CONTAINER_WATCH_ARGS") != "" {
		t.Skip("helper process for TestContainerKill9")
	}
	startContainerWatcher = realStartContainerWatcher
	containerWatchCommand = func(args []string) (*exec.Cmd, error) {
		cmd := exec.Command(os.Args[0], "-test.run=^TestContainerWatchHelper$")
		cmd.Env = append(os.Environ(), "LEASH_TEST_CONTAINER_WATCH_ARGS="+strings.Join(args, "\x1f"))
		return cmd, nil
	}
	r := &runner{runtime: cliRuntime{bin: filepath.Join(dir, "engine")}, logger: log.New(io.Discard, "", 0)}
	r.cfg.workDir = os.Getenv("LEASH_TEST_KILL9_WORK")
	r.cfg.workDirIsTemp = true
	for _, name := range []string{"agent", "agent-leash"} {
		if err := r.launchContainer(context.Background(), name, "run", "-d", "--name", name, "img"); err != nil {
			os.Exit(3)
		}
	}
	if os.Getenv("LEASH_TEST_KILL9_DISARM") == "1" {
		r.disarmContainerWatch()
	}
	if err := os.WriteFile(filepath.Join(dir, "ready"), nil, 0o600); err != nil {
		os.Exit(3)
	}
	time.Sleep(time.Hour)
}

// A SIGKILLed leash runs no teardown at all: its watcher removes both
// containers and the temp work dir within seconds — and does nothing while
// leash lives or once leash disarmed it (#201).
func TestContainerKill9(t *testing.T) {
	for _, disarm := range []bool{false, true} {
		t.Run(fmt.Sprintf("disarm=%v", disarm), func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "engine"), []byte(fakeEngineScript), 0o755); err != nil {
				t.Fatal(err)
			}
			work, err := os.MkdirTemp("", "leash.kill9.")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(work) })
			containers := func() string {
				data, _ := os.ReadFile(filepath.Join(dir, "containers"))
				return strings.TrimSpace(string(data))
			}

			helper := exec.Command(os.Args[0], "-test.run=^TestContainerKill9FakeLeash$")
			helper.Env = append(os.Environ(), "FAKE_ENGINE_DIR="+dir, "LEASH_TEST_KILL9_WORK="+work)
			if disarm {
				helper.Env = append(helper.Env, "LEASH_TEST_KILL9_DISARM=1")
			}
			if err := helper.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = helper.Process.Kill(); _ = helper.Wait() })
			deadline := time.Now().Add(20 * time.Second)
			for {
				if _, err := os.Stat(filepath.Join(dir, "ready")); err == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("fake leash never became ready")
				}
				time.Sleep(20 * time.Millisecond)
			}
			if got := containers(); got != "agent\nagent-leash" {
				t.Fatalf("containers=%q", got)
			}
			time.Sleep(300 * time.Millisecond)
			if got := containers(); got != "agent\nagent-leash" {
				t.Fatalf("watcher removed containers while leash lives: %q", got)
			}

			_ = helper.Process.Signal(syscall.SIGKILL)
			_ = helper.Wait()
			if disarm {
				time.Sleep(time.Second)
				if got := containers(); got != "agent\nagent-leash" {
					t.Fatalf("disarmed watcher removed containers: %q", got)
				}
				if _, err := os.Stat(work); err != nil {
					t.Fatal("disarmed watcher removed the work dir")
				}
				return
			}
			deadline = time.Now().Add(5 * time.Second)
			for containers() != "" || exists(work) {
				if time.Now().After(deadline) {
					log, _ := os.ReadFile(filepath.Join(dir, "log"))
					t.Fatalf("after SIGKILL: containers=%q work dir exists=%v\nengine log:\n%s", containers(), exists(work), log)
				}
				time.Sleep(50 * time.Millisecond)
			}
			engineLog, _ := os.ReadFile(filepath.Join(dir, "log"))
			for _, line := range strings.Split(string(engineLog), "\n") {
				if strings.HasPrefix(line, "rm ") {
					if line != "rm -f agent-leash" {
						t.Fatalf("first removal %q, want the sidecar alone first", line)
					}
					break
				}
			}
		})
	}
}

// The next run's reaping really runs from startContainers' seam with the
// configured runtime.
func TestReapStaleContainersOnStartUsesRuntime(t *testing.T) {
	origAlive, origSelf := ownerProcessAlive, selfOwnerIdentity
	t.Cleanup(func() { ownerProcessAlive, selfOwnerIdentity = origAlive, origSelf })
	self := ownerIdentity{PID: 1, Start: 1, BootID: "b", Machine: "m", PidNS: "p"}
	selfOwnerIdentity = func() ownerIdentity { return self }
	ownerProcessAlive = func(int, uint64) bool { return false }
	eng := &scriptedEngine{containers: []labelledContainer{{ID: "x", Name: "old", Labels: testOwnerLabels(self, 9, 9)}}}
	r := &runner{runtime: eng, logger: log.New(io.Discard, "", 0), diagnostics: io.Discard}
	realReapStaleContainersOnStart(r, context.Background())
	if strings.Join(eng.removed, ",") != "x" {
		t.Fatalf("removed %v", eng.removed)
	}
}

// podman's `rm -f` waits out the stop timeout; a dead run's containers are
// killed at once on both engines.
func TestForceRemoveArgs(t *testing.T) {
	if got := strings.Join(forceRemoveArgs(cliRuntime{bin: "docker"}, []string{"a", "b"}), " "); got != "rm -f a b" {
		t.Fatalf("docker: %q", got)
	}
	if got := strings.Join(forceRemoveArgs(cliRuntime{bin: "podman"}, []string{"a"}), " "); got != "rm -f --time 0 a" {
		t.Fatalf("podman: %q", got)
	}
}
