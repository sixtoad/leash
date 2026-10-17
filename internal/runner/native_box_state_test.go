package runner

import (
	"context"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeHost records the host commands native teardown/reap issue instead of
// touching systemd/iproute2/iptables.
type fakeHost struct {
	mu    sync.Mutex
	calls []string
	block chan struct{} // when non-nil every command blocks until closed or ctx done
}

func (f *fakeHost) install(t *testing.T) {
	t.Helper()
	orig := hostOutput
	hostOutput = func(ctx context.Context, name string, args ...string) (string, error) {
		f.mu.Lock()
		f.calls = append(f.calls, name+" "+strings.Join(args, " "))
		f.mu.Unlock()
		if f.block != nil {
			select {
			case <-f.block:
			case <-ctx.Done():
				return "", ctx.Err()
			}
		}
		return "", nil
	}
	t.Cleanup(func() { hostOutput = orig })
}

func (f *fakeHost) has(sub string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if strings.Contains(c, sub) {
			return true
		}
	}
	return false
}

// fakeProcs models /proc: pid -> start time, plus the boot ID.
func fakeProcs(t *testing.T, procs map[int]uint64, boot string) {
	t.Helper()
	origStart, origBoot := procStartTime, currentBootID
	procStartTime = func(pid int) (uint64, error) {
		if st, ok := procs[pid]; ok {
			return st, nil
		}
		return 0, os.ErrNotExist
	}
	currentBootID = func() string { return boot }
	t.Cleanup(func() { procStartTime, currentBootID = origStart, origBoot })
}

func useStateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	nativeStateDirOverride = dir
	t.Cleanup(func() { nativeStateDirOverride = "" })
	return dir
}

func mkRecord(t *testing.T, dir, name string, pid int, start uint64, boot string) (nativeBoxState, string) {
	t.Helper()
	work := filepath.Join(t.TempDir(), "leash.work")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	st := nativeBoxState{
		Name: name, Unit: name + ".service", Netns: name,
		OwnerPID: pid, OwnerStart: start, BootID: boot, WorkDir: work,
	}
	if err := writeNativeBoxState(dir, st); err != nil {
		t.Fatal(err)
	}
	return st, work
}

// Only boxes whose owner is provably gone are reaped: a dead PID, a reused PID
// (same number, different start time) and a previous boot are stale; a live
// owner with the recorded start time is never touched.
func TestReapStaleNativeBoxesOnlyDeadOwners(t *testing.T) {
	dir := useStateDir(t)
	fakeProcs(t, map[int]uint64{100: 5000, 200: 9999}, "boot-now")
	host := &fakeHost{}
	host.install(t)

	_, liveWork := mkRecord(t, dir, "leash-native-live-100", 100, 5000, "boot-now")
	_, deadWork := mkRecord(t, dir, "leash-native-dead-300", 300, 1, "boot-now")
	_, reusedWork := mkRecord(t, dir, "leash-native-reused-200", 200, 1234, "boot-now")
	_, rebootWork := mkRecord(t, dir, "leash-native-reboot-100", 100, 5000, "boot-old")

	reaped := reapStaleNativeBoxesIn(context.Background(), dir)
	got := strings.Join(reaped, ",")
	for _, want := range []string{"leash-native-dead-300", "leash-native-reused-200", "leash-native-reboot-100"} {
		if !strings.Contains(got, want) {
			t.Errorf("reaped %q, want it to include %s", got, want)
		}
	}
	if strings.Contains(got, "leash-native-live-100") {
		t.Fatalf("a live owner's box was reaped: %s", got)
	}
	if host.has("leash-native-live-100") {
		t.Fatalf("a host command touched the live box: %v", host.calls)
	}
	for _, want := range []string{"ip netns del leash-native-dead-300", "systemctl stop --no-block leash-native-dead-300.service"} {
		if !host.has(want) {
			t.Errorf("missing %q in %v", want, host.calls)
		}
	}
	for _, w := range []string{deadWork, reusedWork, rebootWork} {
		if _, err := os.Stat(w); !os.IsNotExist(err) {
			t.Errorf("stale work dir %s not removed", w)
		}
	}
	if _, err := os.Stat(liveWork); err != nil {
		t.Errorf("live work dir removed: %v", err)
	}
	if _, err := os.Stat(nativeStatePath(dir, "leash-native-live-100")); err != nil {
		t.Errorf("live record removed: %v", err)
	}
	if _, err := os.Stat(nativeStatePath(dir, "leash-native-dead-300")); !os.IsNotExist(err) {
		t.Errorf("dead record kept")
	}
}

// The ExecStopPost reaper is a no-op while the owner lives (normal teardown
// stops the unit itself) and reaps once it is dead.
func TestNativeReapBoxMainHonorsLiveOwner(t *testing.T) {
	dir := useStateDir(t)
	procs := map[int]uint64{100: 5000}
	fakeProcs(t, procs, "b")
	host := &fakeHost{}
	host.install(t)
	_, work := mkRecord(t, dir, "leash-native-x-100", 100, 5000, "b")

	if rc := NativeReapBoxMain([]string{"leash-native-x-100"}); rc != 0 {
		t.Fatalf("rc=%d", rc)
	}
	if len(host.calls) != 0 {
		t.Fatalf("reaped a live owner's box: %v", host.calls)
	}
	delete(procs, 100)
	_ = NativeReapBoxMain([]string{"leash-native-x-100"})
	if !host.has("ip netns del leash-native-x-100") {
		t.Fatalf("dead owner's netns not removed: %v", host.calls)
	}
	if _, err := os.Stat(work); !os.IsNotExist(err) {
		t.Fatal("dead owner's work dir not removed")
	}
	if rc := NativeReapBoxMain([]string{"../etc"}); rc != 2 {
		t.Fatalf("invalid box name accepted (rc=%d)", rc)
	}
}

func TestSafeReapPath(t *testing.T) {
	for p, want := range map[string]bool{
		"": false, "/": false, "/tmp": false, "tmp/x": false, "/tmp/../etc": false,
		"/tmp/leash.abc": true, "/tmp/leash-native-leashd-x.log": true,
	} {
		if got := safeReapPath(p); got != want {
			t.Errorf("safeReapPath(%q)=%v want %v", p, got, want)
		}
	}
}

func nativeTestRunner(t *testing.T) *runner {
	t.Helper()
	r := &runner{runtime: nativeRuntime{}, logger: log.New(io.Discard, "", 0)}
	r.cfg.targetContainer = "forced"
	r.cfg.workDir = filepath.Join(t.TempDir(), "leash.forced")
	r.cfg.workDirIsTemp = true
	if err := os.MkdirAll(r.cfg.workDir, 0o755); err != nil {
		t.Fatal(err)
	}
	return r
}

// The forced-exit path (second Ctrl-C -> os.Exit) removes the netns, stops the
// holder, removes the temp work dir and the box record (#158).
func TestNativeForcedExitCleanupRemovesBox(t *testing.T) {
	dir := useStateDir(t)
	fakeProcs(t, map[int]uint64{os.Getpid(): 42}, "b")
	host := &fakeHost{}
	host.install(t)
	r := nativeTestRunner(t)
	n := nativeLauncher{r: r}
	n.recordBoxState()
	if _, err := os.Stat(nativeStatePath(dir, n.boxBaseName())); err != nil {
		t.Fatalf("record not written: %v", err)
	}

	r.forcedExitCleanup()

	if n.useUserManager() {
		if !host.has("systemctl --user stop --no-block " + n.unitName()) {
			t.Errorf("holder not stopped: %v", host.calls)
		}
	} else {
		for _, want := range []string{"ip netns del " + n.netnsName(), "systemctl stop --no-block " + n.unitName()} {
			if !host.has(want) {
				t.Errorf("missing %q in %v", want, host.calls)
			}
		}
	}
	if _, err := os.Stat(r.cfg.workDir); !os.IsNotExist(err) {
		t.Error("temp work dir not removed on forced exit")
	}
	if _, err := os.Stat(nativeStatePath(dir, n.boxBaseName())); !os.IsNotExist(err) {
		t.Error("box record not removed on forced exit")
	}
}

// A wedged host tool cannot hold the forced exit hostage.
func TestNativeForcedExitCleanupIsBounded(t *testing.T) {
	useStateDir(t)
	host := &fakeHost{block: make(chan struct{})}
	host.install(t)
	defer close(host.block)
	orig := forcedExitBudget
	forcedExitBudget = 200 * time.Millisecond
	t.Cleanup(func() { forcedExitBudget = orig })

	r := nativeTestRunner(t)
	start := time.Now()
	done := r.boundedForcedExitCleanup()
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("forced-exit cleanup took %s; must be bounded by its budget", d)
	}
	// The abandoned teardown's context is canceled once the budget runs out,
	// so the wedged host tool returns and it winds down; join it so it cannot
	// outlive this test's stubs (in production os.Exit follows instead).
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("forced-exit teardown did not wind down after its budget expired")
	}
}

// The holder unit is bound to this leash (not `sleep infinity`), kills what is
// left in the box at once, and reaps through an ExecStopPost in its own unit.
func TestNativeHolderUnitArgs(t *testing.T) {
	fakeProcs(t, map[int]uint64{os.Getpid(): 77}, "b")
	n := nativeLauncher{r: nativeTestRunner(t)}
	args := strings.Join(n.holderUnitArgs(n.unitName()), " ")
	for _, want := range []string{
		"--collect", "--property=Delegate=yes", "--property=KillMode=control-group", "--property=KillSignal=SIGKILL",
		"--native-holder " + strconv.Itoa(os.Getpid()) + " 77",
		"--unit=" + n.unitName(),
	} {
		if !strings.Contains(args, want) {
			t.Errorf("holder args %q missing %q", args, want)
		}
	}
	if strings.Contains(args, "sleep infinity") {
		t.Errorf("holder still sleep infinity: %s", args)
	}
	if post := n.reapExecStopPost("/usr/bin/leash", nil); post != "" {
		if !strings.HasPrefix(post, "-") || !strings.Contains(post, "--native-reap-box "+n.boxBaseName()) || !strings.Contains(post, "--unit="+n.boxBaseName()+"-reap") {
			t.Errorf("ExecStopPost %q", post)
		}
	}
}
