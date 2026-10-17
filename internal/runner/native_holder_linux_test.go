//go:build linux

package runner

import (
	"context"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// The holder returns as soon as its owner is SIGKILLed (so systemd stops the
// box), and immediately when the recorded start time does not match (a PID
// reused before the holder started is not mistaken for the owner).
func TestNativeHolderExitsWhenOwnerKilled(t *testing.T) {
	owner := exec.Command("sleep", "300")
	if err := owner.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Process.Kill() })
	start, err := procStartTime(owner.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	pid := strconv.Itoa(owner.Process.Pid)

	if rc := NativeHolderMain([]string{pid, strconv.FormatUint(start+1, 10)}); rc != 0 {
		t.Fatalf("mismatched start: rc=%d", rc)
	}

	done := make(chan int, 1)
	go func() { done <- NativeHolderMain([]string{pid, strconv.FormatUint(start, 10)}) }()
	select {
	case <-done:
		t.Fatal("holder returned while its owner is alive")
	case <-time.After(300 * time.Millisecond):
	}
	_ = owner.Process.Signal(syscall.SIGKILL)
	_ = owner.Wait()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("holder did not exit after its owner was SIGKILLed")
	}
}

// TestNativeKill9FakeLeash is the re-exec'd "leash": it records its native box
// (as Provision does) and blocks until the parent SIGKILLs it.
func TestNativeKill9FakeLeash(t *testing.T) {
	dir := os.Getenv("LEASH_TEST_NATIVE_KILL9_DIR")
	if dir == "" {
		t.Skip("helper process for TestNativeKill9StaleBoxReapedOnNextRun")
	}
	nativeStateDirOverride = dir
	r := &runner{runtime: nativeRuntime{}, logger: log.New(io.Discard, "", 0)}
	r.cfg.targetContainer = "kill9"
	r.cfg.workDir = os.Getenv("LEASH_TEST_NATIVE_KILL9_WORK")
	r.cfg.workDirIsTemp = true
	n := nativeLauncher{r: r}
	n.recordBoxState()
	if err := os.WriteFile(filepath.Join(dir, "ready"), []byte(n.boxBaseName()), 0o600); err != nil {
		os.Exit(3)
	}
	time.Sleep(time.Hour)
}

// A SIGKILLed leash runs no teardown at all; the next run reaps its box — and
// never a box whose owner is still alive (#158).
func TestNativeKill9StaleBoxReapedOnNextRun(t *testing.T) {
	dir := t.TempDir()
	work := filepath.Join(t.TempDir(), "leash.kill9")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	fake := exec.Command(os.Args[0], "-test.run=^TestNativeKill9FakeLeash$")
	fake.Env = append(os.Environ(), "LEASH_TEST_NATIVE_KILL9_DIR="+dir, "LEASH_TEST_NATIVE_KILL9_WORK="+work)
	if err := fake.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fake.Process.Kill() })
	var name string
	for i := 0; i < 100; i++ {
		if b, err := os.ReadFile(filepath.Join(dir, "ready")); err == nil {
			name = string(b)
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if name == "" {
		t.Fatal("helper never recorded its box")
	}
	host := &fakeHost{}
	host.install(t)

	if got := reapStaleNativeBoxesIn(context.Background(), dir); len(got) != 0 {
		t.Fatalf("reaped a live owner's box: %v", got)
	}
	_ = fake.Process.Signal(syscall.SIGKILL)
	_ = fake.Wait()

	got := reapStaleNativeBoxesIn(context.Background(), dir)
	if len(got) != 1 || got[0] != name {
		t.Fatalf("reaped %v, want [%s]", got, name)
	}
	if os.Geteuid() == 0 && !host.has("ip netns del "+name) {
		t.Errorf("netns not removed: %v", host.calls)
	}
	if !host.has("stop --no-block " + name + ".service") {
		t.Errorf("holder unit not stopped: %v", host.calls)
	}
	if _, err := os.Stat(work); !os.IsNotExist(err) {
		t.Error("dead run's temp work dir not removed")
	}
	if _, err := os.Stat(nativeStatePath(dir, name)); !os.IsNotExist(err) {
		t.Error("dead run's record not removed")
	}
}
