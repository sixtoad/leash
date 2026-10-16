//go:build linux

package runner

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// TestLeashdPdeathsigFakeLeash is the re-exec'd "leash" process: it starts a
// fake leashd via startLeashd, records its PID and blocks until the parent test
// SIGKILLs it.
func TestLeashdPdeathsigFakeLeash(t *testing.T) {
	dir := os.Getenv("LEASH_TEST_LEASHD_PDEATHSIG_DIR")
	if dir == "" {
		t.Skip("helper process for TestNativeLeashdDiesWithLeash")
	}
	r := &runner{}
	cmd := exec.Command("sleep", "300")
	if err := r.startLeashd(cmd, nil); err != nil {
		os.Exit(2)
	}
	if err := os.WriteFile(filepath.Join(dir, "leashd.pid"), []byte(strconv.Itoa(cmd.Process.Pid)), 0o600); err != nil {
		os.Exit(3)
	}
	time.Sleep(time.Hour)
}

// If leash itself is SIGKILLed (no teardown runs at all), the parent-death
// signal must still take leashd — and with it the eBPF LSM — down (#143).
func TestNativeLeashdDiesWithLeash(t *testing.T) {
	dir := t.TempDir()
	fake := exec.Command(os.Args[0], "-test.run=^TestLeashdPdeathsigFakeLeash$")
	fake.Env = append(os.Environ(), "LEASH_TEST_LEASHD_PDEATHSIG_DIR="+dir)
	if err := fake.Start(); err != nil {
		t.Fatal(err)
	}
	leashd := readPID(t, filepath.Join(dir, "leashd.pid"))
	t.Cleanup(func() { _ = syscall.Kill(leashd, syscall.SIGKILL) })
	if !processAlive(leashd) {
		t.Fatal("fake leashd should be running")
	}
	_ = fake.Process.Signal(syscall.SIGKILL)
	_ = fake.Wait()
	assertProcessGone(t, "native leashd after leash SIGKILL", leashd)
}
