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

// TestInjectPdeathsigFakeLeash is the re-exec'd "leash" process: it spawns an
// inject helper via startInjectedProc, records the helper's PID and blocks until
// the parent test SIGKILLs it.
func TestInjectPdeathsigFakeLeash(t *testing.T) {
	dir := os.Getenv("LEASH_TEST_PDEATHSIG_DIR")
	if dir == "" {
		t.Skip("helper process for TestInjectedHelperDiesWithLeash")
	}
	cmd := exec.Command("sleep", "300")
	p, err := startInjectedProc("sleep", cmd, nil)
	if err != nil {
		os.Exit(2)
	}
	if err := os.WriteFile(filepath.Join(dir, "helper.pid"), []byte(strconv.Itoa(p.cmd.Process.Pid)), 0o600); err != nil {
		os.Exit(3)
	}
	time.Sleep(time.Hour)
}

// If leash itself is SIGKILLed (no teardown runs), Pdeathsig must still take
// the helper down.
func TestInjectedHelperDiesWithLeash(t *testing.T) {
	dir := t.TempDir()
	fake := exec.Command(os.Args[0], "-test.run=^TestInjectPdeathsigFakeLeash$")
	fake.Env = append(os.Environ(), "LEASH_TEST_PDEATHSIG_DIR="+dir)
	if err := fake.Start(); err != nil {
		t.Fatal(err)
	}
	helper := readPID(t, filepath.Join(dir, "helper.pid"))
	t.Cleanup(func() { _ = syscall.Kill(helper, syscall.SIGKILL) })
	if !processAlive(helper) {
		t.Fatal("helper should be running")
	}
	_ = fake.Process.Signal(syscall.SIGKILL)
	_ = fake.Wait()
	assertProcessGone(t, "inject helper after leash SIGKILL", helper)
}
