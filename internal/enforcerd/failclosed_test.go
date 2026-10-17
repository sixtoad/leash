//go:build unix

package enforcerd

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/strongdm/leash/internal/lsm"
)

// An update the worker's LSM manager rolled back is reported without
// touching the workload; one that failed closed stops the workload, and the
// answer says so (leashd then fails closed too).
func TestUpdateFailureStopsWorkloadOnlyWhenFailedClosed(t *testing.T) {
	var killed []string
	kill := func(p string) error { killed = append(killed, p); return nil }

	m := updateFailure(&lsm.KernelApplyError{Module: "connect", Err: errors.New("map write")}, "/cg", kill)
	if m.OK || !strings.Contains(m.Error, "connect LSM") || !strings.Contains(m.Error, "previous kernel policy was restored") || len(killed) != 0 {
		t.Fatalf("rolled-back update: %+v, killed %v", m, killed)
	}

	m = updateFailure(&lsm.KernelApplyError{Module: "exec", Err: errors.New("map write"), RollbackErr: errors.New("rollback"), FailedClosed: true}, "/cg", kill)
	if m.OK || !strings.Contains(m.Error, "deny-all") || !strings.Contains(m.Error, "workload was stopped") || len(killed) != 1 || killed[0] != "/cg" {
		t.Fatalf("failed-closed update: %+v, killed %v", m, killed)
	}

	m = updateFailure(&lsm.KernelApplyError{Module: "exec", Err: lsm.ErrKernelFailedClosed, FailedClosed: true}, "/cg", func(string) error { return errors.New("permission denied") })
	if !strings.Contains(m.Error, "stopping the workload failed: permission denied") {
		t.Fatalf("kill failure not reported: %+v", m)
	}
}

func TestKillCgroupUsesCgroupKill(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cgroup.kill"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := KillCgroup(dir); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(filepath.Join(dir, "cgroup.kill")); string(data) != "1" {
		t.Fatalf("cgroup.kill = %q, want 1", data)
	}
	if err := KillCgroup(""); err == nil {
		t.Fatal("an empty cgroup path must be an error")
	}
}

// Without cgroup.kill (Linux < 5.14) every pid in the subtree is SIGKILLed.
func TestKillCgroupFallsBackToSigkill(t *testing.T) {
	dir := t.TempDir()
	child := filepath.Join(dir, "child")
	if err := os.Mkdir(child, 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Skip("no sleep binary:", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(child, "cgroup.procs"), []byte(strconv.Itoa(cmd.Process.Pid)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A real cgroup.procs drops the pid once it exits; this file does not, so
	// KillCgroup reports it still present after its retries.
	_ = KillCgroup(dir)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("process in the cgroup subtree was not killed")
	}
	if cmd.ProcessState.Success() {
		t.Fatalf("process exited normally (%s), want killed", cmd.ProcessState)
	}
}
