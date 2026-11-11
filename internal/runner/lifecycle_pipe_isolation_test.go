package runner

import (
	"context"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestLifecycleBlockedFIFOLeavesCleanupDiagnosticsIndependent(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires normal Unix cleanup permission failure")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	pipe := filepath.Join(dir, "optional.pipe")
	if err := unix.Mkfifo(pipe, 0600); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(pipe, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	reader := os.NewFile(uintptr(fd), pipe)
	defer reader.Close()
	diagRead, diagWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer diagRead.Close()
	defer diagWrite.Close()
	audit := t.TempDir()
	if err := os.WriteFile(filepath.Join(audit, "events.log"), []byte(strings.Repeat("event=deny path=/work/source.go\n", 2000)), 0600); err != nil {
		t.Fatal(err)
	}
	protected := t.TempDir()
	if err := os.WriteFile(filepath.Join(protected, "file"), []byte("test"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(protected, 0500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(protected, 0700)
	t.Setenv(lifecyclePipeEnv, pipe)
	t.Setenv("LEASH_TELEMETRY_RUN_ID", "test-run")
	r := &runner{cfg: config{workDir: protected, workDirIsTemp: true, logDir: audit},
		verbose: true, logger: log.New(diagWrite, "", 0), diagnostics: diagWrite}
	r.initLifecycleTelemetry()
	if r.lifecycleTelemetry == nil {
		t.Fatal("private FIFO was not enabled")
	}
	done := make(chan error, 1)
	go func() { done <- r.finishLifecycle(context.Background(), 0, nil) }()
	blocked := false
	select {
	case err = <-done:
	case <-time.After(2 * time.Second):
		blocked = true
	}
	drained := make(chan struct{})
	go func() { _, _ = io.Copy(io.Discard, reader); close(drained) }()
	if blocked {
		err = <-done
	}
	<-r.lifecycleTelemetry.done
	<-drained
	_ = diagWrite.Close()
	diagnostic, readErr := io.ReadAll(diagRead)
	if blocked || err != nil || readErr != nil || !strings.Contains(string(diagnostic), "failed to remove work dir") {
		t.Fatalf("optional FIFO affected actual cleanup/diagnostic: blocked=%v err=%v read=%v", blocked, err, readErr)
	}
}

func TestLifecyclePipeRefusesStderrAlias(t *testing.T) {
	path, finish := lifecycleCapturePipe(t)
	out, err := os.OpenFile(path, os.O_WRONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = out
	defer func() { os.Stderr = old; _ = out.Close(); finish() }()
	alias, err := openLifecycleOutput(path)
	if alias != nil {
		_ = alias.Close()
	}
	if err == nil {
		t.Fatal("optional FIFO shared the required stderr channel")
	}
}
