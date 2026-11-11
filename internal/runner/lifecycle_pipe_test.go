package runner

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func lifecycleCapturePipe(t *testing.T) (string, func() string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "telemetry.pipe")
	if err := os.Chmod(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	reader := os.NewFile(uintptr(fd), path)
	keep, err := os.OpenFile(path, os.O_WRONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		_ = reader.Close()
		t.Fatal(err)
	}
	var buf bytes.Buffer
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(&buf, reader)
		close(done)
	}()
	var once sync.Once
	finish := func() string {
		once.Do(func() {
			_ = keep.Close()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				_ = reader.Close()
				<-done
				t.Error("optional FIFO producer did not retire")
			}
			_ = reader.Close()
		})
		return buf.String()
	}
	t.Cleanup(func() { finish() })
	return path, finish
}

func TestLifecyclePipeRejectsUnsafeOutputs(t *testing.T) {
	for _, kind := range []string{"relative", "missing", "regular", "symlink", "hardlink", "public", "parent-public", "no-reader"} {
		t.Run(kind, func(t *testing.T) {
			path, finish := lifecycleCapturePipe(t)
			candidate := path
			switch kind {
			case "relative":
				candidate = "telemetry.pipe"
			case "missing":
				candidate += ".missing"
			case "regular":
				candidate += ".file"
				if err := os.WriteFile(candidate, []byte("unchanged"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				candidate += ".link"
				if err := os.Symlink(path, candidate); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				candidate += ".hardlink"
				if err := os.Link(path, candidate); err != nil {
					t.Fatal(err)
				}
			case "public":
				if err := os.Chmod(path, 0666); err != nil {
					t.Fatal(err)
				}
			case "parent-public":
				if err := os.Chmod(filepath.Dir(path), 0755); err != nil {
					t.Fatal(err)
				}
			case "no-reader":
				finish()
			}
			start := time.Now()
			out, err := openLifecycleOutput(candidate)
			if out != nil {
				_ = out.Close()
			}
			if err == nil || time.Since(start) > time.Second {
				t.Fatalf("unsafe output accepted or blocked: %v", err)
			}
		})
	}
}

func TestLifecycleMissingPipeDoesNotFallbackToDiagnostics(t *testing.T) {
	t.Setenv("LEASH_TELEMETRY_RUN_ID", "test-run")
	t.Setenv(lifecyclePipeEnv, "")
	t.Setenv(lifecycleSecretEnv, `["host-only-secret"]`)
	var diagnostics bytes.Buffer
	r := &runner{diagnostics: &diagnostics}
	r.initLifecycleTelemetry()
	if r.lifecycleTelemetry != nil || diagnostics.Len() != 0 || os.Getenv(lifecycleSecretEnv) != "" {
		t.Fatal("optional telemetry fell back to shared output or retained secret input")
	}
}
