package runner

import (
	"bytes"
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
	keep, err := os.OpenFile(path, os.O_WRONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		_ = unix.Close(fd)
		t.Fatal(err)
	}
	var buf bytes.Buffer
	done := make(chan error, 1)
	stop := make(chan struct{})
	go func() {
		// Read the nonblocking descriptor directly: Darwin's kqueue can miss
		// FIFO EOF after the last writer closes. Keep checking read(2) so EOF
		// still proves that every producer has closed, including empty pipes.
		var chunk [32 << 10]byte
		for {
			n, err := unix.Read(fd, chunk[:])
			if n > 0 {
				buf.Write(chunk[:n])
			}
			if err != unix.EAGAIN && err != unix.EINTR {
				if err != nil || n == 0 {
					done <- err
					return
				}
			}
			select {
			case <-stop:
				done <- nil
				return
			case <-time.After(time.Millisecond):
			}
		}
	}()
	var once sync.Once
	finish := func() string {
		once.Do(func() {
			_ = keep.Close()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("capture lifecycle pipe: %v", err)
				}
			case <-time.After(2 * time.Second):
				close(stop)
				<-done
				t.Error("optional FIFO producer did not retire")
			}
			_ = unix.Close(fd)
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
