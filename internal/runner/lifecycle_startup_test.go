package runner

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestLifecycleInteractiveOptInUsesStderrWithoutChangingMode(t *testing.T) {
	if os.Getenv("LEASH_LIFECYCLE_INTERACTIVE_HELPER") == "1" {
		r := &runner{}
		r.initLifecycleTelemetry()
		if r.lifecycleTelemetry == nil || r.opts.noInteractive || r.opts.machineOutput ||
			r.lifecycleTelemetry.out == os.Stderr || r.diagnosticWriter() != os.Stdout {
			os.Exit(91)
		}
		r.lifecycleTelemetry.phase("attach")(nil)
		r.lifecycleTelemetry.finishAudit()
		_, _ = os.Stdout.WriteString("unchanged workload stdout")
		return
	}
	pipe, capture := lifecycleCapturePipe(t)
	t.Setenv(lifecyclePipeEnv, pipe)
	t.Setenv("LEASH_TELEMETRY_RUN_ID", "test-run")
	cmd := exec.Command(os.Args[0], "-test.run=^TestLifecycleInteractiveOptInUsesStderrWithoutChangingMode$")
	cmd.Env = append(os.Environ(), "LEASH_LIFECYCLE_INTERACTIVE_HELPER=1")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(stdout.String(), "unchanged workload stdout") || strings.Contains(stdout.String(), lifecycleSchema) {
		t.Fatalf("optional records changed stdout: %q", stdout.String())
	}
	if len(lifecycleRecords(t, capture())) != 2 || strings.Contains(stderr.String(), lifecycleSchema) {
		t.Fatal("missing interactive telemetry")
	}
}

func TestLifecycleStartupConsumesSecretBeforeRequiredCommands(t *testing.T) {
	t.Setenv(lifecycleSecretEnv, `["must-not-reach-launcher-children"]`)
	t.Setenv("LEASH_TELEMETRY_RUN_ID", "test-run")
	t.Setenv("LEASH_DISABLE_TELEMETRY", "1")
	t.Setenv("PATH", t.TempDir())
	t.Setenv("LEASH_HOME", t.TempDir())
	t.Setenv("LEASH_WORK_DIR", t.TempDir())
	// The missing engine stops execution before mount initialization. The secret
	// must already be consumed on this path, before keychain/helper subprocesses.
	err := execute("leash", []string{"--runtime", "docker", "--", "true"})
	if err == nil || os.Getenv(lifecycleSecretEnv) != "" {
		t.Fatalf("early secret consumption: %v", err)
	}
}

func TestLifecycleAuditOpenRejectsSnapshotReplacementPromptly(t *testing.T) {
	for _, kind := range []string{"fifo", "symlink", "hardlink", "different-inode"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "events.log")
			if err := os.WriteFile(path, []byte("original\n"), 0600); err != nil {
				t.Fatal(err)
			}
			snapshot, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			outside := filepath.Join(dir, "outside")
			if err := os.Rename(path, outside); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "fifo":
				err = syscall.Mkfifo(path, 0600)
			case "symlink":
				err = os.Symlink(outside, path)
			case "hardlink":
				err = os.Link(outside, path)
			case "different-inode":
				err = os.WriteFile(path, []byte("replacement\n"), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				f, err := openLifecycleAudit(path, snapshot)
				if f != nil {
					_ = f.Close()
				}
				done <- err
			}()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("replaced audit source accepted")
				}
			case <-time.After(time.Second):
				t.Fatal("optional audit open blocked")
			}
		})
	}
}
