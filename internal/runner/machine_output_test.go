package runner

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestMachineOutputSelectsStderrForDiagnostics(t *testing.T) {
	t.Parallel()

	if got := (&runner{}).diagnosticWriter(); got != os.Stdout {
		t.Fatalf("default diagnostic writer = %T, want os.Stdout", got)
	}
	if got := (&runner{opts: options{machineOutput: true}}).diagnosticWriter(); got != os.Stderr {
		t.Fatalf("machine diagnostic writer = %T, want os.Stderr", got)
	}
}

func TestMachineOutputRoutesRuntimeLifecycleStreamsToDiagnostics(t *testing.T) {
	mountStateTestMu.Lock()
	t.Cleanup(mountStateTestMu.Unlock)

	original := runCommand
	t.Cleanup(func() { runCommand = original })

	var gotStdout, gotStderr io.Writer
	runCommand = func(_ context.Context, stdout, stderr io.Writer, _ string, _ ...string) error {
		gotStdout = stdout
		gotStderr = stderr
		_, _ = io.WriteString(stdout, "runtime-stdout\n")
		_, _ = io.WriteString(stderr, "runtime-stderr\n")
		return nil
	}

	for _, runtimeName := range []string{"docker", "podman"} {
		t.Run(runtimeName, func(t *testing.T) {
			var diagnostics bytes.Buffer
			r := &runner{
				opts:        options{machineOutput: true},
				runtime:     cliRuntime{bin: runtimeName},
				diagnostics: &diagnostics,
			}
			if err := r.rt().Run(context.Background(), "pull", "image"); err != nil {
				t.Fatalf("Run: %v", err)
			}
			if gotStdout != &diagnostics || gotStderr != &diagnostics {
				t.Fatalf("runtime writers = (%T, %T), want the machine diagnostic writer for both", gotStdout, gotStderr)
			}
			if got := diagnostics.String(); got != "runtime-stdout\nruntime-stderr\n" {
				t.Fatalf("diagnostics = %q, want both runtime streams", got)
			}
		})
	}
}

func TestDefaultRuntimeLifecycleDestinationsRemainUnchanged(t *testing.T) {
	mountStateTestMu.Lock()
	t.Cleanup(mountStateTestMu.Unlock)

	original := runCommand
	t.Cleanup(func() { runCommand = original })

	var gotStdout, gotStderr io.Writer
	runCommand = func(_ context.Context, stdout, stderr io.Writer, _ string, _ ...string) error {
		gotStdout = stdout
		gotStderr = stderr
		return nil
	}

	r := &runner{runtime: cliRuntime{bin: "docker"}}
	if err := r.rt().Run(context.Background(), "pull", "image"); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if gotStdout != os.Stdout || gotStderr != os.Stderr {
		t.Fatalf("default runtime writers = (%T, %T), want (os.Stdout, os.Stderr)", gotStdout, gotStderr)
	}
}

func TestMachineOutputRoutesPointerRuntimeLifecycleStreams(t *testing.T) {
	mountStateTestMu.Lock()
	t.Cleanup(mountStateTestMu.Unlock)

	original := runCommand
	t.Cleanup(func() { runCommand = original })

	var gotStdout, gotStderr io.Writer
	runCommand = func(_ context.Context, stdout, stderr io.Writer, _ string, _ ...string) error {
		gotStdout = stdout
		gotStderr = stderr
		return nil
	}

	var diagnostics bytes.Buffer
	r := &runner{
		opts:        options{machineOutput: true},
		runtime:     &cliRuntime{bin: "docker"},
		diagnostics: &diagnostics,
	}
	if err := r.rt().Run(context.Background(), "pull", "image"); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if gotStdout != &diagnostics || gotStderr != &diagnostics {
		t.Fatalf("pointer runtime writers = (%T, %T), want the machine diagnostic writer for both", gotStdout, gotStderr)
	}
}

func TestWorkloadStdioIsDirectAcrossLauncherSeams(t *testing.T) {
	t.Parallel()

	containerRunner := &runner{runtime: recordingRuntime{inspected: new([]string)}}
	containerCmd := containerRunner.launcher().ExecCommand(context.Background(), "sh", "true", false)

	nativeRunner := &runner{runtime: newNativeRuntime()}
	nativeCmd := nativeRunner.launcher().ExecCommand(context.Background(), "sh", "true", false)

	for name, cmd := range map[string]*exec.Cmd{"container": containerCmd, "native": nativeCmd} {
		attachWorkloadStdio(cmd)
		if cmd.Stdin != os.Stdin || cmd.Stdout != os.Stdout || cmd.Stderr != os.Stderr {
			t.Fatalf("%s workload stdio is not attached directly to the host descriptors", name)
		}
	}
}

func TestMachineOutputPreservesWorkloadBytesAndExitCode(t *testing.T) {
	if os.Getenv("LEASH_TEST_WORKLOAD_HELPER") == "1" {
		_, _ = os.Stdout.Write([]byte{'{', 0, 0xff, '}', '\n', 'x'})
		_, _ = os.Stderr.Write([]byte("agent-stderr\x00tail"))
		os.Exit(37)
	}
	if os.Getenv("LEASH_TEST_RUNNER_HELPER") == "1" {
		r := &runner{opts: options{machineOutput: true}}
		r.diagnosticf("leash-diagnostic\n")
		cmd := exec.Command(os.Args[0], "-test.run=TestMachineOutputPreservesWorkloadBytesAndExitCode")
		cmd.Env = append(os.Environ(), "LEASH_TEST_WORKLOAD_HELPER=1")
		code, err := runWorkloadCommand(cmd)
		if err != nil || cmd.Stdin != os.Stdin || cmd.Stdout != os.Stdout || cmd.Stderr != os.Stderr {
			os.Exit(99)
		}
		os.Exit(code)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestMachineOutputPreservesWorkloadBytesAndExitCode")
	cmd.Env = append(os.Environ(), "LEASH_TEST_RUNNER_HELPER=1")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	exitErr, ok := err.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != 37 {
		t.Fatalf("exit = %v, want exact workload status 37", err)
	}
	wantStdout := []byte{'{', 0, 0xff, '}', '\n', 'x'}
	if !bytes.Equal(stdout.Bytes(), wantStdout) {
		t.Fatalf("stdout = %v, want exact bytes %v", stdout.Bytes(), wantStdout)
	}
	wantStderr := []byte("leash-diagnostic\nagent-stderr\x00tail")
	if !bytes.Equal(stderr.Bytes(), wantStderr) {
		t.Fatalf("stderr = %v, want exact bytes %v", stderr.Bytes(), wantStderr)
	}
}

func TestMachineOutputHelpAfterHelpFlagStaysOffStdout(t *testing.T) {
	if os.Getenv("LEASH_TEST_HELP_HELPER") == "1" {
		if err := execute("leash", []string{"--help", "--machine-output"}); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestMachineOutputHelpAfterHelpFlagStaysOffStdout")
	cmd.Env = append(os.Environ(), "LEASH_TEST_HELP_HELPER=1")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("help helper: %v", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "Usage: leash") {
		t.Fatalf("stderr = %q, want usage text", stderr.String())
	}
}
