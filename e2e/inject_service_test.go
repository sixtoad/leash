package e2e

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestInjectServiceContainer exercises the generic --inject-service mechanism end
// to end in the CONTAINER runtime: leash spawns a protocol-agnostic helper plugin
// on the host, binds its unix socket into the workload container at the identical
// path, sets the mapped workload env var to the in-container socket address, and
// delivers an opaque config payload to the plugin (which leash never interprets).
//
// The plugin here (e2e/testdata/injectstub) knows nothing about D-Bus or secrets;
// it only proves the generic wiring: socket binding, env mapping, and config
// delivery. Docker-gated behind LEASH_E2E — the container path runs in CI with a
// live daemon; without the gate the test skips.
func TestInjectServiceContainer(t *testing.T) {
	skipUnlessE2E(t)

	bin := ensureLeashBinary(t)
	stub := buildInjectStub(t)

	nano := time.Now().UnixNano()

	// Socket dir under /tmp (not a protected root) so leash creates+chowns it and
	// docker can bind-mount it into the workload at the identical path.
	socketDir := fmt.Sprintf("/tmp/leash-e2e-inject-%d", nano)
	socket := filepath.Join(socketDir, "bus")
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })

	// The stub derives its marker path from the socket (<socket>.cfg) because leash
	// may spawn the plugin via `runuser -- env`, which scrubs the environment — so
	// we do NOT rely on INJECTSTUB_MARKER being inherited and read the fallback.
	markerPath := socket + ".cfg"
	sentinel := fmt.Sprintf("e2e-cfg-%d", nano)

	const envVar = "INJECT_ADDR"
	spec := fmt.Sprintf("plugin=%s,env=%s,socket=%s,config=%s", stub, envVar, socket, sentinel)

	targetName := fmt.Sprintf("leash-e2e-inject-target-%d", nano)
	leashName := fmt.Sprintf("leash-e2e-inject-manager-%d", nano)

	shareDir := t.TempDir()
	policyPath := filepath.Join(t.TempDir(), "policy.cedar")
	mustWrite(t, policyPath, []byte(`permit (principal, action == Action::"ProcessLaunch", resource)
when { resource in [ Process::"/bin/sh" ] };`))

	cmd := exec.Command("timeout", "135", bin, "--inject-service", spec, "--", "sleep", "40")
	cmd.Env = append(os.Environ(),
		"TARGET_CONTAINER="+targetName,
		"LEASH_CONTAINER="+leashName,
		"LEASH_SHARE_DIR="+shareDir,
		"LEASH_POLICY_FILE="+policyPath,
		"LEASH_BOOTSTRAP_TIMEOUT=30s",
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start leash runner: %v\nstdout=%s\nstderr=%s", err, stdout.String(), stderr.String())
	}

	defer func() {
		_ = cmd.Process.Signal(os.Interrupt)
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case <-time.After(15 * time.Second):
			_ = cmd.Process.Kill()
		case <-done:
		}
		dockerRmForced(t, targetName, leashName)
	}()

	waitForContainerRunning(t, targetName, 60*time.Second)

	// 1. The mapped workload env var must carry the generic unix-socket address, and
	//    because the socket dir is bound at the identical path, the in-container
	//    address equals the host socket path.
	wantEnv := fmt.Sprintf("%s=unix:path=%s", envVar, socket)
	envOutput := dockerExecOutput(t, targetName, "env")
	if !strings.Contains(envOutput, wantEnv) {
		t.Fatalf("target container missing injected env %q; env=%q\nstdout=%s\nstderr=%s", wantEnv, envOutput, stdout.String(), stderr.String())
	}

	// 2. The live plugin socket must really be bound into the box as a socket at that
	//    identical path.
	if exit := dockerExecExitCode(t, targetName, "sh", "-c", "test -S "+socket); exit != 0 {
		t.Fatalf("expected injected socket %s to be a socket inside target container; exit=%d\nstdout=%s\nstderr=%s", socket, exit, stdout.String(), stderr.String())
	}

	// 3. Config delivery: the plugin recorded the opaque config leash handed it. The
	//    marker file must equal the sentinel we passed via config=, proving leash
	//    delivered the payload verbatim end to end.
	waitForHostFile(t, markerPath, 30*time.Second)
	data, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatalf("read inject marker %s: %v", markerPath, err)
	}
	if got := string(data); got != sentinel {
		t.Fatalf("injected config mismatch: marker=%q want %q", got, sentinel)
	}
}

// buildInjectStub compiles the generic inject-service helper plugin used by the
// test and returns its absolute path (fed into the --inject-service plugin= key).
// It mirrors how ensureLeashBinary builds ../cmd/leash.
func buildInjectStub(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "injectstub")
	cmd := exec.Command("go", "build", "-o", out, "./testdata/injectstub")
	cmd.Env = append(os.Environ(), "GOFLAGS=-vet=off")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("build injectstub: %v\n%s", err, stderr.String())
	}
	abs, err := filepath.Abs(out)
	if err != nil {
		t.Fatalf("resolve injectstub abs path: %v", err)
	}
	return abs
}
