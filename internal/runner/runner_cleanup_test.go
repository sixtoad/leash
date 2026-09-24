package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

type cleanupRuntime struct {
	identityRecordingRuntime
	output func(context.Context, ...string) (string, error)
}

func (rt *cleanupRuntime) Output(ctx context.Context, args ...string) (string, error) {
	return rt.output(ctx, args...)
}
func (rt *cleanupRuntime) Run(ctx context.Context, args ...string) error {
	_, err := rt.output(ctx, args...)
	return err
}
func (rt *cleanupRuntime) Name() string { return "podman" }

func TestTerminationSignalsIncludeInterruptAndTerminate(t *testing.T) {
	got := terminationSignals()
	if !reflect.DeepEqual(got, []os.Signal{os.Interrupt, syscall.SIGTERM}) {
		t.Fatalf("signals = %v", got)
	}
}

func TestContainerLaunchSettlesBeforeCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := &runner{}
	r.runtime = &cleanupRuntime{output: func(launchCtx context.Context, args ...string) (string, error) {
		if _, ok := launchCtx.Deadline(); !ok {
			t.Fatal("launch must have a deadline even with zero bootstrap timeout")
		}
		cancel()
		if err := launchCtx.Err(); err != nil {
			t.Fatalf("parent cancellation reached create: %v", err)
		}
		if !containsArg(args, containerSessionLabel+"="+r.containerSession) {
			t.Fatalf("no ownership label: %v", args)
		}
		return "created-id", nil
	}}
	if err := r.launchContainer(ctx, "target", "run", "--name", "target", "image"); !errors.Is(err, context.Canceled) {
		t.Fatalf("launch error = %v", err)
	}
	if uncertain, tracked := r.containerLaunches["target"]; !tracked || uncertain {
		t.Fatalf("settled launch tracking = %v", r.containerLaunches)
	}
}

func TestContainerLaunchTimeoutIsUncertain(t *testing.T) {
	r := &runner{cfg: config{bootstrapTimeout: time.Millisecond}}
	r.runtime = &cleanupRuntime{output: func(ctx context.Context, args ...string) (string, error) {
		<-ctx.Done()
		return "", ctx.Err()
	}}
	if err := r.launchContainer(context.Background(), "target", "run", "image"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("launch error = %v", err)
	}
	if !r.containerLaunches["target"] {
		t.Fatal("timed-out create must be reconciled")
	}
}

func TestCanceledContainerLaunchDoesNotCreate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := &runner{runtime: &cleanupRuntime{output: func(context.Context, ...string) (string, error) {
		t.Fatal("canceled request created container")
		return "", nil
	}}}
	if err := r.launchContainer(ctx, "target", "run", "image"); !errors.Is(err, context.Canceled) {
		t.Fatalf("launch error = %v", err)
	}
	if len(r.containerLaunches) != 0 {
		t.Fatalf("canceled request tracked: %v", r.containerLaunches)
	}
}

func TestStopContainersReapsLateOwnedContainer(t *testing.T) {
	r := &runner{containerSession: "ours", containerLaunches: map[string]bool{"target": true}, cleanupReconcileWindow: 100 * time.Millisecond, cleanupPollInterval: time.Millisecond}
	checks, removed := 0, 0
	exists := false
	r.runtime = &cleanupRuntime{output: func(ctx context.Context, args ...string) (string, error) {
		if ctx.Err() != nil {
			t.Fatalf("cleanup canceled: %v", ctx.Err())
		}
		switch args[0] {
		case "inspect":
			checks++
			if checks == 5 {
				exists = true
			}
			if exists {
				return "owned-id ours", nil
			}
			return "", errors.New("No such container")
		case "rm":
			if args[2] != "owned-id" {
				t.Fatalf("removed by name or wrong owner: %v", args)
			}
			exists = false
			removed++
			return "", nil
		}
		return "", fmt.Errorf("unexpected command: %v", args)
	}}
	if err := r.stopContainers(context.Background()); err != nil {
		t.Fatal(err)
	}
	if exists || removed != 1 || checks <= 6 {
		t.Fatalf("late cleanup: exists=%v removed=%d checks=%d", exists, removed, checks)
	}
}

func TestStopContainersPreservesForeignContainer(t *testing.T) {
	r := &runner{containerSession: "ours", containerLaunches: map[string]bool{"target": true}, cleanupReconcileWindow: 3 * time.Millisecond, cleanupPollInterval: time.Millisecond}
	r.runtime = &cleanupRuntime{output: func(_ context.Context, args ...string) (string, error) {
		if args[0] != "inspect" {
			t.Fatalf("foreign container modified: %v", args)
		}
		return "foreign-id another-session", nil
	}}
	if err := r.stopContainers(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestStopContainersUsesIDAcrossNameReplacement(t *testing.T) {
	r := &runner{containerSession: "ours", containerLaunches: map[string]bool{"target": false}}
	replaced := false
	r.runtime = &cleanupRuntime{output: func(_ context.Context, args ...string) (string, error) {
		if args[0] == "inspect" {
			if replaced {
				return "foreign-id theirs", nil
			}
			replaced = true
			return "owned-id ours", nil
		}
		if !reflect.DeepEqual(args, []string{"rm", "-f", "owned-id"}) {
			t.Fatalf("unsafe removal %v", args)
		}
		return "", errors.New("No such container: owned-id")
	}}
	if err := r.stopContainers(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestStopContainersReturnsRemovalErrorAndCleansFiles(t *testing.T) {
	work := t.TempDir()
	socket := filepath.Join(t.TempDir(), "plugin.sock")
	if err := os.WriteFile(socket, nil, 0600); err != nil {
		t.Fatal(err)
	}
	wantErr := errors.New("podman unavailable")
	r := &runner{cfg: config{workDir: work, workDirIsTemp: true, targetContainer: "target", leashContainer: "manager"}, injectedCleanup: []string{socket}, containerSession: "ours", containerLaunches: map[string]bool{"target": false, "manager": false}}
	var removals []string
	r.runtime = &cleanupRuntime{output: func(_ context.Context, args ...string) (string, error) {
		if args[0] == "inspect" {
			return args[3] + "-id ours", nil
		}
		removals = append(removals, args[2])
		return "", wantErr
	}}
	if err := r.finishLifecycle(context.Background(), 0, nil); !errors.Is(err, wantErr) {
		t.Fatalf("cleanup error = %v", err)
	}
	if !reflect.DeepEqual(removals, []string{"manager-id", "target-id"}) {
		t.Fatalf("removals = %v", removals)
	}
	for _, path := range []string{work, socket} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("cleanup left %s: %v", path, err)
		}
	}
}

func TestFinalizeSessionPreservesFailureAndReportsCleanupError(t *testing.T) {
	r := &runner{}
	cleanupErr := errors.New("remove failed")
	if err := r.finalizeSession(cleanupErr, 0); !errors.Is(err, cleanupErr) {
		t.Fatalf("successful workload cleanup error = %v", err)
	}
	var exitErr *ExitCodeError
	if err := r.finalizeSession(cleanupErr, 37); !errors.As(err, &exitErr) || exitErr.code != 37 {
		t.Fatalf("workload status lost: %v", err)
	}
}

func TestCleanupReconciliationHonorsDeadline(t *testing.T) {
	r := &runner{containerSession: "ours", containerLaunches: map[string]bool{"target": true}, cleanupPollInterval: time.Hour}
	r.runtime = &cleanupRuntime{output: func(_ context.Context, _ ...string) (string, error) { return "", errors.New("No such container") }}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Millisecond)
	defer cancel()
	if err := (containerLauncher{r: r}).Remove(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cleanup deadline error = %v", err)
	}
}

func TestProvisionNameConflictPreservesForeignContainers(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		t.Run(fmt.Sprint(explicit), func(t *testing.T) {
			r := &runner{cfg: config{targetContainer: "target", leashContainer: "target-leash", targetContainerBase: "target", leashContainerBase: "target-leash", cgroupPathOverride: "/test-cgroup"}}
			r.cfg.listenCfg.Disable = true
			if explicit {
				r.opts.containerName = "target"
			}
			runs := 0
			r.runtime = &cleanupRuntime{output: func(_ context.Context, args ...string) (string, error) {
				switch args[0] {
				case "image":
					return `""`, nil
				case "run":
					runs++
					if runs == 1 {
						return "", errors.New(`container name "target" is already in use`)
					}
					return "new-id", nil
				case "inspect":
					if strings.Contains(args[2], "Architecture") {
						return "amd64", nil
					}
					if args[3] == "target" {
						return "foreign-id theirs", nil
					}
					return "", errors.New("No such container")
				default:
					t.Fatalf("foreign container modified: %v", args)
				}
				return "", nil
			}}
			_, err := (containerLauncher{r: r}).Provision(context.Background(), "SIGTERM")
			if explicit {
				if err == nil || r.cfg.targetContainer != "target" || runs != 1 {
					t.Fatalf("explicit name changed: name=%s runs=%d err=%v", r.cfg.targetContainer, runs, err)
				}
			} else if err != nil || r.cfg.targetContainer != "target1" || runs != 2 {
				t.Fatalf("auto-name retry: name=%s runs=%d err=%v", r.cfg.targetContainer, runs, err)
			}
			if _, tracked := r.containerLaunches["target"]; tracked {
				t.Fatal("conflicting foreign name tracked for cleanup")
			}
			if err := r.stopContainers(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestEnsureNotRunningPreservesStoppedForeignContainer(t *testing.T) {
	r := &runner{cfg: config{targetContainer: "foreign", leashContainer: "manager"}, runtime: &cleanupRuntime{output: func(_ context.Context, args ...string) (string, error) {
		if args[0] != "inspect" {
			t.Fatalf("foreign container modified: %v", args)
		}
		return "/foreign", nil
	}}}
	if err := r.ensureNotRunningContainer(context.Background()); err == nil {
		t.Fatal("occupied name accepted")
	}
}

func TestCleanupUsesSelectedContainerRuntime(t *testing.T) {
	commandOverrideMu.Lock()
	original := commandOutput
	defer func() { commandOutput = original; commandOverrideMu.Unlock() }()
	for _, bin := range []string{"docker", "podman"} {
		t.Run(bin, func(t *testing.T) {
			exists := true
			commands := 0
			commandOutput = func(_ context.Context, name string, args ...string) (string, error) {
				commands++
				if name != bin {
					t.Fatalf("runtime = %s, want %s", name, bin)
				}
				if args[0] == "rm" {
					exists = false
					return "", nil
				}
				if exists {
					return "owned-id ours", nil
				}
				return "", errors.New("No such object")
			}
			r := &runner{runtime: cliRuntime{bin: bin}, containerSession: "ours", containerLaunches: map[string]bool{"target": false}}
			if err := r.stopContainers(context.Background()); err != nil {
				t.Fatal(err)
			}
			if exists || commands != 3 {
				t.Fatalf("cleanup: exists=%v commands=%d", exists, commands)
			}
		})
	}
}

func TestContainerLaunchLostResponseIsUncertain(t *testing.T) {
	want := errors.New("connection reset after create")
	r := &runner{runtime: &cleanupRuntime{output: func(context.Context, ...string) (string, error) { return "", want }}}
	if err := r.launchContainer(context.Background(), "target", "run", "image"); !errors.Is(err, want) {
		t.Fatalf("launch error = %v", err)
	}
	if !r.containerLaunches["target"] {
		t.Fatal("lost create response must be reconciled")
	}
}

func TestProvisionNameConflictRetriesAreBounded(t *testing.T) {
	runs := 0
	r := &runner{cfg: config{targetContainer: "target", leashContainer: "manager"}}
	r.runtime = &cleanupRuntime{output: func(_ context.Context, args ...string) (string, error) {
		switch args[0] {
		case "image":
			return `""`, nil
		case "run":
			runs++
			return "", errors.New("container name already in use")
		case "inspect":
			if strings.Contains(args[2], "Architecture") {
				return "amd64", nil
			}
			return "", errors.New("No such container")
		}
		t.Fatalf("unexpected command: %v", args)
		return "", nil
	}}
	_, err := (containerLauncher{r: r}).Provision(context.Background(), "SIGTERM")
	if err == nil || !strings.Contains(err.Error(), "retry limit") || runs != 100 {
		t.Fatalf("retry bound: runs=%d error=%v", runs, err)
	}
}

type interactiveCleanupRuntime struct {
	identityRecordingRuntime
	command func(context.Context) *exec.Cmd
}

func (rt *interactiveCleanupRuntime) Cmd(ctx context.Context, _ ...string) *exec.Cmd {
	return rt.command(ctx)
}

func TestInteractiveCancellationEntersCleanup(t *testing.T) {
	dir := t.TempDir()
	socket := filepath.Join(dir, "plugin.sock")
	if err := os.WriteFile(socket, nil, 0600); err != nil {
		t.Fatal(err)
	}
	r := &runner{runtime: createProcessRuntime{dir: dir}, injectedCleanup: []string{socket}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		code, err := r.execInteractive(ctx, "sh", "ignored")
		result <- r.finishInteractiveSession(ctx, code, err)
	}()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
waiting:
	for {
		select {
		case err := <-result:
			t.Fatalf("interactive process exited before cancellation: %v", err)
		case <-deadline.C:
			t.Fatal("interactive process did not start")
		case <-ticker.C:
			if _, err := os.Stat(filepath.Join(dir, "started")); err == nil {
				break waiting
			}
		}
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("interactive cancellation error = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("interactive process ignored cancellation")
	}
	if r.keepContainers {
		t.Fatal("canceled session kept containers")
	}
	if _, err := os.Stat(socket); !os.IsNotExist(err) {
		t.Fatalf("plugin teardown skipped: %v", err)
	}
}

func TestInteractiveSetnsFailurePreservesManualAttach(t *testing.T) {
	r := &runner{runtime: &interactiveCleanupRuntime{command: func(ctx context.Context) *exec.Cmd {
		return exec.CommandContext(ctx, "sh", "-c", "echo 'setns: permission denied' >&2; exit 42")
	}}}
	ctx := context.Background()
	code, err := r.execInteractive(ctx, "sh", "ignored")
	if code != 42 || err == nil {
		t.Fatalf("setns result = %d, %v", code, err)
	}
	if got := r.finishInteractiveSession(ctx, code, err); !errors.Is(got, err) {
		t.Fatalf("setns error lost: %v", got)
	}
	if !r.keepContainers {
		t.Fatal("manual-attach recovery no longer retains containers")
	}
}

func TestContainerLaunchRespectsRemainingParentDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	parentDeadline, _ := ctx.Deadline()
	r := &runner{cfg: config{bootstrapTimeout: time.Minute}, runtime: &cleanupRuntime{output: func(launchCtx context.Context, _ ...string) (string, error) {
		deadline, ok := launchCtx.Deadline()
		if !ok || !deadline.Equal(parentDeadline) {
			t.Fatalf("launch deadline %s, want parent %s", deadline, parentDeadline)
		}
		return "id", nil
	}}}
	if err := r.launchContainer(ctx, "target", "run", "image"); err != nil {
		t.Fatal(err)
	}
}

func TestCleanupReconciliationRecoversTransientErrorsForAllNames(t *testing.T) {
	r := &runner{cfg: config{leashContainer: "manager"}, containerSession: "ours", containerLaunches: map[string]bool{"target": true, "manager": true}, cleanupReconcileWindow: 100 * time.Millisecond, cleanupPollInterval: time.Millisecond}
	checks := map[string]int{}
	removed := map[string]bool{}
	failedRemove := false
	r.runtime = &cleanupRuntime{output: func(_ context.Context, args ...string) (string, error) {
		name := args[len(args)-1]
		if args[0] == "inspect" {
			checks[name]++
			if name == "target" && checks[name] == 2 {
				return "", errors.New("temporary inspect failure")
			}
			if removed[name] || (name == "target" && checks[name] < 4) {
				return "", errors.New("No such container")
			}
			return name + " ours", nil
		}
		if name == "manager" && !failedRemove {
			failedRemove = true
			return "", errors.New("temporary removal failure")
		}
		removed[name] = true
		return "", nil
	}}
	if err := r.stopContainers(context.Background()); err != nil {
		t.Fatalf("recovered cleanup failed: %v", err)
	}
	if !removed["target"] || !removed["manager"] {
		t.Fatalf("transient failure skipped another container: %v", removed)
	}
}
