package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

func lifecycleTestSink(t *testing.T, out io.Writer) *lifecycleTelemetry {
	t.Helper()
	t.Setenv("LEASH_TELEMETRY_RUN_ID", "test-run")
	t.Setenv("LEASH_TELEMETRY_MAX_FILE_BYTES", "")
	sink, err := newLifecycleTelemetry(out, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sink.finishAudit)
	return sink
}

func lifecycleRecords(t *testing.T, data string) []map[string]any {
	t.Helper()
	var records []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(data), "\n") {
		if line == "" {
			continue
		}
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("invalid NDJSON %q: %v", line, err)
		}
		if record["schema"] != lifecycleSchema || record["source"] != "leash" || record["run"] != "test-run" {
			t.Fatalf("invalid envelope: %v", record)
		}
		for _, key := range []string{"agent", "dispatch_id"} {
			if value, ok := record[key]; !ok || value != nil {
				t.Fatalf("%s not explicitly null", key)
			}
		}
		if _, err := time.Parse("2006-01-02T15:04:05.000Z", record["timestamp"].(string)); err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
	}
	return records
}

type lifecycleFakeLauncher struct {
	launcher
	calls []string
	err   error
}

func (l *lifecycleFakeLauncher) PullImages(context.Context) error {
	l.calls = append(l.calls, "image_prepare")
	return l.err
}
func (l *lifecycleFakeLauncher) Provision(context.Context, string) (string, error) {
	l.calls = append(l.calls, "provision")
	return "/cgroup", l.err
}
func (l *lifecycleFakeLauncher) StartEnforcement(context.Context, string) error {
	l.calls = append(l.calls, "enforcement")
	return l.err
}
func (l *lifecycleFakeLauncher) WaitReady(context.Context) error {
	l.calls = append(l.calls, "attach")
	return l.err
}
func (l *lifecycleFakeLauncher) Remove(context.Context) error {
	l.calls = append(l.calls, "cleanup")
	return l.err
}

func TestLifecycleLauncherMeasuresGatesWithoutChangingResults(t *testing.T) {
	for _, failure := range []error{nil, errors.New("sensitive error credential")} {
		var out bytes.Buffer
		fake := &lifecycleFakeLauncher{err: failure}
		l := telemetryLauncher{launcher: fake, telemetry: lifecycleTestSink(t, &out)}
		ctx := context.Background()
		if l.PullImages(ctx) != failure {
			t.Fatal("image error changed")
		}
		path, err := l.Provision(ctx, "SIGTERM")
		if path != "/cgroup" || err != failure {
			t.Fatal("provision result changed")
		}
		if l.StartEnforcement(ctx, path) != failure || l.WaitReady(ctx) != failure || l.Remove(ctx) != failure {
			t.Fatal("gate error changed")
		}
		l.telemetry.finishAudit()
		records := lifecycleRecords(t, out.String())
		if len(records) != len(fake.calls)+1 || records[len(records)-1]["type"] != "leash_export" {
			t.Fatal("missing phase")
		}
		for i, record := range records[:len(records)-1] {
			if record["type"] != "phase" || record["name"] != fake.calls[i] {
				t.Fatalf("order: %v", records)
			}
			start, _ := time.Parse(time.RFC3339Nano, record["start"].(string))
			end, _ := time.Parse(time.RFC3339Nano, record["end"].(string))
			if end.Before(start) || record["duration_ms"].(float64) < 0 {
				t.Fatal("invalid timing")
			}
			want := "ok"
			if failure != nil {
				want = "error"
			}
			if record["status"] != want {
				t.Fatalf("status: %v", record)
			}
		}
		if strings.Contains(out.String(), "sensitive") {
			t.Fatal("raw error leaked")
		}
	}
}

type lifecycleFailWriter struct {
	calls int
	short bool
}

func (w *lifecycleFailWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.short {
		return len(p) - 1, nil
	}
	return 0, syscall.ENOSPC
}

func TestLifecycleWriterFailureDisablesOnlyTelemetry(t *testing.T) {
	for _, short := range []bool{false, true} {
		out := &lifecycleFailWriter{short: short}
		sink := lifecycleTestSink(t, out)
		fake := &lifecycleFakeLauncher{err: errors.New("original enforcement failure")}
		l := telemetryLauncher{launcher: fake, telemetry: sink}
		for i := 0; i < 2; i++ {
			if l.WaitReady(context.Background()) != fake.err {
				t.Fatal("required gate error changed")
			}
		}
		sink.finishAudit()
		if out.calls != 1 || !sink.disabled {
			t.Fatal("failed sink was not disabled")
		}
	}
}

func TestLifecycleOptInConsumesHostSecretInput(t *testing.T) {
	pipe, capture := lifecycleCapturePipe(t)
	t.Setenv(lifecyclePipeEnv, pipe)
	t.Setenv("LEASH_TELEMETRY_FD", "99")
	t.Setenv(lifecycleSecretEnv, `["hidden-grant"]`)
	t.Setenv("LEASH_TELEMETRY_RUN_ID", "test-run")
	var out bytes.Buffer
	r := &runner{opts: options{machineOutput: true, envVars: []string{lifecycleSecretEnv + "=hidden-grant", lifecyclePipeEnv + "=" + pipe, "LEASH_TELEMETRY_FD=99", "SAFE=yes"}}, diagnostics: &out}
	r.initLifecycleTelemetry()
	if r.lifecycleTelemetry == nil || os.Getenv(lifecycleSecretEnv) != "" || os.Getenv(lifecyclePipeEnv) != "" || os.Getenv("LEASH_TELEMETRY_FD") != "" || strings.Join(r.opts.envVars, ",") != "SAFE=yes" {
		t.Fatal("host input escaped into child environment")
	}
	r.lifecycleTelemetry.emit(map[string]any{"type": "leash_audit", "message": r.lifecycleTelemetry.redactor.text("hidden-grant")}, 0)
	r.lifecycleTelemetry.finishAudit()
	if strings.Contains(capture(), "hidden-grant") || out.Len() != 0 {
		t.Fatal("explicit secret leaked")
	}
	first := r.lifecycleTelemetry
	r.initLifecycleTelemetry()
	if r.lifecycleTelemetry != first || strings.Contains(r.lifecycleTelemetry.redactor.text("hidden-grant"), "hidden-grant") {
		t.Fatal("repeat initialization replaced credential redaction context")
	}
	t.Setenv("LEASH_TELEMETRY_RUN_ID", "")
	r = &runner{diagnostics: &out}
	r.initLifecycleTelemetry()
	if r.lifecycleTelemetry != nil {
		t.Fatal("telemetry enabled without explicit host opt-in")
	}
}

func TestLifecycleFailurePreservesWorkloadBytesAndExit(t *testing.T) {
	if os.Getenv("LEASH_LIFECYCLE_WORKLOAD_HELPER") == "1" {
		_, _ = os.Stdout.Write([]byte{'{', 0, 0xff, '}', '\n'})
		os.Exit(37)
	}
	if os.Getenv("LEASH_LIFECYCLE_RUNNER_HELPER") == "1" {
		r := &runner{opts: options{machineOutput: true}, lifecycleTelemetry: lifecycleTestSink(t, &lifecycleFailWriter{})}
		if r.lifecycleTelemetry == nil {
			os.Exit(99)
		}
		r.lifecycleTelemetry.phase("image_prepare")(nil)
		cmd := exec.Command(os.Args[0], "-test.run=^TestLifecycleFailurePreservesWorkloadBytesAndExit$")
		cmd.Env = append(os.Environ(), "LEASH_LIFECYCLE_WORKLOAD_HELPER=1")
		code, err := runWorkloadCommand(cmd)
		if err != nil {
			os.Exit(99)
		}
		r.lifecycleTelemetry.finishAudit()
		os.Exit(code)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestLifecycleFailurePreservesWorkloadBytesAndExit$")
	cmd.Env = append(os.Environ(), "LEASH_LIFECYCLE_RUNNER_HELPER=1", "LEASH_TELEMETRY_RUN_ID=test-run")
	var out, diagnostics bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &diagnostics
	err := cmd.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 37 {
		t.Fatalf("exit changed: %v", err)
	}
	if !bytes.Equal(out.Bytes(), []byte{'{', 0, 0xff, '}', '\n'}) {
		t.Fatalf("stdout changed: %v", out.Bytes())
	}
	if diagnostics.Len() != 0 {
		t.Fatal("optional telemetry wrote to shared diagnostics")
	}
}
