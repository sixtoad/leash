package resolvercontract

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func validNativeSource() []string { return []string{"8.8.8.8", "1.1.1.1"} }

func TestMainNativeWritesOnlyJSONToStdout(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	code := Main([]string{"--runtime", "native", "--json"}, &stdout, &stderr, "linux", validNativeSource)
	if code != ExitSuccess {
		t.Fatalf("exit = %d, stderr = %q", code, stderr.String())
	}
	var document Document
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
		t.Fatalf("stdout is not JSON: %v (%q)", err, stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("success stderr = %q", stderr.String())
	}
	if !strings.HasPrefix(stdout.String(), "{") || !strings.HasSuffix(stdout.String(), "\n") {
		t.Fatalf("stdout framing = %q", stdout.String())
	}
}

func TestMainContainerDoesNotReadNativeSource(t *testing.T) {
	t.Parallel()
	for _, runtime := range []string{"docker", "podman"} {
		var stdout, stderr bytes.Buffer
		code := Main([]string{"--runtime", runtime, "--json"}, &stdout, &stderr, "linux", func() []string {
			t.Fatal("container query read the native resolver source")
			return nil
		})
		if code != ExitSuccess {
			t.Fatalf("%s exit = %d, stderr = %q", runtime, code, stderr.String())
		}
		if strings.Contains(stdout.String(), "1.1.1.1") || !strings.Contains(stdout.String(), StrategyRuntimeManaged) {
			t.Fatalf("%s stdout = %s", runtime, stdout.String())
		}
	}
}

func TestMainFailuresKeepStdoutEmpty(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		args   []string
		source NativeResolverSource
		code   int
	}{
		{name: "missing runtime", args: []string{"--json"}, source: validNativeSource, code: ExitUsage},
		{name: "missing json", args: []string{"--runtime", "native"}, source: validNativeSource, code: ExitUsage},
		{name: "json false", args: []string{"--runtime", "native", "--json=false"}, source: validNativeSource, code: ExitUsage},
		{name: "conflicting runtime", args: []string{"--runtime", "native", "--runtime", "docker", "--json"}, source: validNativeSource, code: ExitUsage},
		{name: "conflicting json", args: []string{"--runtime", "native", "--json", "--json=false"}, source: validNativeSource, code: ExitUsage},
		{name: "positional", args: []string{"--runtime", "native", "--json", "extra"}, source: validNativeSource, code: ExitUsage},
		{name: "unknown runtime", args: []string{"--runtime", "container", "--json"}, source: validNativeSource, code: ExitContract},
		{name: "malformed source", args: []string{"--runtime", "native", "--json"}, source: func() []string { return []string{"bad"} }, code: ExitContract},
		{name: "unavailable source", args: []string{"--runtime", "native", "--json"}, code: ExitContract},
		{name: "help", args: []string{"--help"}, source: validNativeSource, code: ExitUsage},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := Main(test.args, &stdout, &stderr, "linux", test.source); code != test.code {
				t.Fatalf("exit = %d, want %d (stderr %q)", code, test.code, stderr.String())
			}
			if stdout.Len() != 0 {
				t.Fatalf("stdout = %q, want empty", stdout.String())
			}
			if stderr.Len() == 0 {
				t.Fatal("stderr is empty")
			}
		})
	}
}

type rejectWriter struct{}

func (rejectWriter) Write([]byte) (int, error) { return 0, errors.New("closed") }

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

func TestMainWriterFailureIsNotSuccess(t *testing.T) {
	t.Parallel()
	var stderr bytes.Buffer
	code := Main([]string{"--runtime", "native", "--json"}, rejectWriter{}, &stderr, "linux", validNativeSource)
	if code != ExitInternal || !strings.Contains(stderr.String(), "write resolver contract") {
		t.Fatalf("exit = %d, stderr = %q", code, stderr.String())
	}
}

func TestMainShortWriterIsNotSuccess(t *testing.T) {
	t.Parallel()
	var stderr bytes.Buffer
	code := Main([]string{"--runtime", "native", "--json"}, shortWriter{}, &stderr, "linux", validNativeSource)
	if code != ExitInternal || !strings.Contains(stderr.String(), "short write") {
		t.Fatalf("exit = %d, stderr = %q", code, stderr.String())
	}
}

func TestMainRejectsLinuxNativeContractOnOtherPlatforms(t *testing.T) {
	t.Parallel()
	for _, platform := range []string{"darwin", "windows", ""} {
		var stdout, stderr bytes.Buffer
		code := Main([]string{"--runtime", "native", "--json"}, &stdout, &stderr, platform, validNativeSource)
		if code != ExitContract || stdout.Len() != 0 || !strings.Contains(stderr.String(), "unsupported") {
			t.Fatalf("platform %q: exit=%d stdout=%q stderr=%q", platform, code, stdout.String(), stderr.String())
		}
	}
}
