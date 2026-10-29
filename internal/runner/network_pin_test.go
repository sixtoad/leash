package runner

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

func TestPinNetworkHostArguments(t *testing.T) {
	opts, err := parseArgs([]string{"--pin-network-host", "Z.test", "--pin-network-host=a.test", "--pin-network-host=z.test", "--", "echo", "x"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(opts.pinNetworkHosts, []string{"a.test", "z.test"}) {
		t.Fatal(opts.pinNetworkHosts)
	}
	for _, args := range [][]string{{"--pin-network-host"}, {"--pin-network-host="}, {"--pin-network-host", "*.test"}, {"--pin-network-host", "127.0.0.1"}} {
		if _, err := parseArgs(args); err == nil {
			t.Fatalf("accepted %q", args)
		}
	}
}

func TestValidateNetworkPinTarget(t *testing.T) {
	for _, raw := range []string{`{}`, `invalid`, `{"HostsPath":"/engine/hosts","HostConfig":{"NetworkMode":"container:other"}}`, `{"HostsPath":"/engine/hosts","Mounts":[{"Destination":"/etc/hosts"}]}`, `{"HostsPath":"/engine/hosts","Mounts":[{"Destination":"/etc"}]}`, `{"HostsPath":"/engine/hosts","Mounts":[{"Destination":"/"}]}`} {
		if err := validateNetworkPinTarget(raw); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	if err := validateNetworkPinTarget(`{"HostsPath":"/engine/hosts","HostConfig":{"NetworkMode":"bridge"},"Mounts":[{"Destination":"/work"}]}`); err != nil {
		t.Fatal(err)
	}
}

func TestNoNetworkPinsDoesNotInvokeRuntime(t *testing.T) {
	var r runner
	if err := r.prepareNetworkPins(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// The helper failure must propagate before callers can start enforcement.
func TestPrepareNetworkPinsFailureStopsPreparation(t *testing.T) {
	rt := &pinRecordingRuntime{helperErr: fmt.Errorf("DNS timeout")}
	r := runner{runtime: rt, opts: options{pinNetworkHosts: []string{"registry.test"}}, cfg: config{targetContainer: "target", targetImage: "image"}, logger: log.New(io.Discard, "", 0)}
	if err := r.prepareNetworkPins(context.Background()); err == nil || !strings.Contains(err.Error(), "DNS timeout") {
		t.Fatalf("got %v", err)
	}
	if len(rt.calls) != 3 {
		t.Fatalf("calls: %v", rt.calls)
	}
	want := []string{"exec", "--user", "0", "target", "/leash/leash-entry-linux-amd64", "--pin-network-hosts", "registry.test"}
	if !reflect.DeepEqual(rt.calls[2], want) {
		t.Fatalf("got %q", rt.calls[2])
	}
}

func TestPrepareNetworkPinsLogsSnapshot(t *testing.T) {
	t.Setenv("GODEBUG", "netdns=go+1")
	rt := &pinRecordingRuntime{diagnostics: "go package net: GODEBUG setting forcing use of Go resolver"}
	var output bytes.Buffer
	r := runner{runtime: rt, opts: options{pinNetworkHosts: []string{"registry.test"}}, cfg: config{targetContainer: "target", targetImage: "image"}, logger: log.New(&output, "", 0)}
	if err := r.prepareNetworkPins(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), rt.diagnostics) {
		t.Fatal("helper diagnostics were not forwarded")
	}
	if !strings.Contains(output.String(), `snapshot=[{"host":"registry.test","addresses":["192.0.2.1"]}]`) {
		t.Fatal(output.String())
	}
}

type pinRecordingRuntime struct {
	identityRecordingRuntime
	calls       [][]string
	helperErr   error
	diagnostics string
}

func (r *pinRecordingRuntime) Output(ctx context.Context, args ...string) (string, error) {
	r.calls = append(r.calls, append([]string(nil), args...))
	if _, ok := ctx.Deadline(); !ok {
		return "", fmt.Errorf("missing deadline")
	}
	if args[0] == "exec" {
		return `[{"host":"registry.test","addresses":["192.0.2.1"]}]`, r.helperErr
	}
	if strings.Contains(strings.Join(args, " "), "Architecture") {
		return "amd64", nil
	}
	return `{"HostsPath":"/engine/hosts","HostConfig":{"NetworkMode":"bridge"}}`, nil
}

func TestPinNetworkHostRejectsUnsupportedRuntime(t *testing.T) {
	t.Setenv("LEASH_HOME", t.TempDir())
	t.Setenv("LEASH_WORK_DIR", t.TempDir())
	for _, backend := range []string{"native", "podman"} {
		_, _, err := loadConfig(t.TempDir(), options{runtime: backend, pinNetworkHosts: []string{"a.test"}})
		if err == nil || !strings.Contains(err.Error(), "--pin-network-host requires Linux Docker") {
			t.Fatalf("%s: %v", backend, err)
		}
	}
}

func (r *pinRecordingRuntime) Cmd(ctx context.Context, args ...string) *exec.Cmd {
	r.calls = append(r.calls, append([]string(nil), args...))
	code := "0"
	diagnostics := r.diagnostics
	if r.helperErr != nil {
		code = "1"
		diagnostics = r.helperErr.Error()
	}
	return exec.CommandContext(ctx, "sh", "-c", `printf '%s\n' "$1"; printf '%s' "$2" >&2; exit "$3"`, "--", `[{"host":"registry.test","addresses":["192.0.2.1"]}]`, diagnostics, code)
}

func TestPinOutputLimit(t *testing.T) {
	var b pinOutputBuffer
	if _, err := b.Write(make([]byte, 64*1024)); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Write([]byte("x")); err == nil {
		t.Fatal("accepted oversized output")
	}
	if b.Len() != 64*1024 {
		t.Fatal("overflow changed output")
	}
}

func TestPinOutputCopyCannotBypassLimit(t *testing.T) {
	var b pinOutputBuffer
	if _, err := io.Copy(&b, strings.NewReader(strings.Repeat("x", 64*1024+1))); err == nil {
		t.Fatal("io.Copy bypassed output limit")
	}
	if b.Len() > 64*1024 {
		t.Fatal("buffer exceeded limit")
	}
}

func TestPinOutputProcessCannotBypassLimit(t *testing.T) {
	var output pinOutputBuffer
	cmd := exec.Command("sh", "-c", `printf '%65537s' x`)
	cmd.Stdout = &output
	if err := cmd.Run(); err == nil {
		t.Fatal("process output bypassed limit")
	}
	if output.Len() > 64*1024 {
		t.Fatal("process output exceeded limit")
	}
}
