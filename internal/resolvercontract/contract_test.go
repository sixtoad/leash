package resolvercontract

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestBuildNativeCanonicalizesResolvers(t *testing.T) {
	t.Parallel()
	document, err := Build("native", []string{
		"2001:0db8::53", "192.0.2.53", "::ffff:192.0.2.53", "fe80::1%eth0", "2001:db8::53",
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	want := []string{"192.0.2.53", "2001:db8::53", "fe80::1"}
	if document.Strategy != StrategyLeashManaged || !reflect.DeepEqual(document.Resolvers, want) {
		t.Fatalf("document = %+v, want strategy %q resolvers %v", document, StrategyLeashManaged, want)
	}
	if document.SchemaVersion != 1 || document.Runtime != "native" {
		t.Fatalf("identity fields = %+v", document)
	}
}

func TestBuildContainerDelegatesWithoutNativeAddresses(t *testing.T) {
	t.Parallel()
	for _, runtime := range []string{"docker", "podman"} {
		document, err := Build(runtime, nil)
		if err != nil {
			t.Fatalf("Build(%q): %v", runtime, err)
		}
		if document.Strategy != StrategyRuntimeManaged || len(document.Resolvers) != 0 {
			t.Fatalf("Build(%q) = %+v", runtime, document)
		}
		if !strings.Contains(document.Discovery, "/etc/resolv.conf") {
			t.Fatalf("Build(%q) discovery = %q", runtime, document.Discovery)
		}
	}
}

func TestBuildRejectsInvalidResolverState(t *testing.T) {
	t.Parallel()
	overLimit := make([]string, MaxResolvers+1)
	for index := range overLimit {
		overLimit[index] = fmt.Sprintf("192.0.2.%d", index+1)
	}
	tests := []struct {
		name string
		rt   string
		in   []string
		want string
	}{
		{name: "empty native", rt: "native", want: "no resolver"},
		{name: "malformed", rt: "native", in: []string{"not-an-ip"}, want: "invalid resolver"},
		{name: "over limit", rt: "native", in: overLimit, want: "exceeds limit"},
		{name: "native data on container", rt: "docker", in: []string{"1.1.1.1"}, want: "must not contain"},
		{name: "unknown runtime", rt: "container", want: "unsupported runtime"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Build(test.rt, test.in)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Build(%q, %v) error = %v, want %q", test.rt, test.in, err, test.want)
			}
		})
	}
}

func TestBuildAppliesLimitAfterDeduplication(t *testing.T) {
	t.Parallel()
	raw := make([]string, MaxResolvers+1)
	for index := range raw {
		raw[index] = "192.0.2.53"
	}
	document, err := Build("native", raw)
	if err != nil {
		t.Fatalf("Build duplicate input: %v", err)
	}
	if !reflect.DeepEqual(document.Resolvers, []string{"192.0.2.53"}) {
		t.Fatalf("resolvers = %v", document.Resolvers)
	}
}

func TestJSONIsDeterministicAndUsesEmptyArray(t *testing.T) {
	t.Parallel()
	document, err := Build("podman", nil)
	if err != nil {
		t.Fatal(err)
	}
	first, err := document.JSON()
	if err != nil {
		t.Fatal(err)
	}
	second, err := document.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) || !strings.Contains(string(first), `"resolvers": []`) {
		t.Fatalf("JSON not stable/explicit: %s", first)
	}
	var decoded map[string]any
	if err := json.Unmarshal(first, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := decoded["schemaVersion"]; got != float64(1) {
		t.Fatalf("schemaVersion = %v", got)
	}
}
