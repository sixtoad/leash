package doctor

import (
	"bytes"
	"strings"
	"testing"
)

func TestCapsFromStatus(t *testing.T) {
	cases := []struct {
		name           string
		status         string
		wantBPF        bool
		wantNetAdmin   bool
		wantOK         bool
		wantParseError bool
	}{
		{
			name:         "root: full effective set",
			status:       "Name:\tleash\nCapEff:\t000001ffffffffff\nCapBnd:\t000001ffffffffff\n",
			wantBPF:      true,
			wantNetAdmin: true,
			wantOK:       true,
		},
		{
			name:   "unprivileged: empty effective set",
			status: "Name:\tleash\nCapEff:\t0000000000000000\n",
			wantOK: true,
		},
		{
			// setcap cap_bpf,cap_net_admin+ep — the non-root path leash supports.
			name:         "file caps: only bpf + net_admin",
			status:       "CapEff:\t0000008000001000\n",
			wantBPF:      true,
			wantNetAdmin: true,
			wantOK:       true,
		},
		{
			name:         "net_admin without bpf",
			status:       "CapEff:\t0000000000001000\n",
			wantNetAdmin: true,
			wantOK:       true,
		},
		{
			name:   "no CapEff field at all",
			status: "Name:\tleash\nUid:\t1000\t1000\t1000\t1000\n",
			wantOK: false,
		},
		{
			name:   "malformed mask",
			status: "CapEff:\tnot-hex\n",
			wantOK: false,
		},
		{
			name:   "empty input",
			status: "",
			wantOK: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			bpf, netAdmin, ok := capsFromStatus(c.status)
			if ok != c.wantOK {
				t.Fatalf("ok = %v, want %v", ok, c.wantOK)
			}
			if bpf != c.wantBPF || netAdmin != c.wantNetAdmin {
				t.Errorf("caps = (bpf=%v, net_admin=%v), want (bpf=%v, net_admin=%v)", bpf, netAdmin, c.wantBPF, c.wantNetAdmin)
			}
		})
	}
}

// Probe touches the real machine, so this only asserts self-consistency — the
// facts themselves differ per host and must not be pinned.
func TestProbeIsSelfConsistent(t *testing.T) {
	h := Probe()
	if h.GOOS == "" {
		t.Error("GOOS should always be populated")
	}
	if h.BPFLSMActive && strings.TrimSpace(h.BPFLSMAdvice) != "" {
		t.Errorf("an active bpf LSM should carry no remedy, got %q", h.BPFLSMAdvice)
	}
	if !h.BPFLSMActive && h.GOOS == "linux" && strings.TrimSpace(h.BPFLSMAdvice) == "" {
		t.Error("an inactive bpf LSM on Linux should carry a remedy")
	}
	// Whatever the host is, evaluating it must produce a coherent report.
	r := Evaluate(h)
	if r.Container.Ready != (r.Container.Engine != nil) {
		t.Errorf("container ready=%v but engine=%v", r.Container.Ready, r.Container.Engine)
	}
}

func TestMainRejectsUnknownFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Main([]string{"--nope"}, &stdout, &stderr); code != exitUsage {
		t.Errorf("unknown flag exit = %d, want %d", code, exitUsage)
	}
	if stdout.Len() != 0 {
		t.Errorf("usage errors must not pollute stdout (scripts parse it): %q", stdout.String())
	}
}

func TestMainJSONIsParseable(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Main([]string{"--json"}, &stdout, &stderr)
	if code != exitUsable && code != exitNoRuntime {
		t.Fatalf("unexpected exit %d (stderr: %s)", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{`"native"`, `"container"`, `"lsm_bpf"`, `"caps"`, `"issues"`, `"engine"`} {
		if !strings.Contains(out, want) {
			t.Errorf("JSON output missing %s:\n%s", want, out)
		}
	}
}
