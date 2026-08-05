package doctor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/strongdm/leash/internal/runner"
)

// Capabilities read inside a user namespace describe that namespace, not the
// host: CAP_BPF there does not permit loading a BPF_PROG_TYPE_LSM program. So
// they must be reported unknown-and-not-ready rather than claimed (issue #53,
// observed live in an unprivileged Proxmox LXC reporting caps:[bpf,net_admin]).

func writeUIDMap(t *testing.T, content string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "uid_map")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	old := procSelfUIDMap
	procSelfUIDMap = p
	t.Cleanup(func() { procSelfUIDMap = old })
}

func TestInUserNamespace(t *testing.T) {
	tests := []struct {
		name   string
		uidMap string
		want   bool
	}{
		{"initial namespace", "         0          0 4294967295\n", false},
		{"initial, no padding", "0 0 4294967295", false},
		{"rootless container map", "         0       1000          1\n", true},
		{"subuid range map", "         0     100000      65536\n", true},
		{"multiple ranges", "0 0 1\n1 100000 65536\n", true},
		{"empty file", "", true},
		{"malformed", "not a map", true},
		{"truncated fields", "0 0", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			writeUIDMap(t, tt.uidMap)
			if got := inUserNamespace(); got != tt.want {
				t.Fatalf("inUserNamespace() = %v, want %v (uid_map %q)", got, tt.want, tt.uidMap)
			}
		})
	}
}

func TestInUserNamespaceUnreadableIsCautious(t *testing.T) {
	old := procSelfUIDMap
	procSelfUIDMap = filepath.Join(t.TempDir(), "does-not-exist")
	t.Cleanup(func() { procSelfUIDMap = old })
	if !inUserNamespace() {
		t.Fatal("an unreadable uid_map must be treated as namespaced (cautious direction)")
	}
}

func TestProbeCapsUnknownInUserNamespace(t *testing.T) {
	// A status file that WOULD report both capabilities, to prove the namespace
	// check wins over the readable bits rather than merely agreeing with them.
	p := filepath.Join(t.TempDir(), "status")
	if err := os.WriteFile(p, []byte("CapEff:\t000001ffffffffff\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldS := procSelfStatus
	procSelfStatus = p
	t.Cleanup(func() { procSelfStatus = oldS })

	writeUIDMap(t, "         0       1000          1\n") // rootless container
	bpf, netAdmin, known := probeCaps()
	if known || bpf || netAdmin {
		t.Fatalf("probeCaps in a user namespace = (%v,%v,known=%v), want all false", bpf, netAdmin, known)
	}

	writeUIDMap(t, "         0          0 4294967295\n") // initial namespace
	bpf, netAdmin, known = probeCaps()
	if !known || !bpf || !netAdmin {
		t.Fatalf("probeCaps in the initial namespace = (%v,%v,known=%v), want all true", bpf, netAdmin, known)
	}
}

func TestNamespacedCapsAreNotReadyAndSayWhy(t *testing.T) {
	h := Host{
		GOOS: "linux", HasSystemd: true, EUID: 0,
		CapsKnown: false, CapsNamespaced: true,
		BPFLSM: runner.LSMActive,
	}
	r := Evaluate(h)
	if r.Native.Status == StatusReady {
		t.Fatal("namespaced caps must never yield a ready native runtime")
	}
	joined := strings.Join(r.Native.Issues, " ")
	if !strings.Contains(joined, "user namespace") {
		t.Fatalf("issue must name the user namespace as the reason, got: %q", joined)
	}
	if strings.Contains(joined, "setcap cap_bpf,cap_net_admin+ep)") && !strings.Contains(joined, "setcap cannot help") {
		t.Fatal("must not prescribe setcap as a remedy inside a namespace")
	}
	var found bool
	for _, u := range r.Unchecked {
		if u.Name == "capabilities" && strings.Contains(u.Reason, "user namespace") {
			found = true
		}
	}
	if !found {
		t.Fatal("unchecked must record capabilities as unestablished, naming the namespace")
	}
}
