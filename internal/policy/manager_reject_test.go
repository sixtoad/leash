package policy

import (
	"fmt"
	"strings"
	"testing"

	"github.com/strongdm/leash/internal/lsm"
	"github.com/strongdm/leash/internal/proxy"
)

func tooManyOpenRules(n int) *lsm.PolicySet {
	set := &lsm.PolicySet{}
	for i := 0; i < n; i++ {
		var r lsm.PolicyRule
		r.Action = lsm.PolicyAllow
		r.Operation = lsm.OpOpen
		p := fmt.Sprintf("/f%d", i)
		copy(r.Path[:], p)
		r.PathLen = int32(len(p))
		set.Open = append(set.Open, r)
	}
	return set
}

// A rule set the kernel would reject must leave everything as it was: the
// manager's layers, the LSM, and the proxy (issue #162: a bad update must keep
// the previous policy, never drop to a partial or empty one).
func TestManagerRejectsKernelInvalidUpdateAndKeepsPrevious(t *testing.T) {
	// A cgroup path makes the LSM enforce kernel limits; validation fails before
	// any BPF work, so this runs unprivileged on any OS.
	lsmMgr := lsm.NewLSMManager("/sys/fs/cgroup/leash-test-not-real", nil, true)
	proxyCalls := 0
	m := NewManager(lsmMgr, func(*lsm.PolicySet, []proxy.HeaderRewriteRule) { proxyCalls++ })

	bad := tooManyOpenRules(lsm.MaxPolicyRules + 1)
	err := m.UpdateFileRules(bad, []proxy.HeaderRewriteRule{{Host: "h", Header: "X", Value: "v"}})
	if err == nil || !strings.Contains(err.Error(), "previous policy kept") {
		t.Fatalf("want the update refused, got %v", err)
	}
	if proxyCalls != 0 {
		t.Fatalf("the proxy must not receive a refused policy (calls=%d)", proxyCalls)
	}
	fileLSM, fileHTTP, _, _ := m.Snapshot()
	if len(fileLSM.Open) != 0 || len(fileHTTP) != 0 {
		t.Fatalf("file layer changed by a refused update: open=%d http=%d", len(fileLSM.Open), len(fileHTTP))
	}

	if err := m.SetRuntimeRules(bad, nil); err == nil {
		t.Fatal("runtime layer must refuse a kernel-invalid set too")
	}
	if _, _, rt, _ := m.Snapshot(); len(rt.Open) != 0 {
		t.Fatalf("runtime layer changed by a refused update: open=%d", len(rt.Open))
	}
}

// Without a scopable cgroup (degraded proxy-only) the kernel is not
// programmed, so its limits do not gate updates.
func TestManagerSkipsKernelLimitsWithoutCgroup(t *testing.T) {
	m := NewManager(lsm.NewLSMManager("", nil, false), nil)
	if err := m.UpdateFileRules(tooManyOpenRules(lsm.MaxPolicyRules+1), nil); err != nil {
		t.Fatalf("no-cgroup manager must not apply kernel limits: %v", err)
	}
}
