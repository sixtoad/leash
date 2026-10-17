package lsm

import (
	"errors"
	"strings"
	"testing"
)

// fakeModule models one LSM module's kernel maps: state is the policy the
// kernel enforces for it ("half:<p>" after a write that failed partway).
type fakeModule struct {
	name  string
	state string
	// fail decides whether the call writing policy p fails, and whether
	// the failed write had already changed the maps (partial).
	fail func(p string) (err error, partial bool)
}

func (f *fakeModule) apply(ps *PolicySet) error {
	p := labelOf(ps)
	if f.fail != nil {
		if err, partial := f.fail(p); err != nil {
			if partial {
				f.state = "half:" + p
			}
			return err
		}
	}
	f.state = p
	return nil
}

func labelOf(ps *PolicySet) string {
	if ps == nil || len(ps.Open) == 0 {
		return "deny-all"
	}
	return string(ps.Open[0].Path[:ps.Open[0].PathLen])
}

func policyNamed(path string) *PolicySet {
	var r PolicyRule
	r.Action, r.Operation = PolicyAllow, OpOpen
	copy(r.Path[:], path)
	r.PathLen = int32(len(path))
	return &PolicySet{Open: []PolicyRule{r}}
}

func newFakeKernel() (*LSMManager, []*fakeModule) {
	mods := []*fakeModule{{name: "file-open"}, {name: "exec"}, {name: "connect"}}
	m := NewLSMManager("/sys/fs/cgroup/test", nil, true)
	for _, mod := range mods {
		m.steps = append(m.steps, kernelStep{mod.name, mod.apply})
	}
	return m, mods
}

func wantStates(t *testing.T, mods []*fakeModule, want string) {
	t.Helper()
	for _, mod := range mods {
		if mod.state != want {
			t.Errorf("%s LSM enforces %q, want %q", mod.name, mod.state, want)
		}
	}
}

// A failure in any module, including a map write that failed partway, puts
// every module back on the last fully applied policy.
func TestUpdateRuntimeRulesRollsBackEveryModule(t *testing.T) {
	for _, failing := range []string{"file-open", "exec", "connect"} {
		for _, partial := range []bool{false, true} {
			name := failing
			if partial {
				name += "/partial-map-write"
			}
			t.Run(name, func(t *testing.T) {
				m, mods := newFakeKernel()
				if err := m.UpdateRuntimeRules(policyNamed("/prev/")); err != nil {
					t.Fatal(err)
				}
				for _, mod := range mods {
					if mod.name == failing {
						mod.fail = func(p string) (error, bool) {
							if p == "/next/" {
								return errors.New("map update: no space left on device"), partial
							}
							return nil, false
						}
					}
				}
				err := m.UpdateRuntimeRules(policyNamed("/next/"))
				var kerr *KernelApplyError
				if !errors.As(err, &kerr) || kerr.Module != failing || kerr.FailedClosed {
					t.Fatalf("err = %v, want a rolled-back KernelApplyError for %s", err, failing)
				}
				if !strings.Contains(err.Error(), failing+" LSM") || !strings.Contains(err.Error(), "previous kernel policy was restored") {
					t.Fatalf("error does not name the module and the rollback: %v", err)
				}
				wantStates(t, mods, "/prev/")

				// The rollback target is still the last good policy.
				for _, mod := range mods {
					mod.fail = nil
				}
				if err := m.UpdateRuntimeRules(policyNamed("/third/")); err != nil {
					t.Fatal(err)
				}
				wantStates(t, mods, "/third/")
			})
		}
	}
}

// Before any policy was applied, the rollback target is deny-all.
func TestUpdateRuntimeRulesFirstApplyRollsBackToDenyAll(t *testing.T) {
	m, mods := newFakeKernel()
	mods[2].fail = func(p string) (error, bool) {
		if p == "/first/" {
			return errors.New("boom"), true
		}
		return nil, false
	}
	if err := m.UpdateRuntimeRules(policyNamed("/first/")); err == nil {
		t.Fatal("want an error")
	}
	wantStates(t, mods, "deny-all")
}

// When the rollback fails too, every module is set to deny-all and later
// updates are refused.
func TestUpdateRuntimeRulesFailsClosedWhenRollbackFails(t *testing.T) {
	m, mods := newFakeKernel()
	if err := m.UpdateRuntimeRules(policyNamed("/prev/")); err != nil {
		t.Fatal(err)
	}
	// exec cannot take the new policy, file-open then cannot restore the old.
	mods[1].fail = func(p string) (error, bool) {
		if p == "/next/" {
			return errors.New("exec map write"), true
		}
		return nil, false
	}
	mods[0].fail = func(p string) (error, bool) {
		if p == "/prev/" {
			return errors.New("open map write during rollback"), true
		}
		return nil, false
	}
	err := m.UpdateRuntimeRules(policyNamed("/next/"))
	var kerr *KernelApplyError
	if !errors.As(err, &kerr) || !kerr.FailedClosed || kerr.RollbackErr == nil || kerr.Module != "exec" {
		t.Fatalf("err = %v, want a failed-closed KernelApplyError for exec", err)
	}
	if !strings.Contains(err.Error(), "deny-all") {
		t.Fatalf("error does not say the kernel failed closed: %v", err)
	}
	wantStates(t, mods, "deny-all")

	for _, mod := range mods {
		mod.fail = nil
	}
	err = m.UpdateRuntimeRules(policyNamed("/after/"))
	if !errors.Is(err, ErrKernelFailedClosed) {
		t.Fatalf("update after fail-closed = %v, want ErrKernelFailedClosed", err)
	}
	wantStates(t, mods, "deny-all")
}

// FailClosed reports a module that cannot be set to deny-all, after trying
// every module.
func TestFailClosedTriesEveryModule(t *testing.T) {
	m, mods := newFakeKernel()
	if err := m.UpdateRuntimeRules(policyNamed("/prev/")); err != nil {
		t.Fatal(err)
	}
	mods[1].fail = func(string) (error, bool) { return errors.New("exec map gone"), false }
	err := m.FailClosed()
	if err == nil || !strings.Contains(err.Error(), "exec LSM") {
		t.Fatalf("FailClosed = %v, want the exec failure", err)
	}
	if mods[0].state != "deny-all" || mods[2].state != "deny-all" || mods[1].state != "/prev/" {
		t.Fatalf("states = %q %q %q", mods[0].state, mods[1].state, mods[2].state)
	}
}

// A module whose programs failed to attach (--allow-proxy-only) is not in
// the kernel: updates skip it rather than failing on its closed maps.
func TestUpdateRuntimeRulesSkipsModulesThatFailedToAttach(t *testing.T) {
	m, mods := newFakeKernel()
	m.requireLSM = false
	m.handleAttachFailure("connect", errors.New("attach refused"))
	mods[2].fail = func(string) (error, bool) { return errors.New("bad file descriptor"), false }
	if err := m.UpdateRuntimeRules(policyNamed("/next/")); err != nil {
		t.Fatalf("update with a detached module: %v", err)
	}
	if mods[0].state != "/next/" || mods[1].state != "/next/" {
		t.Fatalf("attached modules not updated: %q %q", mods[0].state, mods[1].state)
	}
}

// Without a scopable cgroup nothing is programmed, and nothing fails.
func TestFailClosedWithoutCgroupIsNoop(t *testing.T) {
	m := NewLSMManager("", nil, true)
	if err := m.FailClosed(); err != nil {
		t.Fatal(err)
	}
	if err := m.UpdateRuntimeRules(policyNamed("/x/")); err != nil {
		t.Fatal(err)
	}
}
