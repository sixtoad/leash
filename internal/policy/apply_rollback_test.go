package policy

import (
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/strongdm/leash/internal/cedar"
	"github.com/strongdm/leash/internal/lsm"
)

// label names a policy by the paths its open rules allow ("deny-all" when
// none), so the fakes below model what each component enforces.
func label(ps *lsm.PolicySet) string {
	if ps == nil {
		return "deny-all"
	}
	var paths []string
	seen := map[string]bool{}
	for _, r := range ps.Open { // one rule per open mode: name each path once
		if r.Action != lsm.PolicyAllow {
			continue
		}
		if p := string(r.Path[:r.PathLen]); !seen[p] {
			seen[p] = true
			paths = append(paths, p)
		}
	}
	if len(paths) == 0 {
		return "deny-all"
	}
	return strings.Join(paths, ",")
}

func openPolicy(path string) *lsm.PolicySet {
	var r lsm.PolicyRule
	r.Action, r.Operation = lsm.PolicyAllow, lsm.OpOpen
	copy(r.Path[:], path)
	r.PathLen = int32(len(path))
	return &lsm.PolicySet{Open: []lsm.PolicyRule{r}}
}

// fakeKernel is a transactional local LSM (as *lsm.LSMManager is): a failed
// update leaves state on the previous policy, unless failClosed makes it
// report that its own rollback failed, in which case it holds deny-all.
type fakeKernel struct {
	state       string
	fail        func(p string) error
	failClosed  bool
	failClosedN int
}

func (k *fakeKernel) UpdateRuntimeRules(ps *lsm.PolicySet) error {
	p := label(ps)
	if k.fail != nil {
		if err := k.fail(p); err != nil {
			if k.failClosed {
				k.state = "deny-all"
				return &lsm.KernelApplyError{Module: "exec", Err: err, RollbackErr: errors.New("rollback write"), FailedClosed: true}
			}
			return &lsm.KernelApplyError{Module: "exec", Err: err}
		}
	}
	k.state = p
	return nil
}

func (k *fakeKernel) EnforcesKernelPolicy() bool { return true }

func (k *fakeKernel) FailClosed() error {
	k.failClosedN++
	k.state = "deny-all"
	return nil
}

// fakeComponent models the enforcer daemon or the userspace publish: a
// failed call may already have switched part of it (half).
type fakeComponent struct {
	state string
	text  string // the strict Cedar of the last call
	calls []string
	fail  func(p string) error
}

func (c *fakeComponent) apply(comp *cedar.Compilation) error {
	p := label(comp.Policies)
	c.calls = append(c.calls, p)
	c.text = comp.StrictText
	if c.fail != nil {
		if err := c.fail(p); err != nil {
			c.state = "half:" + p
			return err
		}
	}
	c.state = p
	return nil
}

func failOn(policies ...string) func(string) error {
	return func(p string) error {
		for _, f := range policies {
			if p == f {
				return errors.New("injected failure applying " + p)
			}
		}
		return nil
	}
}

type rig struct {
	mgr       *Manager
	kernel    *fakeKernel
	remote    *fakeComponent
	userspace *fakeComponent

	mu       sync.Mutex
	closures []*ApplyError
}

func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{kernel: &fakeKernel{}, remote: &fakeComponent{}, userspace: &fakeComponent{}}
	r.mgr = NewManagerWithKernel(r.kernel, r.userspace.apply)
	r.mgr.SetRemoteKernel(r.remote.apply)
	r.mgr.SetFailClosedHandler(func(e *ApplyError) {
		r.mu.Lock()
		r.closures = append(r.closures, e)
		r.mu.Unlock()
	})
	if err := r.mgr.UpdateFileRules(openPolicy("/prev/"), nil); err != nil {
		t.Fatal(err)
	}
	r.want(t, "/prev/")
	return r
}

// want asserts every component, and the manager, enforce policy p.
func (r *rig) want(t *testing.T, p string) {
	t.Helper()
	if r.kernel.state != p {
		t.Errorf("kernel LSM enforces %q, want %q", r.kernel.state, p)
	}
	if r.remote.state != p {
		t.Errorf("enforcer daemon enforces %q, want %q", r.remote.state, p)
	}
	if r.userspace.state != p {
		t.Errorf("userspace (proxy/MCP/authz) enforces %q, want %q", r.userspace.state, p)
	}
	if got := label(r.mgr.Active().Policies); got != p {
		t.Errorf("manager's active policy is %q, want %q", got, p)
	}
}

func TestApplyFailureRollsBackEveryComponent(t *testing.T) {
	cases := []struct {
		name      string
		inject    func(r *rig)
		component string
	}{
		{"kernel LSM", func(r *rig) { r.kernel.fail = failOn("/next/") }, "kernel LSM (exec)"},
		{"enforcer daemon", func(r *rig) { r.remote.fail = failOn("/next/") }, ComponentRemoteKernel},
		{"userspace publish", func(r *rig) { r.userspace.fail = failOn("/next/") }, ComponentPublish},
	}
	for _, tc := range cases {
		for _, layer := range []string{"file", "runtime"} {
			t.Run(tc.name+"/"+layer, func(t *testing.T) {
				r := newRig(t)
				tc.inject(r)
				var err error
				if layer == "file" {
					err = r.mgr.UpdateFileRules(openPolicy("/next/"), nil)
				} else {
					err = r.mgr.SetRuntimeOnly(true)
					if err != nil {
						t.Fatal(err)
					}
					r.want(t, "deny-all") // runtime-only with an empty runtime layer
					err = r.mgr.SetRuntimeRules(openPolicy("/next/"), nil)
				}
				var aerr *ApplyError
				if !errors.As(err, &aerr) || !errors.Is(err, ErrNotApplied) || errors.Is(err, ErrFailedClosed) {
					t.Fatalf("err = %v, want a rolled-back ApplyError", err)
				}
				if aerr.Component != tc.component || !strings.Contains(err.Error(), tc.component) {
					t.Fatalf("error names %q (%v), want %q", aerr.Component, err, tc.component)
				}
				if layer == "file" {
					r.want(t, "/prev/")
					if file, _, _, _ := r.mgr.Snapshot(); label(file) != "/prev/" {
						t.Fatalf("file layer = %q, want the previous one", label(file))
					}
				} else {
					r.want(t, "deny-all")
					if _, _, rt, _ := r.mgr.Snapshot(); label(rt) != "deny-all" {
						t.Fatalf("runtime layer = %q, want the previous (empty) one", label(rt))
					}
				}
				if len(r.closures) != 0 || r.mgr.FailedClosed() {
					t.Fatal("a successful rollback must not fail closed")
				}

				// The next good change applies normally.
				r.kernel.fail, r.remote.fail, r.userspace.fail = nil, nil, nil
				if err := r.mgr.UpdateFileRules(openPolicy("/third/"), nil); err != nil {
					t.Fatal(err)
				}
				if layer == "file" {
					r.want(t, "/third/")
				}
			})
		}
	}
}

// A component that fails before the userspace switch must never see userspace
// ahead of the kernel: the publish is the last step.
func TestKernelFailureNeverReachesUserspace(t *testing.T) {
	for _, inject := range []func(r *rig){
		func(r *rig) { r.kernel.fail = failOn("/next/") },
		func(r *rig) { r.remote.fail = failOn("/next/") },
	} {
		r := newRig(t)
		inject(r)
		before := len(r.userspace.calls)
		_ = r.mgr.UpdateFileRules(openPolicy("/next/"), nil)
		for _, p := range r.userspace.calls[before:] {
			if p == "/next/" {
				t.Fatal("userspace was switched to a policy the kernel did not take")
			}
		}
	}
}

func TestRollbackFailureFailsClosed(t *testing.T) {
	cases := []struct {
		name      string
		inject    func(r *rig)
		component string
	}{
		// The kernel's own rollback failed: it already holds deny-all.
		{"kernel LSM rollback", func(r *rig) {
			r.kernel.fail, r.kernel.failClosed = failOn("/next/"), true
		}, "kernel LSM (exec)"},
		// The daemon refused the change and then the previous policy.
		{"enforcer daemon rollback", func(r *rig) { r.remote.fail = failOn("/next/", "/prev/") }, ComponentRemoteKernel},
		// The publish failed; then the kernel could not be put back.
		{"kernel rollback after publish", func(r *rig) {
			r.userspace.fail = failOn("/next/")
			r.kernel.fail = failOn("/prev/")
		}, ComponentPublish},
		// The publish failed, and so did re-publishing the previous policy.
		{"userspace rollback", func(r *rig) { r.userspace.fail = failOn("/next/", "/prev/") }, ComponentPublish},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t)
			tc.inject(r)
			err := r.mgr.UpdateFileRules(openPolicy("/next/"), nil)
			var aerr *ApplyError
			if !errors.As(err, &aerr) || !aerr.FailedClosed || !errors.Is(err, ErrFailedClosed) {
				t.Fatalf("err = %v, want a failed-closed ApplyError", err)
			}
			if aerr.Component != tc.component || !strings.Contains(err.Error(), "deny-all") {
				t.Fatalf("error = %v, want component %q and deny-all", err, tc.component)
			}
			r.want(t, "deny-all")
			// Userspace and the daemon got the blanket forbid, which also
			// denies MCP (the empty legacy policy allows it).
			for name, text := range map[string]string{"userspace": r.userspace.text, "enforcer daemon": r.remote.text, "manager": r.mgr.Active().StrictText} {
				if !strings.Contains(text, "forbid (principal, action, resource)") {
					t.Errorf("%s is not on the deny-all policy:\n%s", name, text)
				}
			}
			if !r.mgr.FailedClosed() || len(r.closures) != 1 || r.closures[0] != aerr {
				t.Fatalf("fail-closed handler ran %d times (FailedClosed=%v)", len(r.closures), r.mgr.FailedClosed())
			}
			if r.kernel.failClosedN == 0 {
				t.Fatal("kernel was not told to fail closed")
			}

			// Sticky: nothing else is accepted, and nothing changes.
			r.kernel.fail, r.remote.fail, r.userspace.fail = nil, nil, nil
			if err := r.mgr.UpdateFileRules(openPolicy("/later/"), nil); !errors.Is(err, ErrFailedClosed) {
				t.Fatalf("change after fail-closed = %v, want ErrFailedClosed", err)
			}
			r.want(t, "deny-all")
			if len(r.closures) != 1 {
				t.Fatal("fail-closed handler must run once")
			}
		})
	}
}

// A change refused before it is applied (compile or kernel limits) never
// touches any component; NewManager's onChange cannot fail.
func TestNewManagerOnChangeStillReceivesEveryPolicy(t *testing.T) {
	var got []string
	m := NewManager(nil, func(c *cedar.Compilation) { got = append(got, label(c.Policies)) })
	if err := m.UpdateFileRules(openPolicy("/a/"), nil); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "/a/" {
		t.Fatalf("onChange got %v", got)
	}
}
