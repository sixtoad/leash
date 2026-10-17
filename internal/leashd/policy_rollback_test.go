package leashd

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	cedarutil "github.com/strongdm/leash/internal/cedar"
	"github.com/strongdm/leash/internal/enforcerd"
	"github.com/strongdm/leash/internal/lsm"
	"github.com/strongdm/leash/internal/policy"
)

// modelKernel is a transactional local LSM: a failed update keeps the
// previous policy (state), as *lsm.LSMManager does; with rollbackFails it
// reports that its own rollback failed and holds deny-all.
type modelKernel struct {
	mu            sync.Mutex
	state         *lsm.PolicySet
	fail          bool
	rollbackFails bool
	failedClosed  bool
}

func (k *modelKernel) UpdateRuntimeRules(ps *lsm.PolicySet) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.failedClosed {
		return &lsm.KernelApplyError{Module: "every", Err: lsm.ErrKernelFailedClosed, FailedClosed: true}
	}
	if k.fail {
		if k.rollbackFails {
			k.state, k.failedClosed = &lsm.PolicySet{}, true
			return &lsm.KernelApplyError{Module: "exec", Err: errors.New("exec_policy_rules: no space left on device"), RollbackErr: errors.New("file-open map write"), FailedClosed: true}
		}
		return &lsm.KernelApplyError{Module: "exec", Err: errors.New("exec_policy_rules: no space left on device")}
	}
	k.state = ps
	return nil
}

func (k *modelKernel) EnforcesKernelPolicy() bool { return true }

func (k *modelKernel) FailClosed() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.state, k.failedClosed = &lsm.PolicySet{}, true
	return nil
}

func (k *modelKernel) set(fail bool) {
	k.mu.Lock()
	k.fail = fail
	k.mu.Unlock()
}

func (k *modelKernel) enforced() *lsm.PolicySet {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.state
}

func samePolicy(a, b *lsm.PolicySet) bool {
	return a != nil && b != nil && len(a.Open) == len(b.Open) && len(a.Exec) == len(b.Exec) && len(a.Connect) == len(b.Connect) &&
		(len(a.Open) == 0 || a.Open[0] == b.Open[0])
}

func apiNextPolicy() string {
	return policy.DefaultCedar() + "\npermit (principal, action == Action::\"NetworkConnect\", resource) when { resource in [Host::\"example.com\"] };\n"
}

// The policy API's apply paths return an error naming the component that
// failed, persist nothing, and leave the previous policy in effect in the
// kernel and in userspace.
func TestPolicyAPIApplyFailureKeepsPreviousPolicy(t *testing.T) {
	tmpDir := setupLeashDirs(t)
	policyPath := filepath.Join(tmpDir, "policies.cedar")

	kernel := &modelKernel{}
	var published []string
	mgr := policy.NewManagerWithKernel(kernel, func(c *cedarutil.Compilation) error {
		published = append(published, c.StrictText)
		return nil
	})
	api := newPolicyAPI(mgr, policyPath, nil, nil, nil)
	mux := http.NewServeMux()
	api.register(mux)

	post := func(path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(body))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		return w
	}
	if w := post("/api/policies", policy.DefaultCedar()); w.Code != http.StatusOK {
		t.Fatalf("seed POST = %d: %s", w.Code, w.Body.String())
	}
	prev := mgr.Active()
	prevRuntime, _ := loadCedarRuntime()

	kernel.set(true)
	w := post("/api/policies", apiNextPolicy())
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "kernel LSM (exec)") || !strings.Contains(w.Body.String(), "previous policy is still in effect") {
		t.Fatalf("POST with a failing exec LSM = %d %s, want 500 naming the exec LSM", w.Code, w.Body.String())
	}
	if mgr.Active() != prev {
		t.Fatal("manager switched to a policy that was not applied")
	}
	if !samePolicy(kernel.enforced(), prev.Policies) {
		t.Fatal("kernel model is not on the previous policy")
	}
	if published[len(published)-1] != prev.StrictText {
		t.Fatal("userspace is not on the previous policy")
	}
	if got, _ := loadCedarRuntime(); !bytes.Equal(got, prevRuntime) {
		t.Fatal("a policy that was not applied was persisted as the runtime policy")
	}

	// The persist path (file layer) behaves the same.
	w = post("/api/policies/persist?force=1", apiNextPolicy())
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "kernel LSM (exec)") {
		t.Fatalf("persist with a failing exec LSM = %d %s", w.Code, w.Body.String())
	}
	if _, err := os.Stat(policyPath); !os.IsNotExist(err) {
		t.Fatalf("policy file written for a policy that was not applied (stat: %v)", err)
	}
	if mgr.Active() != prev || mgr.FailedClosed() {
		t.Fatal("persist failure changed the active policy")
	}
}

// A file-watcher reload that fails to apply keeps the previous policy
// everywhere (the manager rolled back; nothing is re-applied on top).
func TestApplyFileReloadKeepsPreviousOnApplyFailure(t *testing.T) {
	kernel := &modelKernel{}
	var published int
	mgr := policy.NewManagerWithKernel(kernel, func(*cedarutil.Compilation) error { published++; return nil })
	first, err := cedarutil.CompileString("leash.cedar", remotePolicy)
	if err != nil {
		t.Fatal(err)
	}
	if err := applyFileReload(mgr, &policy.Config{LSMPolicies: first.Policies}); err != nil {
		t.Fatal(err)
	}
	prev := mgr.Active()
	n := published

	kernel.set(true)
	next, err := cedarutil.CompileString("leash.cedar", policy.DefaultCedar())
	if err != nil {
		t.Fatal(err)
	}
	err = applyFileReload(mgr, &policy.Config{LSMPolicies: next.Policies, HTTPRewrites: next.HTTPRules})
	if !errors.Is(err, policy.ErrNotApplied) || !strings.Contains(err.Error(), "kernel LSM (exec)") {
		t.Fatalf("reload = %v, want ErrNotApplied naming the exec LSM", err)
	}
	if mgr.Active() != prev || !samePolicy(kernel.enforced(), prev.Policies) || published != n {
		t.Fatal("a failed reload changed the manager, the kernel or userspace")
	}
}

// The enforcer daemon refusing an update makes the manager send the previous
// policy again; refusing that too fails closed.
func TestRemoteKernelUpdateFailureRollsBack(t *testing.T) {
	k, d, _ := newTestRemote(t)
	mgr := policy.NewManager(lsm.NewLSMManager("", nil, true), nil)
	mgr.SetRemoteKernel(k.update)
	var closures []*policy.ApplyError
	mgr.SetFailClosedHandler(func(e *policy.ApplyError) { closures = append(closures, e) })

	first, _ := cedarutil.CompileString("leash.cedar", remotePolicy)
	if err := mgr.UpdateFileRules(first.Policies, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := k.attach(mgr.Active); err != nil {
		t.Fatal(err)
	}
	prev := mgr.Active()

	next, _ := cedarutil.CompileString("leash.cedar", remotePolicy+"\n@leash_semantics(\"cedar\")\nforbid (principal, action == Action::\"FileOpenReadOnly\", resource == File::\"/etc/hostname\");")
	d.setRefuse(func(r enforcerd.Request) string {
		if r.Op == enforcerd.OpUpdate && r.Policy != prev.StrictText {
			return "update the kernel tables: connect LSM: map write failed; the previous kernel policy was restored"
		}
		return ""
	})
	err := mgr.UpdateFileRules(next.Policies, nil)
	if !errors.Is(err, policy.ErrNotApplied) || !strings.Contains(err.Error(), policy.ComponentRemoteKernel) {
		t.Fatalf("update = %v, want ErrNotApplied naming the enforcer daemon", err)
	}
	reqs := d.requests()
	if last := reqs[len(reqs)-1]; last.Op != enforcerd.OpUpdate || last.Policy != prev.StrictText {
		t.Fatalf("previous policy not re-sent to the daemon: last request %+v", last)
	}
	if mgr.Active() != prev {
		t.Fatal("manager switched although the daemon refused")
	}

	// Refusing the rollback too fails closed: deny-all is sent and the
	// handler (leashd: stop the workload) runs.
	d.setRefuse(func(r enforcerd.Request) string {
		if r.Op == enforcerd.OpUpdate && !strings.Contains(r.Policy, "forbid (principal, action, resource)") {
			return "worker gone"
		}
		return ""
	})
	err = mgr.UpdateFileRules(next.Policies, nil)
	if !errors.Is(err, policy.ErrFailedClosed) || len(closures) != 1 {
		t.Fatalf("update = %v (handler ran %d times), want fail-closed", err, len(closures))
	}
	reqs = d.requests()
	if last := reqs[len(reqs)-1]; !strings.Contains(last.Policy, "forbid (principal, action, resource)") {
		t.Fatalf("deny-all not sent to the daemon: last request %+v", last)
	}
}

func TestPolicyFailedClosedStopsWorkload(t *testing.T) {
	origKill, origExit, origDelay := killWorkloadCgroup, exitLeashd, failClosedExitDelay
	t.Cleanup(func() { killWorkloadCgroup, exitLeashd, failClosedExitDelay = origKill, origExit, origDelay })
	failClosedExitDelay = 0

	cases := []struct {
		name     string
		cgroup   string
		remote   bool
		killErr  error
		wantKill bool
		wantExit bool
	}{
		{"local, workload stopped", "/sys/fs/cgroup/leash/w", false, nil, true, true},
		// leashd holds the deny-all programs: exiting would detach them.
		{"local, stop failed", "/sys/fs/cgroup/leash/w", false, errors.New("permission denied"), true, false},
		// The rootless watcher kills the target once the leash container stops.
		{"enforcer daemon, stop failed", "/sys/fs/cgroup/user.slice/w", true, errors.New("permission denied"), true, true},
		{"no cgroup", "", false, nil, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var killed []string
			killWorkloadCgroup = func(p string) error { killed = append(killed, p); return tc.killErr }
			exited := make(chan int, 1)
			exitLeashd = func(code int) { exited <- code }

			rt := &runtimeState{cfg: &runtimeConfig{CgroupPath: tc.cgroup}}
			if tc.remote {
				rt.remote = &remoteKernel{}
			}
			kernel := &modelKernel{fail: true, rollbackFails: true}
			mgr := policy.NewManagerWithKernel(kernel, nil)
			mgr.SetFailClosedHandler(rt.policyFailedClosed)
			err := mgr.UpdateFileRules(&lsm.PolicySet{}, nil)
			if !errors.Is(err, policy.ErrFailedClosed) {
				t.Fatalf("err = %v", err)
			}
			if got := len(killed) == 1 && killed[0] == tc.cgroup; got != tc.wantKill {
				t.Fatalf("killed %v, want kill=%v of %q", killed, tc.wantKill, tc.cgroup)
			}
			select {
			case code := <-exited:
				if !tc.wantExit || code != 1 {
					t.Fatalf("exit(%d), want exit=%v", code, tc.wantExit)
				}
			case <-time.After(300 * time.Millisecond):
				if tc.wantExit {
					t.Fatal("leashd did not exit")
				}
			}
			if !samePolicy(kernel.enforced(), &lsm.PolicySet{}) {
				t.Fatal("kernel not deny-all")
			}
		})
	}
}
