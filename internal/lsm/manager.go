//go:generate bash -c "if [ \"$(uname -s)\" = 'Linux' ]; then command -v bpf2go 1>/dev/null 2>&1 || go install github.com/cilium/ebpf/cmd/bpf2go && bpf2go -cc clang -tags linux lsmOpen bpf/lsm_open.bpf.c -- -I./bpf && bpf2go -cc clang -tags linux lsmExec bpf/lsm_exec.bpf.c -- -I./bpf && bpf2go -cc clang -tags linux lsmConnect bpf/lsm_connect.bpf.c -- -I./bpf; else echo 'Skipping bpf2go in non-Linux build environment'; fi"

package lsm

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

// LSMManager manages multiple LSM programs and handles policy reloading
type LSMManager struct {
	cgroupPath string
	logger     *SharedLogger

	// requireLSM makes an eBPF LSM attach failure fatal instead of degrading to
	// proxy-only enforcement. True unless proxy-only was explicitly allowed.
	requireLSM      bool
	containerRootfs bool

	// Active LSM programs
	openLsm    *OpenLsm
	execLsm    *ExecLsm
	connectLsm *ConnectLsm

	reloadMutex sync.RWMutex
	degradeOnce sync.Once

	// applied is the last policy every module accepted: the rollback target
	// when an update fails partway (nil before the first update, when the
	// target is deny-all). failedClosed is sticky: once a rollback failed and
	// the modules were set to deny-all, no further update is accepted.
	applied      *PolicySet
	failedClosed bool

	// steps, when set (tests), replaces the per-module updaters.
	steps []kernelStep

	// attachFailed records modules whose programs failed to attach under
	// --allow-proxy-only: they are not in the kernel, so updates skip them
	// (their closed maps would only return EBADF).
	attachMu     sync.Mutex
	attachFailed map[string]bool

	// attachWG tracks the initial LSM program attaches so a readiness watcher
	// fires only after ALL of them settle (attached or failed), not the first.
	// trackOnce wires the per-attempt hook lazily; settleWatchOnce guards the
	// single watcher goroutine.
	attachWG        sync.WaitGroup
	trackOnce       sync.Once
	settleWatchOnce sync.Once

	// runWG tracks the attach goroutines for their whole lifetime (attach plus
	// event loop). Each closes its BPF links when it returns, so LoadAndStart
	// waits on it at shutdown to detach the programs before leashd exits.
	runWG sync.WaitGroup
}

// lsmDetachWait bounds how long LoadAndStart waits at shutdown for the attach
// goroutines to close their links. The kernel also detaches them when leashd's
// FDs close on exit, so this only orders the detach; it can never hang shutdown.
var lsmDetachWait = 3 * time.Second

// SetContainerRootfs enables container layered-root compatibility. Native
// sessions intentionally leave it disabled and retain actual-user-home policy.
func (m *LSMManager) SetContainerRootfs(enabled bool) {
	m.containerRootfs = enabled
}

func NewLSMManager(cgroupPath string, logger *SharedLogger, requireLSM bool) *LSMManager {
	return &LSMManager{
		cgroupPath: cgroupPath,
		logger:     logger,
		requireLSM: requireLSM,
	}
}

// handleAttachFailure decides what happens when an eBPF LSM program fails to
// attach (most often because the kernel doesn't have "bpf" as an active LSM).
// Fail-closed is the default (issue #117): unless proxy-only was explicitly
// allowed (--allow-proxy-only / LEASH_ALLOW_PROXY_ONLY) it is fatal. With the
// opt-out, leash degrades to proxy-only (Layer 2, fail-closed) and continues,
// warning loudly once. leashd forces requireLSM in --lsm-only mode (no proxy
// to degrade to), so the non-fatal branch — and its "L7 proxy remains active"
// warning — is only reachable when the proxy is actually running.
func (m *LSMManager) handleAttachFailure(label string, err error) {
	m.attachMu.Lock()
	if m.attachFailed == nil {
		m.attachFailed = map[string]bool{}
	}
	m.attachFailed[label] = true
	m.attachMu.Unlock()
	if m.requireLSM {
		fmt.Fprintf(os.Stderr, "leash: FATAL: %s LSM failed to attach (%v); refusing to run the workload unenforced (%s)\n", label, err, failClosedRemedy)
		os.Exit(1)
	}
	markLayer1Degraded()
	// The attach attempt is counted as settled by the defer in
	// LoadAndAttachBPFWithSetup (fires on failure too), so no Done() here.
	m.degradeOnce.Do(func() {
		fmt.Fprintf(os.Stderr, "leash: WARNING: eBPF LSM enforcement (Layer 1) is unavailable (%s: %v).\n", label, err)
		fmt.Fprintf(os.Stderr, "leash: continuing in degraded proxy-only mode because --allow-proxy-only is set — filesystem/exec/socket policies are NOT enforced; the L7 proxy (Layer 2) remains active and fail-closed.\n")
		fmt.Fprintf(os.Stderr, "leash: enable the bpf LSM (lsm=...,bpf in the kernel cmdline), or drop --allow-proxy-only / LEASH_ALLOW_PROXY_ONLY to make this fatal.\n")
	})
}

// trackAttach registers one pending attach attempt. It lazily wires the
// per-attempt settle hook, so every LoadAndAttachBPF exit (via its defer)
// decrements the group.
func (m *LSMManager) trackAttach() {
	m.trackOnce.Do(func() { onLSMAttached = m.attachWG.Done })
	m.attachWG.Add(1)
}

// StartSettleWatch fires the enforcement-settled hook once every tracked attach
// has settled. Call it after the initial policy load, before LoadAndStart
// blocks. Safe to call more than once.
func (m *LSMManager) StartSettleWatch() {
	m.settleWatchOnce.Do(func() {
		go func() {
			m.attachWG.Wait()
			notifyEnforcementSettled()
		}()
	})
}

func (m *LSMManager) LoadAndStart() error {
	// The shared sticky latch (shutdown.go) rather than a private
	// signal.Notify: a signal already consumed by an attach goroutine's event
	// loop would otherwise leave this wait blocked forever (#143).
	InstallShutdownHandler()

	fmt.Printf("LSM Manager started. Press Ctrl-C to stop.\n")

	<-ShutdownRequested()
	fmt.Printf("Received shutdown signal\n")
	m.waitDetached(lsmDetachWait)
	return nil
}

// goAttach runs one LSM program's attach + event loop in the background,
// tracked by runWG so shutdown can wait for its links to close.
func (m *LSMManager) goAttach(fn func()) {
	m.runWG.Add(1)
	go func() {
		defer m.runWG.Done()
		fn()
	}()
}

// waitDetached waits (bounded) for every attach goroutine to return, i.e. for
// every BPF link to be closed. It reports whether they all returned in time.
func (m *LSMManager) waitDetached(timeout time.Duration) bool {
	done := make(chan struct{})
	go func() {
		m.runWG.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		fmt.Fprintf(os.Stderr, "leash: LSM programs did not detach within %s; exiting anyway (the kernel detaches them when leashd exits)\n", timeout)
		return false
	}
}

// ValidateKernelPolicyLimits checks a policy set against the limits the
// kernel programs enforce (rule counts and byte-for-byte path lengths) without
// changing any state.
func ValidateKernelPolicyLimits(policies *PolicySet) error {
	if policies == nil {
		return nil
	}
	if err := validateOpenPolicyRules(ConvertToFileOpenRules(policies.Open)); err != nil {
		return fmt.Errorf("invalid open policies: %w", err)
	}
	if err := validateExecPolicyRules(ConvertToExecRules(policies.Exec)); err != nil {
		return fmt.Errorf("invalid exec policies: %w", err)
	}
	return nil
}

// The file-open and exec LSMs are always created and attached, like the connect
// LSM (#118, #139). Previously a policy with no file (or no exec) rules never created
// that program, so the whole category was unenforced (fail open) instead of
// taking Cedar's default (deny) -- while removing the last rule from an
// already-attached program did deny. The no-rule default is now derived exactly
// as it is with rules: deny unless the policy explicitly permits the root path
// "/" (rootPathPolicy / execDefaultAllow). The file-open program also carries
// the directory-mutation and link hooks, which are enforced in the same case.
//
// Bootstrapping: the workload's own start (launcher shell, leash helpers, the
// dynamic loader and libraries, runc's /proc access in container mode) runs in
// the governed cgroup, so a policy must permit what the workload needs to start
// in every category, exactly as policies with rules in that category already
// must. The built-in bootstrap policy (no policy file) permits Dir::"/" for
// file open and exec and is unaffected.
func (m *LSMManager) updateOpenLSM(policies *PolicySet) error {
	rules := ConvertToFileOpenRules(policies.Open)
	if !policies.HasOpenPolicies() {
		fmt.Printf("No file open policies found; file open LSM enforces the default (deny unless Dir::\"/\" is explicitly permitted)\n")
		rules = []OpenPolicyRule{}
	}

	if m.openLsm == nil {
		// Create new open LSM
		var err error
		m.openLsm, err = NewOpenLsm(m.cgroupPath, m.logger)
		if err != nil {
			return fmt.Errorf("failed to create file open LSM: %w", err)
		}
		m.openLsm.containerOverlay = m.containerRootfs

		// Load policies and start in background
		if err := m.openLsm.LoadPolicies(rules); err != nil {
			return fmt.Errorf("failed to load open policies: %w", err)
		}

		m.trackAttach()
		m.goAttach(func() {
			if err := m.openLsm.LoadAndAttach(loadLsmOpen); err != nil {
				m.handleAttachFailure("file-open", err)
			}
		})
		return nil
	}

	return m.openLsm.LoadPolicies(rules)
}

func (m *LSMManager) updateExecLSM(policies *PolicySet) error {
	rules := ConvertToExecRules(policies.Exec)
	if !policies.HasExecPolicies() {
		fmt.Printf("No exec policies found; exec LSM enforces the default (deny unless Dir::\"/\" is explicitly permitted)\n")
		rules = []ExecPolicyRule{}
	}

	if m.execLsm == nil {
		var err error
		m.execLsm, err = NewExecLsm(m.cgroupPath, m.logger)
		if err != nil {
			return fmt.Errorf("failed to create exec LSM: %w", err)
		}

		if err := m.execLsm.LoadPolicies(rules); err != nil {
			return fmt.Errorf("failed to load exec policies: %w", err)
		}

		m.trackAttach()
		m.goAttach(func() {
			if err := m.execLsm.LoadAndAttach(loadLsmExec); err != nil {
				m.handleAttachFailure("exec", err)
			}
		})
		return nil
	}

	return m.execLsm.LoadPolicies(rules)
}

// connectDefaultOverride decides the kernel connect LSM's default verdict
// override for a policy set. It is a pure function so the decision can be unit
// tested without a kernel.
//
//   - An explicit default (e.g. `forbid ... Host::"*"`) always wins.
//   - With connect rules present and no explicit default, nil is returned and
//     ConnectLsm.LoadPolicies derives the default from the rules (an allow
//     wildcard `Host::"*"` or an any-destination allow => allow, else deny).
//   - With NO connect rules, the kernel mirrors the proxy's default
//     (ConnectDefaultAllow, which is false unless the policy explicitly
//     permitted network access). A nil override with empty rules makes
//     LoadPolicies fall back to deny.
//
// The connect LSM is always attached (issue #118): a policy that never mentions
// the network must not leave IPv4 egress unenforced.
func connectDefaultOverride(policies *PolicySet) *bool {
	if policies == nil {
		return nil
	}
	if policies.ConnectDefaultExplicit {
		val := policies.ConnectDefaultAllow
		return &val
	}
	if len(policies.Connect) == 0 && policies.ConnectDefaultAllow {
		val := true
		return &val
	}
	return nil
}

// proxyRestricts reports whether the policy restricts traffic that only the
// L7 proxy enforces: an MCP forbid (PolicySet.ProxyRestricted from the
// kernel compiler, or a deny rule in an MCP rule list built in code). A
// packet socket builds its own TCP stream past the proxy's redirect, so such
// a policy keeps packet, raw and SCTP sockets denied
// (ConnectLsm.unaddressedAllowed, #188).
func proxyRestricts(policies *PolicySet) bool {
	if policies == nil {
		return false
	}
	if policies.ProxyRestricted {
		return true
	}
	for _, r := range policies.MCP {
		if r.Action != PolicyAllow {
			return true
		}
	}
	return false
}

func (m *LSMManager) updateConnectLSM(policies *PolicySet) error {
	defaultOverride := connectDefaultOverride(policies)
	rules := ConvertToConnectRules(policies.Connect)
	if !policies.HasConnectPolicies() {
		fmt.Printf("No connect policies found; connect LSM enforces the default (deny unless network is explicitly permitted)\n")
		rules = []ConnectPolicyRule{}
	}

	if m.connectLsm == nil {
		var err error
		m.connectLsm, err = NewConnectLsm(m.cgroupPath, m.logger)
		if err != nil {
			return fmt.Errorf("failed to create connect LSM: %w", err)
		}
		m.connectLsm.proxyRestricted = proxyRestricts(policies)

		if err := m.connectLsm.LoadPolicies(rules, defaultOverride); err != nil {
			return fmt.Errorf("failed to load connect policies: %w", err)
		}

		m.trackAttach()
		m.goAttach(func() {
			if err := m.connectLsm.LoadAndAttach(loadLsmConnect); err != nil {
				m.handleAttachFailure("connect", err)
			}
		})
		return nil
	}

	m.connectLsm.proxyRestricted = proxyRestricts(policies)
	return m.connectLsm.LoadPolicies(rules, defaultOverride)
}

// EnforcesKernelPolicy reports whether UpdateRuntimeRules programs the kernel
// (a scopable cgroup is configured). Without one it is a no-op (degraded
// proxy-only mode), so kernel limits do not apply.
func (m *LSMManager) EnforcesKernelPolicy() bool {
	return m != nil && m.cgroupPath != ""
}

// ErrKernelFailedClosed is returned for every update after the kernel failed
// closed: the modules hold deny-all and the workload is being stopped.
var ErrKernelFailedClosed = errors.New("kernel enforcement failed closed (deny-all); no further policy updates are accepted")

// KernelApplyError reports a kernel policy update that failed in Module. The
// update is never left half-applied: every module was put back on the
// previous policy or, when that rollback failed too (RollbackErr), every
// module was set to deny-all (FailedClosed).
type KernelApplyError struct {
	Module       string
	Err          error
	RollbackErr  error
	FailedClosed bool
}

func (e *KernelApplyError) Error() string {
	msg := fmt.Sprintf("%s LSM: %v", e.Module, e.Err)
	switch {
	case e.RollbackErr != nil:
		msg += fmt.Sprintf("; restoring the previous kernel policy failed (%v): the kernel failed closed (deny-all)", e.RollbackErr)
	case e.FailedClosed:
		msg += "; the kernel failed closed (deny-all)"
	default:
		msg += "; the previous kernel policy was restored"
	}
	return msg
}

func (e *KernelApplyError) Unwrap() error { return e.Err }

// kernelStep updates one LSM module. Steps run in order; a failed step is
// rolled back together with every step before it.
type kernelStep struct {
	module string
	apply  func(*PolicySet) error
}

func (m *LSMManager) kernelSteps() []kernelStep {
	if m.steps != nil {
		return m.steps
	}
	return []kernelStep{
		{"file-open", m.updateOpenLSM},
		{"exec", m.updateExecLSM},
		{"connect", m.updateConnectLSM},
	}
}

func (m *LSMManager) moduleAttachFailed(module string) bool {
	m.attachMu.Lock()
	defer m.attachMu.Unlock()
	return m.attachFailed[module]
}

// UpdateRuntimeRules updates all LSM modules with new rules as one
// transaction. When a module fails, every module already updated, and the
// failed one (which may be half-written), is put back on the last policy that
// was fully applied. If that rollback fails, every module is set to deny-all
// and the manager refuses further updates (fail closed), so the kernel is
// never left more permissive than the last good policy. Failures are
// reported as *KernelApplyError.
func (m *LSMManager) UpdateRuntimeRules(policies *PolicySet) error {
	m.reloadMutex.Lock()
	defer m.reloadMutex.Unlock()

	if m.cgroupPath == "" {
		// Degraded mode: without a scopable cgroup we cannot attach cgroup-scoped
		// BPF-LSM programs (they would govern the whole host, not the target).
		// Skip kernel enforcement entirely; the proxy layer still enforces L7
		// policy. See internal/leashd/runtime.go preFlight and issue #67.
		return nil
	}
	if m.failedClosed {
		return &KernelApplyError{Module: "every", Err: ErrKernelFailedClosed, FailedClosed: true}
	}
	if policies == nil {
		policies = &PolicySet{}
	}

	// Validate every module's kernel limits before touching any of them, so
	// a rule one module would reject cannot leave the others half-updated.
	if err := ValidateKernelPolicyLimits(policies); err != nil {
		return err
	}

	steps := m.kernelSteps()
	for i, step := range steps {
		if m.moduleAttachFailed(step.module) {
			continue
		}
		err := step.apply(policies.Clone())
		if err == nil {
			continue
		}
		kerr := &KernelApplyError{Module: step.module, Err: err}
		if rbErr := m.rollbackLocked(steps[:i+1]); rbErr != nil {
			kerr.RollbackErr = rbErr
			kerr.FailedClosed = true
			_ = m.failClosedLocked()
		}
		return kerr
	}
	m.applied = policies.Clone()
	return nil
}

// rollbackLocked re-applies the last fully applied policy (deny-all before
// the first) to steps, in order. It tries every step and reports each failure.
func (m *LSMManager) rollbackLocked(steps []kernelStep) error {
	target := m.applied
	if target == nil {
		target = &PolicySet{}
	}
	var errs []error
	for _, step := range steps {
		if m.moduleAttachFailed(step.module) {
			continue
		}
		if err := step.apply(target.Clone()); err != nil {
			errs = append(errs, fmt.Errorf("%s LSM: %w", step.module, err))
		}
	}
	return errors.Join(errs...)
}

// FailClosed sets every LSM module to deny-all (an empty policy denies every
// file open, exec and connect) and refuses further updates. Every module is
// tried. The error names the modules that could not be set: their kernel
// state is unknown, so the caller must stop the workload.
func (m *LSMManager) FailClosed() error {
	if m == nil {
		return nil
	}
	m.reloadMutex.Lock()
	defer m.reloadMutex.Unlock()
	if m.cgroupPath == "" {
		return nil
	}
	return m.failClosedLocked()
}

func (m *LSMManager) failClosedLocked() error {
	m.failedClosed = true
	var errs []error
	for _, step := range m.kernelSteps() {
		if m.moduleAttachFailed(step.module) {
			continue
		}
		if err := step.apply(&PolicySet{}); err != nil {
			errs = append(errs, fmt.Errorf("%s LSM: %w", step.module, err))
		}
	}
	if err := errors.Join(errs...); err != nil {
		fmt.Fprintf(os.Stderr, "leash: FATAL: could not set the kernel LSM to deny-all: %v\n", err)
		return err
	}
	fmt.Fprintf(os.Stderr, "leash: FATAL: kernel LSM policy failed closed: every module is set to deny-all\n")
	return nil
}
