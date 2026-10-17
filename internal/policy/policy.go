package policy

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/strongdm/leash/internal/cedar"
	"github.com/strongdm/leash/internal/lsm"
	"github.com/strongdm/leash/internal/proxy"
)

// Config is the parsed policy content split for different subsystems.
type Config struct {
	// Compilation is the compiled file: strict Cedar, engine, kernel tables.
	Compilation  *cedar.Compilation
	LSMPolicies  *lsm.PolicySet
	HTTPRewrites []proxy.HeaderRewriteRule
	Cedar        string
	Path         string
	lastModTime  time.Time
}

// Parse reads a Cedar policy file and returns combined Config including LSM and http.rewrite rules.
func Parse(path string) (*Config, error) {
	compilation, err := cedar.CompileFile(path)
	if err != nil {
		return nil, err
	}

	stat, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to stat Cedar policy file: %w", err)
	}

	return &Config{
		Compilation:  compilation,
		LSMPolicies:  compilation.Policies,
		HTTPRewrites: compilation.HTTPRules,
		Cedar:        compilation.Cedar,
		Path:         path,
		lastModTime:  stat.ModTime(),
	}, nil
}

// WatchCedar polls the Cedar file and invokes onUpdate when a new valid
// configuration is available. When compilation fails, onError receives the
// structured Cedar error while the previous configuration remains active.
func WatchCedar(path string, interval time.Duration, onUpdate func(*Config), onError func(*cedar.ErrorDetail)) (func(), error) {
	stat, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to stat Cedar policy file: %w", err)
	}

	stop := make(chan struct{})
	ticker := time.NewTicker(interval)

	go func(initialModTime time.Time) {
		defer ticker.Stop()
		// Track the last successful mod time separately so partial writes keep retrying until a valid config is parsed.
		lastSuccessModTime := initialModTime
		var lastErrorModTime time.Time

		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				info, statErr := os.Stat(path)
				if statErr != nil {
					if onError != nil {
						onError(&cedar.ErrorDetail{
							Summary:    "failed to stat Cedar policy file",
							Message:    fmt.Sprintf("failed to stat Cedar policy file %q: %v", path, statErr),
							File:       path,
							Suggestion: "Ensure the Cedar file remains accessible to the leash daemon.",
							Code:       "CEDAR_IO",
							Raw:        statErr,
						})
					}
					continue
				}
				if !info.ModTime().After(lastSuccessModTime) {
					continue
				}

				cfg, parseErr := Parse(path)
				if parseErr != nil {
					var detail *cedar.ErrorDetail
					if errors.As(parseErr, &detail) {
						if onError != nil && !info.ModTime().Equal(lastErrorModTime) {
							onError(detail)
						}
					} else if onError != nil && !info.ModTime().Equal(lastErrorModTime) {
						onError(&cedar.ErrorDetail{
							Summary:    "failed to parse Cedar policy",
							Message:    fmt.Sprintf("failed to parse Cedar policy %q: %v", path, parseErr),
							File:       path,
							Suggestion: "Review the Cedar file and correct the reported error.",
							Code:       "CEDAR_PARSE",
							Raw:        parseErr,
						})
					}
					lastErrorModTime = info.ModTime()
					continue
				}

				cfg.lastModTime = info.ModTime()
				lastSuccessModTime = info.ModTime()
				lastErrorModTime = time.Time{}
				if onUpdate != nil {
					onUpdate(cfg)
				}
			}
		}
	}(stat.ModTime())

	cancel := func() { close(stop) }
	return cancel, nil
}

// ParseHTTPRuleString parses an HTTP rewrite rule string into a HeaderRewriteRule
func ParseHTTPRuleString(ruleStr string) (*proxy.HeaderRewriteRule, error) {
	// Parse: "allow http.rewrite <host> header:<header>:<value>"
	parts := strings.Fields(ruleStr)
	if len(parts) < 4 {
		return nil, fmt.Errorf("invalid HTTP rewrite rule format")
	}

	if parts[0] != "allow" || parts[1] != "http.rewrite" {
		return nil, fmt.Errorf("invalid HTTP rewrite rule format")
	}

	host := parts[2]
	headerTok := parts[3]

	if !strings.HasPrefix(headerTok, "header:") {
		return nil, fmt.Errorf("invalid header format")
	}

	headerTok = strings.TrimPrefix(headerTok, "header:")
	hv := strings.SplitN(headerTok, ":", 2)
	if len(hv) != 2 {
		return nil, fmt.Errorf("invalid header format")
	}

	headerName := strings.TrimSpace(hv[0])
	headerValue := strings.TrimSpace(hv[1])

	// Handle multi-word values
	if len(parts) > 4 {
		headerValue += " " + strings.Join(parts[4:], " ")
	}

	return &proxy.HeaderRewriteRule{
		Host:   host,
		Header: headerName,
		Value:  headerValue,
	}, nil
}

// ErrCompile marks a policy change that does not compile: the layers merge
// into a policy that fails the legacy rewrite, the engine or the kernel
// compiler (#142). Nothing of such a change is applied.
var ErrCompile = errors.New("policy does not compile")

// ErrRejected marks a policy change refused before it was committed because
// the kernel would not accept it (#162). Like ErrCompile, nothing of it is
// applied: the previous policy stays active everywhere.
var ErrRejected = errors.New("policy rejected, previous policy kept")

// ErrNotApplied marks a policy change that failed while it was being applied
// (a kernel module, the enforcer daemon or the userspace publish) and was
// rolled back: the previous policy is still in effect everywhere. The error
// is an *ApplyError naming the component.
var ErrNotApplied = errors.New("policy not applied, previous policy restored")

// ErrFailedClosed marks a change whose apply failed and whose rollback failed
// too: enforcement was set to deny-all in the kernel and in userspace, and
// every later change is refused. The workload must be stopped.
var ErrFailedClosed = errors.New("policy enforcement failed closed (deny-all)")

// Component names used in ApplyError.
const (
	ComponentRemoteKernel = "enforcer daemon"
	ComponentPublish      = "userspace policy publish (proxy, MCP, authz)"
)

// ApplyError reports a policy change that failed in Component while it was
// being applied. Unless FailedClosed, every component was put back on the
// previous policy. With FailedClosed, restoring it failed (RollbackErr) and
// enforcement was set to deny-all instead.
type ApplyError struct {
	Component    string
	Err          error
	RollbackErr  error
	FailedClosed bool
}

func (e *ApplyError) Error() string {
	msg := fmt.Sprintf("policy not applied: %s failed: %v", e.Component, e.Err)
	if !e.FailedClosed {
		return msg + "; the previous policy is still in effect"
	}
	if e.RollbackErr != nil {
		msg += fmt.Sprintf("; restoring the previous policy failed (%v)", e.RollbackErr)
	}
	return msg + "; enforcement failed closed (deny-all)"
}

func (e *ApplyError) Unwrap() []error {
	if e.FailedClosed {
		return []error{ErrFailedClosed, e.Err}
	}
	return []error{ErrNotApplied, e.Err}
}

// Kernel is the local eBPF LSM as the manager drives it (*lsm.LSMManager).
// UpdateRuntimeRules must be transactional itself: on error the kernel is on
// the previous policy, or deny-all when the error is an
// *lsm.KernelApplyError with FailedClosed set.
type Kernel interface {
	UpdateRuntimeRules(*lsm.PolicySet) error
	EnforcesKernelPolicy() bool
	FailClosed() error
}

// Manager holds the policy layers (the file and the runtime overlay) as
// Cedar and keeps one active policy compiled from them (#142): the legacy
// layers are rewritten to strict Cedar together, the strict layers are added
// as written, and one engine and one set of kernel tables are built from the
// result. Every change recompiles the merge; a change that does not compile
// is rejected with ErrCompile and the previous policy stays active.
//
// Applying a change is a transaction (#193): the kernel (local LSM, then the
// enforcer daemon) is programmed first, then userspace (proxy, MCP, authz)
// is switched, and only then is the change committed. A failure at any step
// rolls every component back to the previous policy and returns an
// *ApplyError naming the component. If that rollback fails, enforcement
// fails closed: deny-all in the kernel and in userspace, the fail-closed
// handler runs (leashd stops the workload), and later changes are refused.
type Manager struct {
	fileRules        *lsm.PolicySet
	fileHTTPRules    []proxy.HeaderRewriteRule
	runtimeRules     *lsm.PolicySet
	runtimeHTTPRules []proxy.HeaderRewriteRule
	runtimeOnly      bool // when true, active rules are runtime-only (ignore file layer)
	active           *cedar.Compilation
	failedClosed     bool
	lastRewrite      string
	lastWarnings     string
	runtimeMutex     sync.RWMutex

	// applyMutex orders changes: compile, apply and commit happen as one
	// step, so subsystems see policy changes in order.
	applyMutex sync.Mutex

	// Subsystem references for live updates
	kernel  Kernel
	publish func(*cedar.Compilation) error // switches userspace to a policy

	// remoteKernel, when set, programs the kernel through the rootless
	// enforcer daemon instead of a local kernel (docs/ROOTLESS.md). It
	// receives every newly active policy; an error is an LSM update failure.
	remoteKernel func(*cedar.Compilation) error

	// onFailClosed runs once when enforcement fails closed.
	onFailClosed func(*ApplyError)

	// denyAll is the fail-closed policy (denyAllCedar).
	denyAll *cedar.Compilation
}

// SetRemoteKernel routes kernel updates to f (the enforcer daemon client).
// Kernel limits are then validated before every change, as with a local
// LSM. Call it before the first policy change.
func (m *Manager) SetRemoteKernel(f func(*cedar.Compilation) error) {
	m.applyMutex.Lock()
	defer m.applyMutex.Unlock()
	m.remoteKernel = f
}

// SetFailClosedHandler sets f to run when a change and its rollback both
// failed and enforcement was set to deny-all. f must stop the workload; it
// runs with the manager's apply lock held and must not change the policy.
func (m *Manager) SetFailClosedHandler(f func(*ApplyError)) {
	m.applyMutex.Lock()
	defer m.applyMutex.Unlock()
	m.onFailClosed = f
}

// NewManager creates a new policy manager. onChange receives every newly
// active policy (kernel tables, engine, HTTP rewrites), in order.
func NewManager(lsmManager *lsm.LSMManager, onChange func(active *cedar.Compilation)) *Manager {
	var kernel Kernel
	if lsmManager != nil {
		kernel = lsmManager
	}
	var publish func(*cedar.Compilation) error
	if onChange != nil {
		publish = func(c *cedar.Compilation) error {
			onChange(c)
			return nil
		}
	}
	return NewManagerWithKernel(kernel, publish)
}

// NewManagerWithKernel creates a policy manager over kernel (nil: none) and
// publish, which switches userspace (proxy, MCP, authz) to a policy and may
// fail. Both receive every newly active policy, in order.
func NewManagerWithKernel(kernel Kernel, publish func(*cedar.Compilation) error) *Manager {
	m := &Manager{
		fileRules:        &lsm.PolicySet{},
		fileHTTPRules:    []proxy.HeaderRewriteRule{},
		runtimeRules:     &lsm.PolicySet{},
		runtimeHTTPRules: []proxy.HeaderRewriteRule{},
		kernel:           kernel,
		publish:          publish,
	}
	active, err := m.compile(m.fileRules, m.fileHTTPRules, m.runtimeRules, m.runtimeHTTPRules, false)
	if err != nil {
		panic(fmt.Sprintf("policy: the empty policy does not compile: %v", err))
	}
	m.active = active
	denyAll, err := cedar.CompileLayers([]cedar.Layer{{Source: &lsm.PolicySource{Name: "deny-all.cedar", Text: denyAllCedar}}})
	if err != nil {
		panic(fmt.Sprintf("policy: the deny-all policy does not compile: %v", err))
	}
	m.denyAll = denyAll
	return m
}

// denyAllCedar is the fail-closed policy: one strict forbid of everything,
// so the engine denies every request (MCP included, which the empty legacy
// policy allows) and the kernel tables deny every file open, exec, mutation
// and connect.
const denyAllCedar = `@leash_semantics("cedar")
forbid (principal, action, resource);
`

// PolicySetCompat is a type alias to expose *lsm.PolicySet to external packages with minimal coupling.
type PolicySetCompat = lsm.PolicySet

func (m *Manager) compile(file *lsm.PolicySet, fileHTTP []proxy.HeaderRewriteRule, runtime *lsm.PolicySet, runtimeHTTP []proxy.HeaderRewriteRule, runtimeOnly bool) (*cedar.Compilation, error) {
	var layers []cedar.Layer
	if !runtimeOnly {
		layers = append(layers, cedar.LayerOf(file, fileHTTP))
	}
	layers = append(layers, cedar.LayerOf(runtime, runtimeHTTP))
	active, err := cedar.CompileLayers(layers)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCompile, err)
	}
	return active, nil
}

// change compiles the layers with mutate applied and, when they compile,
// applies them everywhere and commits them; see Manager.
func (m *Manager) change(mutate func(file, runtime **lsm.PolicySet, fileHTTP, runtimeHTTP *[]proxy.HeaderRewriteRule, runtimeOnly *bool)) error {
	m.applyMutex.Lock()
	defer m.applyMutex.Unlock()

	m.runtimeMutex.RLock()
	file, runtime := m.fileRules, m.runtimeRules
	fileHTTP, runtimeHTTP := m.fileHTTPRules, m.runtimeHTTPRules
	runtimeOnly := m.runtimeOnly
	prev := m.active
	failedClosed := m.failedClosed
	m.runtimeMutex.RUnlock()

	if failedClosed {
		return fmt.Errorf("%w: refusing policy changes until leash restarts", ErrFailedClosed)
	}

	mutate(&file, &runtime, &fileHTTP, &runtimeHTTP, &runtimeOnly)
	active, err := m.compile(file, fileHTTP, runtime, runtimeHTTP, runtimeOnly)
	if err != nil {
		return err
	}
	// A set the kernel would reject is refused before anything changes: the
	// previous rules stay active in the manager, the LSM and the proxy (#162).
	if err := m.validateKernelLimits(active); err != nil {
		return err
	}

	if err := m.apply(prev, active); err != nil {
		return err
	}

	m.runtimeMutex.Lock()
	m.fileRules, m.runtimeRules = file, runtime
	m.fileHTTPRules, m.runtimeHTTPRules = fileHTTP, runtimeHTTP
	m.runtimeOnly = runtimeOnly
	m.active = active
	m.runtimeMutex.Unlock()
	return nil
}

// GetActiveRules returns the active kernel tables and HTTP rewrites.
func (m *Manager) GetActiveRules() (*lsm.PolicySet, []proxy.HeaderRewriteRule) {
	m.runtimeMutex.RLock()
	defer m.runtimeMutex.RUnlock()
	return m.active.Policies.Clone(), append([]proxy.HeaderRewriteRule(nil), m.active.HTTPRules...)
}

// Active returns the active policy: the merged strict Cedar, its engine and
// kernel tables. It is immutable. After enforcement failed closed it is the
// deny-all policy.
func (m *Manager) Active() *cedar.Compilation {
	m.runtimeMutex.RLock()
	defer m.runtimeMutex.RUnlock()
	return m.active
}

// FailedClosed reports whether enforcement failed closed (see Manager).
func (m *Manager) FailedClosed() bool {
	m.runtimeMutex.RLock()
	defer m.runtimeMutex.RUnlock()
	return m.failedClosed
}

// UpdateFileRules replaces the file layer. A PolicySet compiled from Cedar
// (cedar.CompileString) carries its source; one built in code is a legacy
// IR layer.
func (m *Manager) UpdateFileRules(newFileRules *lsm.PolicySet, newHTTPRules []proxy.HeaderRewriteRule) error {
	return m.change(func(file, _ **lsm.PolicySet, fileHTTP, _ *[]proxy.HeaderRewriteRule, _ *bool) {
		*file = newFileRules.Clone()
		*fileHTTP = append([]proxy.HeaderRewriteRule(nil), newHTTPRules...)
	})
}

// SetRuntimeRules replaces the runtime layer.
func (m *Manager) SetRuntimeRules(newLSM *lsm.PolicySet, newHTTP []proxy.HeaderRewriteRule) error {
	return m.change(func(_, runtime **lsm.PolicySet, _, runtimeHTTP *[]proxy.HeaderRewriteRule, _ *bool) {
		*runtime = newLSM.Clone()
		*runtimeHTTP = append([]proxy.HeaderRewriteRule(nil), newHTTP...)
	})
}

// SetRuntimeOnly toggles whether the Manager should ignore the file layer when
// computing active rules. When enabled, only runtime rules are applied to the
// LSM/proxy; file rules continue to be tracked and exposed via Snapshot() for UI.
func (m *Manager) SetRuntimeOnly(enabled bool) error {
	return m.change(func(_, _ **lsm.PolicySet, _, _ *[]proxy.HeaderRewriteRule, runtimeOnly *bool) {
		*runtimeOnly = enabled
	})
}

// validateKernelLimits checks a compiled policy against the kernel's limits
// before it is committed, so a rejected update never reaches the proxy or
// leaves the LSM modules half-updated. Only meaningful with an LSM to enforce
// them.
func (m *Manager) validateKernelLimits(active *cedar.Compilation) error {
	if active == nil {
		return nil
	}
	if m.remoteKernel == nil && (m.kernel == nil || !m.kernel.EnforcesKernelPolicy()) {
		return nil
	}
	if err := lsm.ValidateKernelPolicyLimits(active.Policies); err != nil {
		return fmt.Errorf("%w: %w", ErrRejected, err)
	}
	return nil
}

// apply switches every component from prev to next: the local kernel, the
// enforcer daemon, then userspace. On a failure it rolls back what changed
// and returns an *ApplyError; if the rollback fails, it fails closed.
func (m *Manager) apply(prev, next *cedar.Compilation) error {
	m.logRewrite(next)

	localApplied := false
	if m.kernel != nil {
		if err := m.kernel.UpdateRuntimeRules(next.Policies.Clone()); err != nil {
			component := "kernel LSM"
			var kerr *lsm.KernelApplyError
			if errors.As(err, &kerr) {
				component = fmt.Sprintf("kernel LSM (%s)", kerr.Module)
				if kerr.FailedClosed {
					// err already describes the kernel's failed rollback.
					return m.failClosed(component, err, nil)
				}
			}
			// The kernel restored its previous policy itself; nothing else
			// was touched.
			return &ApplyError{Component: component, Err: err}
		}
		localApplied = true
	}

	if m.remoteKernel != nil {
		if err := m.remoteKernel(next); err != nil {
			// The daemon's outcome is unknown (a refusal is rolled back by
			// its worker, a timeout or a dropped session may not be), so
			// the previous policy is sent again.
			if rbErr := m.rollbackKernel(prev, localApplied, true); rbErr != nil {
				return m.failClosed(ComponentRemoteKernel, err, rbErr)
			}
			return &ApplyError{Component: ComponentRemoteKernel, Err: err}
		}
	}

	if m.publish != nil {
		if err := m.publish(next); err != nil {
			// The publish may have switched some consumers: switch them all
			// back, and the kernel with them.
			rbErr := m.rollbackKernel(prev, localApplied, m.remoteKernel != nil)
			if pubErr := m.publish(prev); pubErr != nil {
				rbErr = errors.Join(rbErr, fmt.Errorf("%s: %w", ComponentPublish, pubErr))
			}
			if rbErr != nil {
				return m.failClosed(ComponentPublish, err, rbErr)
			}
			return &ApplyError{Component: ComponentPublish, Err: err}
		}
	}
	return nil
}

// rollbackKernel puts the kernel components that took next back on prev.
func (m *Manager) rollbackKernel(prev *cedar.Compilation, local, remote bool) error {
	var errs []error
	if local && m.kernel != nil {
		if err := m.kernel.UpdateRuntimeRules(prev.Policies.Clone()); err != nil {
			errs = append(errs, fmt.Errorf("kernel LSM: %w", err))
		}
	}
	if remote && m.remoteKernel != nil {
		if err := m.remoteKernel(prev); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", ComponentRemoteKernel, err))
		}
	}
	return errors.Join(errs...)
}

// failClosed sets every component to deny-all, marks the manager failed
// closed and runs the fail-closed handler. It returns the ApplyError for the
// change that caused it.
func (m *Manager) failClosed(component string, cause, rollbackErr error) error {
	aerr := &ApplyError{Component: component, Err: cause, RollbackErr: rollbackErr, FailedClosed: true}
	deny := m.denyAll

	var errs []error
	if m.kernel != nil {
		if err := m.kernel.FailClosed(); err != nil {
			errs = append(errs, fmt.Errorf("kernel LSM: %w", err))
		}
	}
	if m.remoteKernel != nil {
		if err := m.remoteKernel(deny); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", ComponentRemoteKernel, err))
		}
	}
	if m.publish != nil {
		if err := m.publish(deny); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", ComponentPublish, err))
		}
	}

	m.runtimeMutex.Lock()
	m.failedClosed = true
	m.active = deny
	m.runtimeMutex.Unlock()

	if err := errors.Join(errs...); err != nil {
		log.Printf("leash: FATAL: setting deny-all failed (%v); only stopping the workload keeps it from running unenforced", err)
	}
	if m.onFailClosed != nil {
		m.onFailClosed(aerr)
	} else {
		log.Printf("leash: FATAL: %v", aerr)
	}
	return aerr
}

// logRewrite logs what the legacy rewrite changed and where the kernel is
// stricter than Cedar, once per distinct result.
func (m *Manager) logRewrite(active *cedar.Compilation) {
	var warnings []string
	for _, w := range active.Warnings {
		warnings = append(warnings, w.String())
	}
	if key := strings.Join(warnings, "\n"); key != m.lastWarnings {
		m.lastWarnings = key
		for _, w := range warnings {
			log.Printf("policy: warning: kernel stricter than Cedar: %s", w)
		}
	}
	if active.Rewrite == nil {
		m.lastRewrite = ""
		return
	}
	lines := active.Rewrite.Summary()
	key := strings.Join(lines, "\n")
	if key == m.lastRewrite {
		return
	}
	m.lastRewrite = key
	log.Printf("policy: legacy Leash semantics rewritten to strict Cedar (%d forbids gained exceptions); run `leash policy migrate` to make it explicit", len(active.Rewrite.Exceptions))
	for _, line := range lines {
		log.Printf("policy: legacy rewrite: %s", line)
	}
}

// Snapshot returns copies of file and runtime rule layers for safe inspection.
func (m *Manager) Snapshot() (fileLSM *lsm.PolicySet, fileHTTP []proxy.HeaderRewriteRule, runtimeLSM *lsm.PolicySet, runtimeHTTP []proxy.HeaderRewriteRule) {
	m.runtimeMutex.RLock()
	defer m.runtimeMutex.RUnlock()
	fl := m.fileRules.Clone()
	rl := m.runtimeRules.Clone()
	fh := append([]proxy.HeaderRewriteRule(nil), m.fileHTTPRules...)
	rh := append([]proxy.HeaderRewriteRule(nil), m.runtimeHTTPRules...)
	return fl, fh, rl, rh
}
