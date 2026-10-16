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

// Manager holds the policy layers (the file and the runtime overlay) as
// Cedar and keeps one active policy compiled from them (#142): the legacy
// layers are rewritten to strict Cedar together, the strict layers are added
// as written, and one engine and one set of kernel tables are built from the
// result. Every change recompiles the merge; a change that does not compile
// is rejected with ErrCompile and the previous policy stays active.
type Manager struct {
	fileRules        *lsm.PolicySet
	fileHTTPRules    []proxy.HeaderRewriteRule
	runtimeRules     *lsm.PolicySet
	runtimeHTTPRules []proxy.HeaderRewriteRule
	runtimeOnly      bool // when true, active rules are runtime-only (ignore file layer)
	active           *cedar.Compilation
	lastRewrite      string
	lastWarnings     string
	runtimeMutex     sync.RWMutex

	// applyMutex orders changes: compile, commit and apply happen as one
	// step, so subsystems see policy changes in order.
	applyMutex sync.Mutex

	// Subsystem references for live updates
	lsmManager *lsm.LSMManager
	onChange   func(*cedar.Compilation) // receives every newly active policy
}

// NewManager creates a new policy manager. onChange receives every newly
// active policy (kernel tables, engine, HTTP rewrites), in order.
func NewManager(lsmManager *lsm.LSMManager, onChange func(active *cedar.Compilation)) *Manager {
	m := &Manager{
		fileRules:        &lsm.PolicySet{},
		fileHTTPRules:    []proxy.HeaderRewriteRule{},
		runtimeRules:     &lsm.PolicySet{},
		runtimeHTTPRules: []proxy.HeaderRewriteRule{},
		lsmManager:       lsmManager,
		onChange:         onChange,
	}
	active, err := m.compile(m.fileRules, m.fileHTTPRules, m.runtimeRules, m.runtimeHTTPRules, false)
	if err != nil {
		panic(fmt.Sprintf("policy: the empty policy does not compile: %v", err))
	}
	m.active = active
	return m
}

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
// commits and applies them.
func (m *Manager) change(mutate func(file, runtime **lsm.PolicySet, fileHTTP, runtimeHTTP *[]proxy.HeaderRewriteRule, runtimeOnly *bool)) error {
	m.applyMutex.Lock()
	defer m.applyMutex.Unlock()

	m.runtimeMutex.RLock()
	file, runtime := m.fileRules, m.runtimeRules
	fileHTTP, runtimeHTTP := m.fileHTTPRules, m.runtimeHTTPRules
	runtimeOnly := m.runtimeOnly
	m.runtimeMutex.RUnlock()

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

	m.runtimeMutex.Lock()
	m.fileRules, m.runtimeRules = file, runtime
	m.fileHTTPRules, m.runtimeHTTPRules = fileHTTP, runtimeHTTP
	m.runtimeOnly = runtimeOnly
	m.active = active
	m.runtimeMutex.Unlock()

	return m.apply(active)
}

// GetActiveRules returns the active kernel tables and HTTP rewrites.
func (m *Manager) GetActiveRules() (*lsm.PolicySet, []proxy.HeaderRewriteRule) {
	m.runtimeMutex.RLock()
	defer m.runtimeMutex.RUnlock()
	return m.active.Policies.Clone(), append([]proxy.HeaderRewriteRule(nil), m.active.HTTPRules...)
}

// Active returns the active policy: the merged strict Cedar, its engine and
// kernel tables. It is immutable.
func (m *Manager) Active() *cedar.Compilation {
	m.runtimeMutex.RLock()
	defer m.runtimeMutex.RUnlock()
	return m.active
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
	if m.lsmManager == nil || !m.lsmManager.EnforcesKernelPolicy() || active == nil {
		return nil
	}
	if err := lsm.ValidateKernelPolicyLimits(active.Policies); err != nil {
		return fmt.Errorf("%w: %w", ErrRejected, err)
	}
	return nil
}

func (m *Manager) apply(active *cedar.Compilation) error {
	m.logRewrite(active)

	// Attempt LSM update; record error but do not short-circuit proxy updates so
	// that the userspace proxy reflects current policy even on non-Linux hosts
	// or early bootstrap when LSM may be unavailable.
	var lsmErr error
	if m.lsmManager != nil {
		if err := m.lsmManager.UpdateRuntimeRules(active.Policies.Clone()); err != nil {
			lsmErr = fmt.Errorf("failed to update LSM: %w", err)
		}
	}
	if m.onChange != nil {
		m.onChange(active)
	}
	return lsmErr
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
