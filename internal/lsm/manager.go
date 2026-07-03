//go:generate bash -c "if [ \"$(uname -s)\" = 'Linux' ]; then command -v bpf2go 1>/dev/null 2>&1 || go install github.com/cilium/ebpf/cmd/bpf2go && bpf2go -cc clang -tags linux lsmOpen bpf/lsm_open.bpf.c -- -I./bpf && bpf2go -cc clang -tags linux lsmExec bpf/lsm_exec.bpf.c -- -I./bpf && bpf2go -cc clang -tags linux lsmConnect bpf/lsm_connect.bpf.c -- -I./bpf; else echo 'Skipping bpf2go in non-Linux build environment'; fi"

package lsm

import (
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

// LSMManager manages multiple LSM programs and handles policy reloading
type LSMManager struct {
	cgroupPath string
	logger     *SharedLogger

	// requireLSM makes an eBPF LSM attach failure fatal instead of degrading to
	// proxy-only enforcement.
	requireLSM bool

	// Active LSM programs
	openLsm    *OpenLsm
	execLsm    *ExecLsm
	connectLsm *ConnectLsm

	reloadMutex sync.RWMutex
	degradeOnce sync.Once

	// attachWG tracks the initial LSM program attaches so a host launcher is
	// released only after ALL of them settle (attached or degraded), not the
	// first. settleWatchOnce guards the single watcher goroutine.
	attachWG        sync.WaitGroup
	settleWatchOnce sync.Once
}

func NewLSMManager(cgroupPath string, logger *SharedLogger, requireLSM bool) *LSMManager {
	m := &LSMManager{
		cgroupPath: cgroupPath,
		logger:     logger,
		requireLSM: requireLSM,
	}
	// Count each successful program attach toward "all attached".
	onLSMAttached = m.attachWG.Done
	return m
}

// StartSettleWatch fires the enforcement-settled hook once every attach spawned
// by the initial policy load has reported (attached or degraded). Call it after
// that load, before LoadAndStart blocks. Safe to call more than once.
func (m *LSMManager) StartSettleWatch() {
	m.settleWatchOnce.Do(func() {
		go func() {
			m.attachWG.Wait()
			notifyEnforcementSettled()
		}()
	})
}

// handleAttachFailure decides what happens when an eBPF LSM program fails to
// attach (most often because the kernel doesn't have "bpf" as an active LSM).
// With requireLSM it is fatal; otherwise leash degrades to proxy-only (Layer 2,
// fail-closed) and continues, warning loudly once.
func (m *LSMManager) handleAttachFailure(label string, err error) {
	if m.requireLSM {
		fmt.Fprintf(os.Stderr, "leash: FATAL: %s LSM failed to attach and --require-lsm is set: %v\n", label, err)
		os.Exit(1)
	}
	// This program failed to attach — count it as settled (degraded) so the
	// "all attached" watcher can still fire.
	m.attachWG.Done()
	m.degradeOnce.Do(func() {
		fmt.Fprintf(os.Stderr, "leash: WARNING: eBPF LSM enforcement (Layer 1) is unavailable (%s: %v).\n", label, err)
		fmt.Fprintf(os.Stderr, "leash: continuing in degraded proxy-only mode — filesystem/exec/socket policies are NOT enforced; the L7 proxy (Layer 2) remains active and fail-closed.\n")
		fmt.Fprintf(os.Stderr, "leash: enable the bpf LSM (lsm=...,bpf in the kernel cmdline) or pass --require-lsm to make this fatal.\n")
	})
}

func (m *LSMManager) LoadAndStart() error {
	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	fmt.Printf("LSM Manager started. Press Ctrl-C to stop.\n")

	// Wait for shutdown signal
	select {
	case <-sigChan:
		fmt.Printf("Received shutdown signal\n")
	}

	return nil
}

func (m *LSMManager) updateOpenLSM(policies *PolicySet) error {
	if !policies.HasOpenPolicies() {
		// No open policies, ensure LSM is stopped
		if m.openLsm != nil {
			fmt.Printf("No open policies found, open LSM will continue with empty rules\n")
			// Just reload with empty rules instead of stopping
			return m.openLsm.LoadPolicies([]OpenPolicyRule{})
		}
		return nil
	}

	if m.openLsm == nil {
		// Create new open LSM
		var err error
		m.openLsm, err = NewOpenLsm(m.cgroupPath, m.logger)
		if err != nil {
			return fmt.Errorf("failed to create file open LSM: %w", err)
		}

		// Load policies and start in background
		if err := m.openLsm.LoadPolicies(ConvertToFileOpenRules(policies.Open)); err != nil {
			return fmt.Errorf("failed to load open policies: %w", err)
		}

		m.attachWG.Add(1)
		go func() {
			if err := m.openLsm.LoadAndAttach(loadLsmOpen); err != nil {
				m.handleAttachFailure("file-open", err)
			}
		}()
	} else {
		// Update existing policies
		return m.openLsm.LoadPolicies(ConvertToFileOpenRules(policies.Open))
	}

	return nil
}

func (m *LSMManager) updateExecLSM(policies *PolicySet) error {
	if !policies.HasExecPolicies() {
		if m.execLsm != nil {
			fmt.Printf("No exec policies found, exec LSM will continue with empty rules\n")
			return m.execLsm.LoadPolicies([]ExecPolicyRule{})
		}
		return nil
	}

	if m.execLsm == nil {
		var err error
		m.execLsm, err = NewExecLsm(m.cgroupPath, m.logger)
		if err != nil {
			return fmt.Errorf("failed to create exec LSM: %w", err)
		}

		if err := m.execLsm.LoadPolicies(ConvertToExecRules(policies.Exec)); err != nil {
			return fmt.Errorf("failed to load exec policies: %w", err)
		}

		m.attachWG.Add(1)
		go func() {
			if err := m.execLsm.LoadAndAttach(loadLsmExec); err != nil {
				m.handleAttachFailure("exec", err)
			}
		}()
	} else {
		return m.execLsm.LoadPolicies(ConvertToExecRules(policies.Exec))
	}

	return nil
}

func (m *LSMManager) updateConnectLSM(policies *PolicySet) error {
	var defaultOverride *bool
	if policies.ConnectDefaultExplicit {
		val := policies.ConnectDefaultAllow
		defaultOverride = &val
	}

	if !policies.HasConnectPolicies() {
		if m.connectLsm != nil {
			fmt.Printf("No connect policies found, connect LSM will continue with empty rules\n")
			return m.connectLsm.LoadPolicies([]ConnectPolicyRule{}, defaultOverride)
		}
		return nil
	}

	if m.connectLsm == nil {
		var err error
		m.connectLsm, err = NewConnectLsm(m.cgroupPath, m.logger)
		if err != nil {
			return fmt.Errorf("failed to create connect LSM: %w", err)
		}

		if err := m.connectLsm.LoadPolicies(ConvertToConnectRules(policies.Connect), defaultOverride); err != nil {
			return fmt.Errorf("failed to load connect policies: %w", err)
		}

		m.attachWG.Add(1)
		go func() {
			if err := m.connectLsm.LoadAndAttach(loadLsmConnect); err != nil {
				m.handleAttachFailure("connect", err)
			}
		}()
	} else {
		return m.connectLsm.LoadPolicies(ConvertToConnectRules(policies.Connect), defaultOverride)
	}

	return nil
}

// UpdateRuntimeRules updates all LSM modules with new runtime rules
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

	if err := m.updateOpenLSM(policies); err != nil {
		return err
	}
	if err := m.updateExecLSM(policies); err != nil {
		return err
	}
	if err := m.updateConnectLSM(policies); err != nil {
		return err
	}
	return nil
}
