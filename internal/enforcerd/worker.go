//go:build unix

package enforcerd

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	cedarutil "github.com/strongdm/leash/internal/cedar"
	"github.com/strongdm/leash/internal/enforcement"
	"github.com/strongdm/leash/internal/lsm"
)

// A session worker is one process per attached session (leash daemon
// worker). It owns that session's eBPF LSM programs, exactly as leashd owns
// them in a rootful run: the same lsm.LSMManager, the same compilation. One
// process per session keeps the lsm package's process-wide state (the
// attach-settled hook, the shutdown latch) per session, and lets a session
// end by the worker exiting, which closes its BPF links.
//
// The worker exits — detaching — when the client detaches, when its cgroup
// is removed or has no processes left (the container stopped, including after
// a leash crash), or when the daemon goes away (the control connection
// closes). It never loosens anything: every program it loads can only deny.

// updateFailure is the answer to an update the worker's LSM manager could not
// apply. The manager rolled the kernel back to the session's previous policy;
// if that failed too, every program holds deny-all, and the workload is
// stopped here, where the cgroup is known to be the validated one, before
// leashd learns of it (#193). The error says which happened, so leashd fails
// closed as well.
func updateFailure(err error, cgroup string, kill func(string) error) Message {
	msg := "update the kernel tables: " + err.Error()
	var kerr *lsm.KernelApplyError
	if !errors.As(err, &kerr) || !kerr.FailedClosed {
		return Message{Type: TypeResult, Error: msg}
	}
	if kill == nil {
		kill = KillCgroup
	}
	if killErr := kill(cgroup); killErr != nil {
		msg += fmt.Sprintf("; stopping the workload failed: %v", killErr)
	} else {
		msg += "; the workload was stopped"
	}
	fmt.Fprintf(os.Stderr, "leash-enforcerd: FATAL: %s\n", msg)
	return Message{Type: TypeResult, Error: msg}
}

// compileSessionPolicy compiles session policy text the way leashd compiles a
// policy file: cedar.CompileLayers, which rewrites legacy text, builds the
// engine and compiles the kernel tables (transpiler.CompileKernel), followed
// by the kernel's limits.
func compileSessionPolicy(text string) (*lsm.PolicySet, error) {
	comp, err := cedarutil.CompileLayers([]cedarutil.Layer{{Source: &lsm.PolicySource{Name: "session.cedar", Text: text}}})
	if err != nil {
		return nil, fmt.Errorf("policy does not compile: %w", err)
	}
	if err := lsm.ValidateKernelPolicyLimits(comp.Policies); err != nil {
		return nil, fmt.Errorf("policy exceeds the kernel's limits: %w", err)
	}
	return comp.Policies, nil
}

// hostTable is the resolver the worker installs: the addresses the client
// resolved in the workload's network namespace.
type hostTable struct {
	mu    sync.RWMutex
	hosts map[string][]net.IP
}

func (h *hostTable) set(raw map[string][]string) {
	m := make(map[string][]net.IP, len(raw))
	for name, ips := range raw {
		for _, s := range ips {
			if ip := net.ParseIP(s); ip != nil {
				m[name] = append(m[name], ip)
			}
		}
	}
	h.mu.Lock()
	h.hosts = m
	h.mu.Unlock()
}

func (h *hostTable) lookup(name string) ([]net.IP, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	ips, ok := h.hosts[name]
	if !ok || len(ips) == 0 {
		return nil, fmt.Errorf("%s was not resolved by the client", name)
	}
	return ips, nil
}

type workerOut struct {
	mu sync.Mutex
	w  io.Writer
}

func (o *workerOut) send(m Message) {
	m.V = ProtocolVersion
	data, err := json.Marshal(m)
	if err != nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	_, _ = o.w.Write(append(data, '\n'))
}

type eventForwarder struct{ out *workerOut }

func (e eventForwarder) BroadcastLog(line string) {
	e.out.send(Message{Type: TypeEvent, Line: line})
}

// WorkerHooks are the parts of a worker that touch the kernel, replaceable in
// tests.
type WorkerHooks struct {
	ReadLSMList func() ([]byte, error)
	// PollInterval is how often the worker checks its cgroup.
	PollInterval time.Duration
	// SettleTimeout bounds the wait for every program to attach.
	SettleTimeout time.Duration
	// KillCgroup stops the workload when the kernel failed closed
	// (default: KillCgroup).
	KillCgroup func(path string) error
}

// RunWorker serves one session on conn (the daemon's end of a socketpair):
// it reads the attach request, attaches, reports, then serves updates and
// detach until the session ends. It returns when the programs are detached.
func RunWorker(conn io.ReadWriteCloser, hooks WorkerHooks) error {
	if hooks.ReadLSMList == nil {
		hooks.ReadLSMList = func() ([]byte, error) { return os.ReadFile(enforcement.ActiveLSMPath) }
	}
	if hooks.PollInterval == 0 {
		hooks.PollInterval = time.Second
	}
	if hooks.SettleTimeout == 0 {
		hooks.SettleTimeout = 60 * time.Second
	}
	out := &workerOut{w: conn}
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 64*1024), MaxLineBytes)
	if !sc.Scan() {
		return errors.New("no attach request")
	}
	var req Request
	if err := json.Unmarshal(sc.Bytes(), &req); err != nil || req.Op != OpAttach {
		out.send(Message{Type: TypeResult, Error: "expected an attach request"})
		return errors.New("expected an attach request")
	}
	fail := func(msg string) error {
		out.send(Message{Type: TypeResult, Error: msg})
		return errors.New(msg)
	}
	// The daemon validated the path and recorded the cgroup's id; a cgroup
	// replaced since then is not the one that was validated.
	if id, err := CgroupID(req.Cgroup); err != nil || id != req.CgroupID || id == 0 {
		return fail(fmt.Sprintf("cgroup %s changed after validation; refusing to attach", req.Cgroup))
	}
	policies, err := compileSessionPolicy(req.Policy)
	if err != nil {
		return fail(err.Error())
	}
	audit := lsm.AuditConfig{Lossless: req.AuditLossless}
	if req.AuditRingBufferKB != 0 {
		size, err := lsm.ParseAuditRingBufferKB(strconv.FormatUint(uint64(req.AuditRingBufferKB), 10))
		if err != nil {
			return fail(err.Error())
		}
		audit.RingBufferBytes = size
	}
	if err := lsm.SetAuditConfig(audit); err != nil {
		return fail(err.Error())
	}

	hosts := &hostTable{}
	hosts.set(req.Hosts)
	lsm.SetHostResolver(hosts.lookup)
	// Attach failures are reported to the client (which fails closed), not
	// turned into an exit by the lsm package.
	lsm.SetRequireLSM(false)
	logger, _ := lsm.NewSharedLogger("")
	logger.SetBroadcaster(eventForwarder{out: out})
	settled := make(chan struct{})
	var settleOnce sync.Once
	lsm.SetEnforcementSettledHook(func() { settleOnce.Do(func() { close(settled) }) })

	mgr := lsm.NewLSMManager(req.Cgroup, logger, false)
	mgr.SetContainerRootfs(true)
	lsm.BumpMemlockRlimit()
	lsm.InstallShutdownHandler()
	if err := mgr.UpdateRuntimeRules(policies); err != nil {
		return fail("load policy: " + err.Error())
	}
	mgr.StartSettleWatch()
	select {
	case <-settled:
	case <-time.After(hooks.SettleTimeout):
		return fail(fmt.Sprintf("eBPF LSM programs did not attach within %s", hooks.SettleTimeout))
	}
	state, reason := enforcement.ClassifyLSMList(hooks.ReadLSMList())
	switch {
	case lsm.Layer1Degraded():
		return fail("an eBPF LSM program failed to attach (see the enforcer daemon's journal: journalctl -u leash-enforcerd)")
	case lsm.Layer1AttachedPrograms() <= 0:
		return fail("no eBPF LSM program attached")
	case state != enforcement.LSMListActive:
		return fail(reason)
	}
	out.send(Message{Type: TypeResult, OK: true, Programs: lsm.Layer1AttachedPrograms(), AuditLossless: audit.Lossless})

	var endReason string
	var endMu sync.Mutex
	end := func(r string) {
		endMu.Lock()
		if endReason == "" {
			endReason = r
		}
		endMu.Unlock()
		lsm.RequestShutdown()
	}
	go func() {
		for sc.Scan() {
			var r Request
			if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
				continue
			}
			switch r.Op {
			case OpUpdate:
				ps, err := compileSessionPolicy(r.Policy)
				if err != nil {
					out.send(Message{Type: TypeResult, Error: err.Error() + "; the previous policy stays enforced"})
					continue
				}
				hosts.set(r.Hosts)
				if err := mgr.UpdateRuntimeRules(ps); err != nil {
					out.send(updateFailure(err, req.Cgroup, hooks.KillCgroup))
					continue
				}
				out.send(Message{Type: TypeResult, OK: true})
			case OpDetach:
				out.send(Message{Type: TypeResult, OK: true})
				end("detached by the client")
				return
			default:
				out.send(Message{Type: TypeResult, Error: "unexpected op " + r.Op})
			}
		}
		end("the daemon closed the session's control connection")
	}()
	go func() {
		t := time.NewTicker(hooks.PollInterval)
		defer t.Stop()
		for {
			select {
			case <-lsm.ShutdownRequested():
				return
			case <-t.C:
			}
			id, err := CgroupID(req.Cgroup)
			if err != nil || id != req.CgroupID {
				end("the workload's cgroup was removed")
				return
			}
			if populated, err := CgroupPopulated(req.Cgroup); err == nil && !populated {
				end("the workload's cgroup has no processes left")
				return
			}
		}
	}()
	_ = mgr.LoadAndStart() // blocks until shutdown, then waits for the links to close
	endMu.Lock()
	r := endReason
	endMu.Unlock()
	out.send(Message{Type: TypeEnded, Error: r})
	return nil
}
