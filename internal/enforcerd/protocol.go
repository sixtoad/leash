// Package enforcerd is the leash enforcer daemon: a small, privileged,
// socket-activated system service that attaches leash's eBPF LSM enforcement
// to the cgroups of rootless container workloads.
//
// Rootless podman cannot load BPF LSM programs: the leash container is root
// only inside a user namespace, and BPF_PROG_TYPE_LSM needs CAP_BPF and
// CAP_PERFMON in the initial user namespace. The daemon holds exactly those
// two capabilities. A rootless leashd asks it, over a group-restricted Unix
// socket, to enforce the session's policy on the workload's cgroup; the daemon
// compiles the policy with the same pipeline leashd uses
// (cedar.CompileLayers, which ends in transpiler.CompileKernel) and loads it
// with the same lsm.LSMManager, in a per-session worker process. It never
// grants anything: a BPF LSM program can only deny an operation the kernel
// would otherwise allow, and the daemon only attaches programs scoped to
// cgroups the caller owns.
//
// See docs/ROOTLESS.md for the security model.
package enforcerd

import (
	"errors"
	"fmt"
	"strings"
)

// Wire protocol v1: newline-delimited JSON over a stream Unix socket. The
// client sends Requests; the daemon answers each one with a Message of Type
// "result", in order, and may interleave Messages of Type "event" (an
// enforcement event line for the session's log) and, at most once, "ended"
// (the session is over: the worker exited, so enforcement is no longer
// attached). The daemon and its per-session workers speak the same protocol,
// so the daemon relays a session's messages unchanged.
const (
	ProtocolVersion = 1

	// DefaultSocketPath is where the systemd socket unit listens.
	DefaultSocketPath = "/run/leash/enforcerd.sock"
	// EnvSocket overrides the socket path (leashd reads it inside the leash
	// container, where the runner mounts the socket's directory).
	EnvSocket = "LEASH_ENFORCER_SOCKET"
	// GroupName is the group allowed to connect (socket mode 0660).
	GroupName = "leash"

	// MaxLineBytes bounds one request line; MaxPolicyBytes the policy text in
	// it. MaxHosts and MaxIPsPerHost bound the resolved-host table.
	MaxLineBytes   = 2 << 20
	MaxPolicyBytes = 1 << 20
	MaxHosts       = 1024
	MaxIPsPerHost  = 64
)

// Operations.
const (
	OpStatus = "status"
	OpAttach = "attach"
	OpUpdate = "update"
	OpDetach = "detach"
)

// Message types.
const (
	TypeResult = "result"
	TypeEvent  = "event"
	TypeEnded  = "ended"
)

// Request is one client request.
type Request struct {
	V  int    `json:"v"`
	Op string `json:"op"`
	// Cgroup is the absolute cgroup v2 directory to enforce on (attach).
	Cgroup string `json:"cgroup,omitempty"`
	// CgroupID is the cgroup's inode number as the daemon validated it; set
	// by the daemon when it forwards an attach to its worker, never trusted
	// from a client.
	CgroupID uint64 `json:"cgroupId,omitempty"`
	// Policy is the session's active policy as strict Cedar text (attach,
	// update): cedar.Compilation.StrictText.
	Policy string `json:"policy,omitempty"`
	// Hosts are the IPv4 and IPv6 addresses the client resolved, in the workload's
	// network namespace, for the policy's hostname connect rules (the kernel
	// matches connects by IP; the daemon has no network).
	Hosts map[string][]string `json:"hosts,omitempty"`
	// AuditRingBufferKB sizes each eBPF object's audit ring buffer in KiB
	// (attach; 0 = the default). Bounded by the lsm package's limits.
	AuditRingBufferKB uint32 `json:"auditRingBufferKb,omitempty"`
	// AuditLossless asks for the lossless audit posture (attach): an
	// operation whose audit record cannot be written is denied.
	AuditLossless bool `json:"auditLossless,omitempty"`
}

// Message is one daemon (or worker) message.
type Message struct {
	V     int    `json:"v"`
	Type  string `json:"type"`
	OK    bool   `json:"ok,omitempty"`
	Error string `json:"error,omitempty"`
	// Session names an attached session (attach result).
	Session string `json:"session,omitempty"`
	// Programs is the number of eBPF LSM programs attached (attach result).
	Programs int `json:"programs,omitempty"`
	// Status answers OpStatus.
	Status *Status `json:"status,omitempty"`
	// Line is an enforcement event log line (TypeEvent).
	Line string `json:"line,omitempty"`
	// AuditLossless confirms the lossless audit posture is in force (attach
	// result). A client that asked for it refuses an attach without it: an
	// older daemon ignores the request field.
	AuditLossless bool `json:"auditLossless,omitempty"`
}

// Status describes the daemon to a client.
type Status struct {
	Version  string `json:"version"`
	Protocol int    `json:"protocol"`
	// BPFLSM is "active", "inactive" or "unknown": whether "bpf" is in the
	// kernel's active LSM list (programs attach regardless; they only run
	// when it is active).
	BPFLSM       string `json:"bpfLSM"`
	BPFLSMReason string `json:"bpfLSMReason,omitempty"`
	// UID is the caller's uid as the daemon resolved it (the owner of a
	// subordinate uid).
	UID int `json:"uid"`
	// Sessions is the number of sessions the caller has attached.
	Sessions int `json:"sessions"`
}

// Validate checks a client request's shape and limits.
func (r *Request) Validate() error {
	if r.V != ProtocolVersion {
		return fmt.Errorf("unsupported protocol version %d (this daemon speaks %d)", r.V, ProtocolVersion)
	}
	switch r.Op {
	case OpStatus, OpDetach:
	case OpAttach:
		if strings.TrimSpace(r.Cgroup) == "" {
			return errors.New("attach: cgroup is required")
		}
		fallthrough
	case OpUpdate:
		if len(r.Policy) > MaxPolicyBytes {
			return fmt.Errorf("policy is %d bytes, more than the %d-byte limit", len(r.Policy), MaxPolicyBytes)
		}
		if len(r.Hosts) > MaxHosts {
			return fmt.Errorf("%d resolved hosts, more than the limit of %d", len(r.Hosts), MaxHosts)
		}
		for name, ips := range r.Hosts {
			if len(name) == 0 || len(name) > 253 {
				return fmt.Errorf("invalid resolved host name %q", name)
			}
			if len(ips) > MaxIPsPerHost {
				return fmt.Errorf("host %q has %d addresses, more than the limit of %d", name, len(ips), MaxIPsPerHost)
			}
		}
	default:
		return fmt.Errorf("unknown op %q", r.Op)
	}
	return nil
}
