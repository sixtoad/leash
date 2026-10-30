package leashd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	cedarutil "github.com/strongdm/leash/internal/cedar"
	"github.com/strongdm/leash/internal/enforcerd"
	"github.com/strongdm/leash/internal/lsm"
)

// remoteKernel programs the kernel through the leash enforcer daemon, for a
// rootless run (docs/ROOTLESS.md). It replaces the local LSM manager's
// attach: the daemon compiles the same policy text with the same pipeline
// and loads it with the same LSM programs, scoped to the workload's cgroup.
// Hostname connect rules are resolved here, in the workload's network
// namespace, exactly as the local loader resolves them.
type remoteKernel struct {
	socket string
	cgroup string
	events func(line string)
	lookup func(host string) ([]net.IP, error)
	dial   func(ctx context.Context, socket string, onEvent func(string)) (*enforcerd.Client, error)

	mu       sync.Mutex
	client   *enforcerd.Client
	attached bool
	detached bool
}

func newRemoteKernel(socket, cgroup string, events func(string)) *remoteKernel {
	return &remoteKernel{socket: socket, cgroup: cgroup, events: events, lookup: net.LookupIP, dial: enforcerd.Dial}
}

// resolveHosts resolves the hostname connect rules of a policy to the
// addresses the local loader would use (A and AAAA: the kernel connect
// program matches IPv4 and IPv6).
func (k *remoteKernel) resolveHosts(active *cedarutil.Compilation) map[string][]string {
	if active == nil {
		return nil
	}
	out := map[string][]string{}
	for _, name := range lsm.ConnectHostnames(active.Policies) {
		ips, err := k.lookup(name)
		if err != nil {
			continue // unresolved, as the local loader skips it
		}
		var addrs []string
		for _, ip := range ips {
			if ip4 := ip.To4(); ip4 != nil {
				addrs = append(addrs, ip4.String())
			} else if ip16 := ip.To16(); ip16 != nil {
				addrs = append(addrs, ip16.String())
			}
		}
		sort.Strings(addrs)
		if len(addrs) > enforcerd.MaxIPsPerHost {
			addrs = addrs[:enforcerd.MaxIPsPerHost]
		}
		if len(addrs) > 0 {
			out[name] = addrs
		}
	}
	return out
}

// attach connects and attaches the currently active policy (read under the
// lock, so a concurrent policy change is either included or sent after).
func (k *remoteKernel) attach(active func() *cedarutil.Compilation) (int, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := k.dial(ctx, k.socket, k.events)
	if err != nil {
		return 0, fmt.Errorf("cannot reach the leash enforcer daemon at %s: %w (%s)", k.socket, err, enforcerd.RemedyFor(err))
	}
	comp := active()
	text := ""
	if comp != nil {
		text = comp.StrictText
	}
	audit := lsm.CurrentAuditConfig()
	c.SetAudit(audit.RingBufferBytes>>10, audit.Lossless)
	_, programs, err := c.Attach(k.cgroup, text, k.resolveHosts(comp))
	if err != nil {
		_ = c.Close()
		return 0, fmt.Errorf("the leash enforcer daemon refused to enforce on %s: %w", k.cgroup, err)
	}
	k.client = c
	k.attached = true
	return programs, nil
}

// update sends a newly active policy. Before attach it is a no-op: attach
// sends the policy that is active then.
func (k *remoteKernel) update(active *cedarutil.Compilation) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if !k.attached || k.detached {
		return nil
	}
	return k.client.Update(active.StrictText, k.resolveHosts(active))
}

// ended is closed when the daemon reports the session over or the
// connection drops (nil channel, never ready, before attach).
func (k *remoteKernel) ended() <-chan struct{} {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.client == nil {
		return nil
	}
	return k.client.Ended()
}

func (k *remoteKernel) err() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.client == nil {
		return errors.New("not attached")
	}
	return k.client.Err()
}

// detach ends the session at shutdown.
func (k *remoteKernel) detach() {
	k.mu.Lock()
	defer k.mu.Unlock()
	if !k.attached || k.detached {
		return
	}
	k.detached = true
	_ = k.client.Detach()
	_ = k.client.Close()
}
