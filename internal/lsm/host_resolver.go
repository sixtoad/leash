package lsm

import (
	"bytes"
	"net"
	"sort"
	"sync"
)

// The kernel connect program matches IPv4 addresses, so hostname rules are
// resolved to addresses when the policy loads. leashd resolves in the
// workload's network namespace with net.LookupIP. The rootless enforcer
// daemon runs without a network (PrivateNetwork=yes) and in another network
// namespace anyway, so it loads the addresses its client resolved in the
// workload's namespace instead (SetHostResolver).

var (
	hostResolverMu sync.RWMutex
	hostResolver   = net.LookupIP
)

// SetHostResolver replaces the lookup used for hostname connect rules. nil
// restores net.LookupIP. Set it once, before any policy loads.
func SetHostResolver(f func(host string) ([]net.IP, error)) {
	hostResolverMu.Lock()
	defer hostResolverMu.Unlock()
	if f == nil {
		f = net.LookupIP
	}
	hostResolver = f
}

func lookupHostIPs(host string) ([]net.IP, error) {
	hostResolverMu.RLock()
	f := hostResolver
	hostResolverMu.RUnlock()
	return f(host)
}

// ConnectHostnames returns the hostnames the kernel connect loader resolves
// for ps: the names of exact-host connect rules, without wildcards and the
// Host::"*" default. Sorted and deduplicated.
func ConnectHostnames(ps *PolicySet) []string {
	if ps == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, rule := range ConvertToConnectRules(ps.Connect) {
		if rule.DestIP != 0 || rule.HostnameLen == 0 || rule.IsWildcard == 1 {
			continue
		}
		if isConnectDefault(rule.DestIP, rule.DestPort, rule.Hostname[:], rule.HostnameLen) {
			continue
		}
		name := string(bytes.TrimRight(rule.Hostname[:], "\x00"))
		if name == "" || name == "*" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
