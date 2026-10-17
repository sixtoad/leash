package lsm

import (
	"bytes"
	"fmt"
	"net"
	"sort"
)

// The macOS extensions enforce the same tables the Linux kernel loaders build
// (#142 parity). Rather than re-deriving them from the policy rules (which is
// how the old macsync translation lost operation modes, exact paths, port
// numbers and longest-prefix precedence), MacTablesFor runs the real loader
// compilation and exports its result: the file-open index (exact and prefix
// entries per open mode, with the specificity and order the BPF lookup
// compares), the directory-mutation index, the exec rules in precedence order
// and the expanded connect rules. The Swift matchers in mac-leash/Shared
// implement the four BPF lookups over these tables and nothing else.

// MacTables is the kernel enforcement state for a policy, in plain values.
type MacTables struct {
	Open     MacOpenTable
	Mutation MacMutationTable
	Exec     MacExecTable
	Connect  MacConnectTable
}

// MacOpenTable is the compiled file-open index. Entries are per open mode
// (OpOpenRO or OpOpenRW): a generic rule is expanded to both, as the kernel
// does. A request is decided by the longest prefix entry for its mode, the
// exact entry for its mode, and specificity then order between them
// (indexedOpenDecision); with neither, by DefaultAllow.
type MacOpenTable struct {
	DefaultAllow bool
	Exact        []MacOpenEntry
	Prefix       []MacOpenEntry
}

// MacOpenEntry is one index entry.
type MacOpenEntry struct {
	Operation   uint32 // OpOpenRO or OpOpenRW
	Path        string
	Allow       bool
	Specificity uint32
	Order       uint32
}

// MacMutationTable is the directory-mutation index (mkdir, unlink, rmdir,
// rename source and destination, hard-link destination): an exact deny
// denies; otherwise the longest matching allow prefix wins only when it is
// strictly more specific than the longest matching deny prefix; no allow
// denies (check_mutation_policy).
type MacMutationTable struct {
	Allow     []MacMutationPrefix
	Deny      []MacMutationPrefix
	ExactDeny []string
}

// MacMutationPrefix is a mutation prefix and its specificity.
type MacMutationPrefix struct {
	Path        string
	Specificity uint32
}

// MacExecTable is the exec rule list in the kernel's precedence order: the
// first rule whose path is a byte prefix of the executable path (an Exact
// rule: equal to it) decides; with none, DefaultAllow.
type MacExecTable struct {
	DefaultAllow bool
	Rules        []MacExecEntry
}

// MacExecEntry is one exec rule. A rule with Args (deny rules only; an allow
// rule with arguments never matches and is not exported) denies only when one
// of the exec's arguments equals one of them, and otherwise falls through.
type MacExecEntry struct {
	Path  string
	Exact bool
	Allow bool
	Args  []string
}

// MacConnectTable is the expanded connect rule list (hostnames resolved,
// wildcards left to the proxy), every deny first: the first matching rule
// decides; with none, DefaultAllow. An IPv4-mapped IPv6 destination is
// decided as IPv4.
type MacConnectTable struct {
	DefaultAllow bool
	Rules        []MacConnectEntry
}

// MacConnectEntry matches a destination: Family 0 any address, 4 an IPv4
// address, 6 an IPv6 address; Port 0 any port.
type MacConnectEntry struct {
	Family int
	IP     string
	Port   uint16
	Allow  bool
}

// MacTablesFor compiles ps exactly as LSMManager loads it into the kernel
// (OpenLsm, ExecLsm and ConnectLsm LoadPolicies, with the connect default
// override of updateConnectLSM). Hostname connect rules are resolved through
// the configured host resolver, as on Linux.
func MacTablesFor(ps *PolicySet) (*MacTables, error) {
	if ps == nil {
		ps = &PolicySet{}
	}
	t := &MacTables{}

	o := &OpenLsm{}
	if err := o.LoadPolicies(ConvertToFileOpenRules(ps.Open)); err != nil {
		return nil, fmt.Errorf("file-open table: %w", err)
	}
	idx := compileOpenIndex(o.policyRules)
	t.Open.DefaultAllow = o.defaultPolicyResult
	for key, v := range idx.exact {
		if key.Operation != OpOpenRO && key.Operation != OpOpenRW {
			continue // generic-domain copies are never looked up
		}
		t.Open.Exact = append(t.Open.Exact, MacOpenEntry{
			Operation: key.Operation, Path: string(key.Path[:key.PathLen]),
			Allow: v.Action == PolicyAllow, Specificity: v.Specificity, Order: v.Order,
		})
	}
	for key, v := range idx.prefix {
		op := uint32(key.Domain)
		if op != OpOpenRO && op != OpOpenRW {
			continue
		}
		n := (key.PrefixLen - openIndexDomainBits) / 8
		t.Open.Prefix = append(t.Open.Prefix, MacOpenEntry{
			Operation: op, Path: string(key.Path[:n]),
			Allow: v.Action == PolicyAllow, Specificity: v.Specificity, Order: v.Order,
		})
	}
	sortOpenEntries(t.Open.Exact)
	sortOpenEntries(t.Open.Prefix)

	mut := compileMutationIndex(o.policyRules)
	for key, spec := range mut.allows {
		n := (key.PrefixLen - mutationIndexDomainBits) / 8
		t.Mutation.Allow = append(t.Mutation.Allow, MacMutationPrefix{Path: string(key.Path[:n]), Specificity: uint32(spec)})
	}
	for key, spec := range mut.denies {
		n := (key.PrefixLen - mutationIndexDomainBits) / 8
		t.Mutation.Deny = append(t.Mutation.Deny, MacMutationPrefix{Path: string(key.Path[:n]), Specificity: uint32(spec)})
	}
	for key := range mut.selfDenies {
		t.Mutation.ExactDeny = append(t.Mutation.ExactDeny, string(key.Path[:key.PathLen]))
	}
	sortMutationPrefixes(t.Mutation.Allow)
	sortMutationPrefixes(t.Mutation.Deny)
	sort.Strings(t.Mutation.ExactDeny)

	e := &ExecLsm{}
	if err := e.LoadPolicies(ConvertToExecRules(ps.Exec)); err != nil {
		return nil, fmt.Errorf("exec table: %w", err)
	}
	t.Exec.DefaultAllow = e.defaultPolicyResult
	for _, r := range e.policyRules {
		path := r.Path[:r.PathLen]
		entry := MacExecEntry{Allow: r.Action == PolicyAllow}
		if n := len(path); n > 0 && path[n-1] == 0 {
			entry.Exact = true
			path = path[:n-1]
		}
		entry.Path = string(path)
		if r.ArgCount > 0 {
			if entry.Allow {
				continue // check_exec_policy never matches an allow rule with arguments
			}
			for i := int32(0); i < r.ArgCount && i < int32(len(r.Args)); i++ {
				entry.Args = append(entry.Args, string(bytes.TrimRight(r.Args[i][:r.ArgLens[i]], "\x00")))
			}
		}
		t.Exec.Rules = append(t.Exec.Rules, entry)
	}

	var override *bool
	if ps.ConnectDefaultExplicit {
		v := ps.ConnectDefaultAllow
		override = &v
	}
	c := &ConnectLsm{}
	if err := c.LoadPolicies(ConvertToConnectRules(ps.Connect), override); err != nil {
		return nil, fmt.Errorf("connect table: %w", err)
	}
	t.Connect.DefaultAllow = c.defaultPolicyResult
	for _, r := range c.policyRules {
		entry := MacConnectEntry{Port: r.DestPort, Allow: r.Action == PolicyAllow}
		switch r.Family {
		case afInet:
			entry.Family = 4
			entry.IP = canonicalIPv4String(r.DestIP)
		case afInet6:
			entry.Family = 6
			entry.IP = net.IP(r.DestIP6[:]).String()
		}
		t.Connect.Rules = append(t.Connect.Rules, entry)
	}
	return t, nil
}

// Entries are emitted in a fixed order so the same policy always produces
// the same tables (and the same version hash).
func sortOpenEntries(es []MacOpenEntry) {
	sort.Slice(es, func(i, j int) bool {
		if es[i].Path != es[j].Path {
			return es[i].Path < es[j].Path
		}
		return es[i].Operation < es[j].Operation
	})
}

func sortMutationPrefixes(ps []MacMutationPrefix) {
	sort.Slice(ps, func(i, j int) bool { return ps[i].Path < ps[j].Path })
}
