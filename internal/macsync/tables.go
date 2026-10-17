package macsync

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/strongdm/leash/internal/lsm"
)

// TablesSemantics names the decision procedure the extensions must apply to
// MacPolicyTables. An extension that does not implement exactly this refuses
// the tables (and so enforces nothing it does not understand: it denies).
const TablesSemantics = "leash-kernel-v1"

// MacPolicyTables is the policy the macOS extensions enforce: the kernel
// tables of lsm.MacTablesFor (compiled from the Cedar policy by
// transpiler.CompileKernel), plus leash's own protected paths and ports. It is
// the payload of TypeMacPolicyTables; the Swift side is
// mac-leash/Shared/PolicyCore.
//
// Every lookup is on the path the extension reports after firmlink
// normalization (canonicalMacPath): Endpoint Security reports /tmp, /etc and
// /var by their /private targets, and policies name the short form.
type MacPolicyTables struct {
	Version   string `json:"version"`
	Semantics string `json:"semantics"`

	File      MacFileTable      `json:"file"`
	Mutation  MacMutationTable  `json:"mutation"`
	Exec      MacExecTable      `json:"exec"`
	Network   MacNetworkTable   `json:"network"`
	Protected MacProtectedTable `json:"protected"`
}

// MacFileTable is lsm.MacOpenTable on the wire. Op is "read" (open without
// FWRITE) or "write" (any write mode).
type MacFileTable struct {
	DefaultAllow bool           `json:"default_allow"`
	Exact        []MacFileEntry `json:"exact"`
	Prefix       []MacFileEntry `json:"prefix"`
}

// MacFileEntry is one file-open index entry.
type MacFileEntry struct {
	Op          string `json:"op"`
	Path        string `json:"path"`
	Allow       bool   `json:"allow"`
	Specificity uint32 `json:"spec"`
	Order       uint32 `json:"order"`
}

// MacMutationTable is lsm.MacMutationTable on the wire.
type MacMutationTable struct {
	Allow     []MacMutationPrefix `json:"allow"`
	Deny      []MacMutationPrefix `json:"deny"`
	ExactDeny []string            `json:"exact_deny"`
}

// MacMutationPrefix is a mutation prefix and its specificity.
type MacMutationPrefix struct {
	Path        string `json:"path"`
	Specificity uint32 `json:"spec"`
}

// MacExecTable is lsm.MacExecTable on the wire, rules in precedence order.
type MacExecTable struct {
	DefaultAllow bool           `json:"default_allow"`
	Rules        []MacExecEntry `json:"rules"`
}

// MacExecEntry is one exec rule.
type MacExecEntry struct {
	Path  string   `json:"path"`
	Exact bool     `json:"exact,omitempty"`
	Allow bool     `json:"allow"`
	Args  []string `json:"args,omitempty"`
}

// MacNetworkTable is lsm.MacConnectTable on the wire, rules in precedence
// order (every deny first).
type MacNetworkTable struct {
	DefaultAllow bool              `json:"default_allow"`
	Rules        []MacNetworkEntry `json:"rules"`
}

// MacNetworkEntry matches a destination: Family 0 any address, 4 IPv4, 6
// IPv6; Port 0 any port.
type MacNetworkEntry struct {
	Family int    `json:"family"`
	IP     string `json:"ip,omitempty"`
	Port   uint16 `json:"port"`
	Allow  bool   `json:"allow"`
}

// MacProtectedTable is what a leashed workload may never touch, whatever the
// policy says. On Linux the workload cannot see leash's own state at all (it
// lives outside the box) and the netfilter rules reject the leash ports; on
// macOS the workload runs on the host as the same user, so the extensions deny
// it these explicitly, before the policy tables are consulted.
type MacProtectedTable struct {
	// Paths are denied for every open, mutation and exec: the path itself
	// and everything below it.
	Paths []string `json:"paths"`
	// Ports are denied on loopback and unspecified destinations: the daemon's
	// Control UI/API and the MITM proxy listener.
	Ports []uint16 `json:"ports"`
}

// Protection names leash's own state for MacProtectedTable.
type Protection struct {
	Paths []string
	Ports []uint16
}

// CompileTables builds the macOS policy tables for policy: the kernel tables
// (resolving hostname rules, as the Linux loader does), converted to the wire
// form, with protection added. It fails when the policy names a path the
// extensions could not see as written (firmlinkConflict).
func CompileTables(policy *lsm.PolicySet, protection Protection) (*MacPolicyTables, error) {
	kt, err := lsm.MacTablesFor(policy)
	if err != nil {
		return nil, err
	}
	t := &MacPolicyTables{Semantics: TablesSemantics}

	t.File.DefaultAllow = kt.Open.DefaultAllow
	conv := func(es []lsm.MacOpenEntry, exact bool) ([]MacFileEntry, error) {
		out := make([]MacFileEntry, 0, len(es))
		for _, e := range es {
			check := checkFirmlink
			if exact {
				check = checkFirmlinkExact
			}
			if err := check(e.Path); err != nil {
				return nil, err
			}
			op := "read"
			if e.Operation == lsm.OpOpenRW {
				op = "write"
			}
			out = append(out, MacFileEntry{Op: op, Path: e.Path, Allow: e.Allow, Specificity: e.Specificity, Order: e.Order})
		}
		return out, nil
	}
	if t.File.Exact, err = conv(kt.Open.Exact, true); err != nil {
		return nil, err
	}
	if t.File.Prefix, err = conv(kt.Open.Prefix, false); err != nil {
		return nil, err
	}

	t.Mutation.Allow = []MacMutationPrefix{}
	t.Mutation.Deny = []MacMutationPrefix{}
	t.Mutation.ExactDeny = []string{}
	for _, p := range kt.Mutation.Allow {
		if err := checkFirmlink(p.Path); err != nil {
			return nil, err
		}
		t.Mutation.Allow = append(t.Mutation.Allow, MacMutationPrefix{Path: p.Path, Specificity: p.Specificity})
	}
	for _, p := range kt.Mutation.Deny {
		if err := checkFirmlink(p.Path); err != nil {
			return nil, err
		}
		t.Mutation.Deny = append(t.Mutation.Deny, MacMutationPrefix{Path: p.Path, Specificity: p.Specificity})
	}
	for _, p := range kt.Mutation.ExactDeny {
		if err := checkFirmlinkExact(p); err != nil {
			return nil, err
		}
		t.Mutation.ExactDeny = append(t.Mutation.ExactDeny, p)
	}

	t.Exec.DefaultAllow = kt.Exec.DefaultAllow
	t.Exec.Rules = []MacExecEntry{}
	for _, r := range kt.Exec.Rules {
		check := checkFirmlink
		if r.Exact {
			check = checkFirmlinkExact
		}
		if err := check(r.Path); err != nil {
			return nil, err
		}
		t.Exec.Rules = append(t.Exec.Rules, MacExecEntry{Path: r.Path, Exact: r.Exact, Allow: r.Allow, Args: r.Args})
	}

	t.Network.DefaultAllow = kt.Connect.DefaultAllow
	t.Network.Rules = []MacNetworkEntry{}
	for _, r := range kt.Connect.Rules {
		t.Network.Rules = append(t.Network.Rules, MacNetworkEntry{Family: r.Family, IP: r.IP, Port: r.Port, Allow: r.Allow})
	}

	t.Protected.Paths = []string{}
	for _, p := range protection.Paths {
		p = canonicalMacPath(strings.TrimRight(p, "/"))
		if p == "" || p == "/" {
			continue // never protect the whole file system by accident
		}
		t.Protected.Paths = append(t.Protected.Paths, p)
	}
	t.Protected.Ports = append([]uint16{}, protection.Ports...)

	t.Version, err = tablesVersion(t)
	if err != nil {
		return nil, err
	}
	return t, nil
}

// tablesVersion is a content hash of the tables, so an extension's
// acknowledgement names exactly what it applied.
func tablesVersion(t *MacPolicyTables) (string, error) {
	c := *t
	c.Version = ""
	data, err := json.Marshal(&c)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:8]), nil
}

// macFirmlinks are the system directories macOS presents through a symlink:
// /tmp, /etc and /var are /private/tmp, /private/etc and /private/var.
var macFirmlinks = []string{"/etc", "/tmp", "/var"}

// canonicalMacPath maps the /private form Endpoint Security reports back to
// the short form policies are written with ("/private/tmp/x" -> "/tmp/x").
// The Swift matcher applies the same mapping (PolicyCore.canonicalPath).
func canonicalMacPath(path string) string {
	for _, fl := range macFirmlinks {
		long := "/private" + fl
		if path == long || strings.HasPrefix(path, long+"/") {
			return path[len("/private"):]
		}
	}
	return path
}

// checkFirmlink refuses a table path that could match a path in its /private
// form: after canonicalMacPath no looked-up path has that form, so such an
// entry would silently stop applying. Only "/" may be a prefix of both forms.
func checkFirmlink(path string) error {
	if path == "/" || path == "" {
		return nil
	}
	for _, fl := range macFirmlinks {
		long := "/private" + fl
		if strings.HasPrefix(long+"/", path) || path == long || strings.HasPrefix(path, long+"/") {
			return fmt.Errorf("the policy names %q, which macOS only reaches as %s/...: on macOS, name %s/... instead (/tmp, /etc and /var are links into /private)", path, long, fl)
		}
	}
	return nil
}

// checkFirmlinkExact is checkFirmlink for an entry that matches only its own
// path: it conflicts only when that path is in the /private form.
func checkFirmlinkExact(path string) error {
	if canonicalMacPath(path) != path {
		return checkFirmlink(path)
	}
	return nil
}
