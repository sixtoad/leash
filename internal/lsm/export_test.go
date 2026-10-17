package lsm

import (
	"net"
	"reflect"
)

// LegacyModelForTest exposes the legacy (#138) decision model to external
// tests; see legacy_model_test.go.
type LegacyModelForTest struct{ m *legacyModel }

// NewLegacyModelForTest builds the legacy model of ps.
func NewLegacyModelForTest(ps *PolicySet) LegacyModelForTest {
	return LegacyModelForTest{m: newLegacyModel(ps)}
}

func (l LegacyModelForTest) Open(path string, op uint32) bool { return l.m.openAllowed(path, op) }
func (l LegacyModelForTest) Exec(path string) bool            { return l.m.execAllowed(path, nil) }
func (l LegacyModelForTest) Connect(host, ip string, port uint16) bool {
	return l.m.connectAllowed(host, ip, port)
}
func (l LegacyModelForTest) MCP(server, tool string) bool { return l.m.mcpAllowed(server, tool) }

// KernelForTest is the kernel state the loaders compile from a PolicySet,
// decided by the userspace models of the BPF lookups.
type KernelForTest struct {
	openIndex      compiledOpenIndex
	openDefault    bool
	mutation       compiledMutationIndex
	exec           []ExecPolicyRule
	execDefault    bool
	connect        []ConnectPolicyRuleBPF
	connectDefault bool
}

// NewKernelForTest loads ps the way LSMManager does (OpenLsm, ExecLsm and
// ConnectLsm LoadPolicies, with the connect default override of
// updateConnectLSM). Plain hostname connect rules reach the kernel through
// DNS at load time; they are dropped here so tests never resolve names.
func NewKernelForTest(ps *PolicySet) (*KernelForTest, error) {
	k := &KernelForTest{}
	o := &OpenLsm{}
	if err := o.LoadPolicies(ConvertToFileOpenRules(ps.Open)); err != nil {
		return nil, err
	}
	k.openIndex, k.openDefault = compileOpenIndex(o.policyRules), o.defaultPolicyResult
	k.mutation = compileMutationIndex(o.policyRules)
	e := &ExecLsm{}
	if err := e.LoadPolicies(ConvertToExecRules(ps.Exec)); err != nil {
		return nil, err
	}
	k.exec, k.execDefault = e.policyRules, e.defaultPolicyResult
	var connect []PolicyRule
	for _, r := range ps.Connect {
		host := string(r.Hostname[:r.HostnameLen])
		if r.HostnameLen > 0 && host != "*" && r.IsWildcard == 0 {
			continue
		}
		connect = append(connect, r)
	}
	var override *bool
	if ps.ConnectDefaultExplicit {
		v := ps.ConnectDefaultAllow
		override = &v
	}
	c := &ConnectLsm{}
	if err := c.LoadPolicies(ConvertToConnectRules(connect), override); err != nil {
		return nil, err
	}
	k.connect, k.connectDefault = c.policyRules, c.defaultPolicyResult
	return k, nil
}

func (k *KernelForTest) Open(path string, op uint32) bool {
	return indexedOpenDecision(k.openIndex, k.openDefault, path, op) == PolicyAllow
}

// Mutation models check_mutation_policy (mkdir, unlink, rmdir, each side of
// rename) over the compiled mutation index; see mutationDecision.
func (k *KernelForTest) Mutation(path string) bool {
	return mutationDecision(k.mutation, path)
}

// Link models the hard-link guard: the source must be readable (a read-only
// open through the same index).
func (k *KernelForTest) Link(source string) bool { return k.Open(source, OpOpenRO) }

func (k *KernelForTest) Exec(path string) bool {
	return execDecision(k.exec, k.execDefault, path, nil) == PolicyAllow
}

// Connect decides a connection to an IPv4, IPv4-mapped IPv6 or IPv6 address
// the way lsm_connect does (read_inet_dest, then check_connect_policy).
func (k *KernelForTest) Connect(ip string, port uint16) bool {
	return connectBPFDecisionDest(k.connect, k.connectDefault, connectDestOf(net.ParseIP(ip), port)) == PolicyAllow
}

// OpenDecisionForTest runs rules through the same pipeline LoadPolicies uses
// (conversion, precedence sort, root default, full-byte index
// compilation) and evaluates path/operation with the userspace model of
// check_open_indexed_policy. It lets external tests (package lsm_test) check
// front-end output (Cedar, line format) against enforcement semantics without
// a kernel.
func OpenDecisionForTest(rules []PolicyRule, path string, operation uint32) uint32 {
	converted := ConvertToFileOpenRules(rules)
	sortOpenRulesByPrecedence(converted)
	return indexedOpenDecision(compileOpenIndex(converted), rootPathPolicy(converted), path, operation)
}

// SameKernelIndexesForTest reports whether two rule sets compile to identical
// file-open and directory-mutation kernel indexes (including directory-self
// entries and mutation grants), i.e. whether they enforce identically.
func SameKernelIndexesForTest(a, b []PolicyRule) bool {
	compile := func(rules []PolicyRule) (compiledOpenIndex, compiledMutationIndex, bool) {
		converted := ConvertToFileOpenRules(rules)
		sortOpenRulesByPrecedence(converted)
		return compileOpenIndex(converted), compileMutationIndex(converted), rootPathPolicy(converted)
	}
	openA, mutA, rootA := compile(a)
	openB, mutB, rootB := compile(b)
	return rootA == rootB && reflect.DeepEqual(openA, openB) && reflect.DeepEqual(mutA, mutB)
}

// ValidateOpenRulesForTest exposes the kernel-load validation for external tests.
func ValidateOpenRulesForTest(rules []PolicyRule) error {
	return validateOpenPolicyRules(ConvertToFileOpenRules(rules))
}
