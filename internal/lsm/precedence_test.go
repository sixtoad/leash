package lsm

import (
	"math/rand"
	"net"
	"reflect"
	"strings"
	"testing"
)

// Issue #135: rule order must not decide a permit/forbid conflict, and the same
// rules in any order must produce the same kernel state.

const precedenceShuffles = 200

func shuffled[T any](rng *rand.Rand, in []T) []T {
	out := append([]T(nil), in...)
	rng.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

func precedenceOpenRules() []OpenPolicyRule {
	return []OpenPolicyRule{
		// Same path and operation, both effects.
		openRuleForPath(PolicyAllow, OpOpenRO, "/w/same"),
		openRuleForPath(PolicyDeny, OpOpenRO, "/w/same"),
		// Generic deny against an operation-specific allow on one path.
		openRuleForPath(PolicyDeny, OpOpen, "/w/generic-deny"),
		openRuleForPath(PolicyAllow, OpOpenRW, "/w/generic-deny"),
		// Generic allow against an operation-specific deny on one path.
		openRuleForPath(PolicyAllow, OpOpen, "/w/specific-deny"),
		openRuleForPath(PolicyDeny, OpOpenRO, "/w/specific-deny"),
		// Directory rules: prefix and directory-self entries collide too.
		openDirectoryRuleForPath(PolicyAllow, OpOpen, "/w/dir/"),
		openDirectoryRuleForPath(PolicyDeny, OpOpen, "/w/dir/"),
		openDirectoryRuleForPath(PolicyAllow, OpOpenRW, "/w/rw/"),
		openDirectoryRuleForPath(PolicyDeny, OpOpenRW, "/w/rw/"),
		// Unrelated rules of the same lengths.
		openRuleForPath(PolicyAllow, OpOpen, "/w/emas"),
		openDirectoryRuleForPath(PolicyAllow, OpOpen, "/w/"),
		openRuleForPath(PolicyAllow, OpOpen, "/"),
	}
}

func TestOpenPrecedenceIsOrderIndependentAndDenyWins(t *testing.T) {
	rng := rand.New(rand.NewSource(135))
	base := precedenceOpenRules()

	compile := func(rules []OpenPolicyRule) ([]OpenPolicyRule, compiledOpenIndex, compiledMutationIndex, bool) {
		l := &OpenLsm{}
		if err := l.LoadPolicies(rules); err != nil {
			t.Fatal(err)
		}
		return l.policyRules, compileOpenIndex(l.policyRules), compileMutationIndex(l.policyRules), l.defaultPolicyResult
	}
	wantRules, wantOpen, wantMut, wantDefault := compile(base)

	type probe struct {
		path string
		op   uint32
		want uint32
	}
	probes := []probe{
		{"/w/same", OpOpenRO, PolicyDeny},
		{"/w/generic-deny", OpOpenRW, PolicyDeny},
		{"/w/generic-deny", OpOpenRO, PolicyDeny},
		{"/w/specific-deny", OpOpenRO, PolicyDeny},
		{"/w/specific-deny", OpOpenRW, PolicyAllow},
		{"/w/dir", OpOpenRO, PolicyDeny},
		{"/w/dir/f", OpOpenRW, PolicyDeny},
		{"/w/rw/f", OpOpenRW, PolicyDeny},
		{"/w/emas", OpOpenRW, PolicyAllow},
		{"/w/other", OpOpenRO, PolicyAllow},
	}
	for _, p := range probes {
		if got := indexedOpenDecision(wantOpen, wantDefault, p.path, p.op); got != p.want {
			t.Fatalf("decision(%q, op=%d) = %d, want %d", p.path, p.op, got, p.want)
		}
	}
	// The rw directory deny must reach the mutation deny index alongside the
	// grant; the kernel checks denies first.
	if _, ok := wantMut.denies[mutationPrefixKeyForTest("/w/rw/")]; !ok {
		t.Fatal("rw directory deny missing from mutation deny index")
	}

	for i := 0; i < precedenceShuffles; i++ {
		rules, open, mut, def := compile(shuffled(rng, base))
		if !reflect.DeepEqual(rules, wantRules) {
			t.Fatalf("shuffle %d: loaded rule order differs", i)
		}
		if !reflect.DeepEqual(open, wantOpen) || !reflect.DeepEqual(mut, wantMut) || def != wantDefault {
			t.Fatalf("shuffle %d: compiled kernel indexes differ", i)
		}
	}
}

// compileOpenIndex itself, without the precedence sort, still lets a deny
// win a key collision against an earlier allow.
func TestCompileOpenIndexDenyWinsCollisionInAnyOrder(t *testing.T) {
	rng := rand.New(rand.NewSource(1350))
	base := precedenceOpenRules()
	for i := 0; i < precedenceShuffles; i++ {
		index := compileOpenIndex(shuffled(rng, base))
		for _, key := range []openPrefixRuleKey{
			prefixIndexKey(OpOpenRO, "/w/same"),
			prefixIndexKey(OpOpenRW, "/w/generic-deny"),
			prefixIndexKey(OpOpenRO, "/w/specific-deny"),
			prefixIndexKey(OpOpenRO, "/w/dir/"),
			prefixIndexKey(OpOpenRW, "/w/rw/"),
		} {
			if got := index.prefix[key]; got.Action != PolicyDeny {
				t.Fatalf("shuffle %d: prefix %q op %d = %+v, want deny", i, strings.TrimRight(string(key.Path[:]), "\x00"), key.Domain, got)
			}
		}
		if got := index.exact[exactIndexKey(OpOpenRW, "/w/dir")]; got.Action != PolicyDeny {
			t.Fatalf("shuffle %d: directory-self = %+v, want deny", i, got)
		}
	}
}

func mutationPrefixKeyForTest(path string) mutationPrefixRuleKey {
	key := mutationPrefixRuleKey{PrefixLen: mutationIndexDomainBits + uint32(len(path))*8}
	copy(key.Path[:], path)
	return key
}

func execRuleForTest(action int32, path string, args ...string) ExecPolicyRule {
	r := ExecPolicyRule{Action: action, Operation: OpExec, PathLen: int32(len(path)), ArgCount: int32(len(args))}
	copy(r.Path[:], path)
	if strings.HasSuffix(path, "/") {
		r.IsDirectory = 1
	}
	for i, a := range args {
		copy(r.Args[i][:], a)
		r.ArgLens[i] = int32(len(a))
	}
	return r
}

// execDecision models check_exec_policy's first-match scan for rules without
// arguments (argument-bearing allow rules never match; deny rules with
// arguments only deny on an argument match and otherwise fall through).
func execDecision(rules []ExecPolicyRule, defaultAllow bool, path string, args []string) int32 {
	for _, r := range rules {
		// check_exec_policy compares rule bytes against the NUL-terminated
		// resolved path: a rule ending in NUL (an exact path) matches only
		// where the path ends.
		if !strings.HasPrefix(path+"\x00", string(r.Path[:r.PathLen])) {
			continue
		}
		if r.ArgCount == 0 {
			return r.Action
		}
		if r.Action == PolicyDeny {
			for p := int32(0); p < r.ArgCount; p++ {
				for _, a := range args {
					if a == string(r.Args[p][:r.ArgLens[p]]) {
						return PolicyDeny
					}
				}
			}
		}
	}
	if defaultAllow {
		return PolicyAllow
	}
	return PolicyDeny
}

func TestExecPrecedenceIsOrderIndependentAndDenyWins(t *testing.T) {
	rng := rand.New(rand.NewSource(1351))
	base := []ExecPolicyRule{
		execRuleForTest(PolicyAllow, "/usr/bin/rm"),
		execRuleForTest(PolicyDeny, "/usr/bin/rm"),
		execRuleForTest(PolicyAllow, "/usr/bin/git"),
		execRuleForTest(PolicyDeny, "/usr/bin/git", "push"),
		execRuleForTest(PolicyAllow, "/usr/bin/"),
		execRuleForTest(PolicyDeny, "/usr/bin/"),
		execRuleForTest(PolicyAllow, "/opt/"),
		execRuleForTest(PolicyAllow, "/"),
	}
	load := func(rules []ExecPolicyRule) *ExecLsm {
		l := &ExecLsm{}
		if err := l.LoadPolicies(rules); err != nil {
			t.Fatal(err)
		}
		return l
	}
	want := load(base)
	cases := []struct {
		path string
		args []string
		want int32
	}{
		{"/usr/bin/rm", nil, PolicyDeny},
		{"/usr/bin/git", []string{"push"}, PolicyDeny},
		{"/usr/bin/git", []string{"status"}, PolicyAllow},
		{"/usr/bin/ls", nil, PolicyDeny},
		{"/opt/tool", nil, PolicyAllow},
	}
	for _, tc := range cases {
		if got := execDecision(want.policyRules, want.defaultPolicyResult, tc.path, tc.args); got != tc.want {
			t.Fatalf("exec %q %v = %d, want %d", tc.path, tc.args, got, tc.want)
		}
	}
	for i := 0; i < precedenceShuffles; i++ {
		input := shuffled(rng, base)
		snapshot := append([]ExecPolicyRule(nil), input...)
		got := load(input)
		if !reflect.DeepEqual(got.policyRules, want.policyRules) || got.defaultPolicyResult != want.defaultPolicyResult {
			t.Fatalf("shuffle %d: loaded exec rules differ", i)
		}
		if !reflect.DeepEqual(input, snapshot) {
			t.Fatalf("shuffle %d: LoadPolicies reordered the caller's slice", i)
		}
	}
}

func connectRuleForTest(action int32, ip uint32, port uint16, host string) ConnectPolicyRule {
	r := ConnectPolicyRule{Action: action, Operation: OpConnect, DestIP: ip, DestPort: port, HostnameLen: int32(len(host))}
	copy(r.Hostname[:], host)
	if strings.HasPrefix(host, "*.") {
		r.IsWildcard = 1
	}
	return r
}

// connectDestForTest is struct connect_dest: a destination classified by
// read_inet_dest.
type connectDestForTest struct {
	family uint32
	ip     uint32
	ip6    [16]byte
	port   uint16
}

// connectDestOf models read_inet_dest: an IPv4 or IPv4-mapped IPv6 address
// is AF_INET with its canonical value, any other IPv6 address AF_INET6.
func connectDestOf(ip net.IP, port uint16) connectDestForTest {
	if v4, ok := canonicalIPv4(ip); ok {
		return connectDestForTest{family: afInet, ip: v4, port: port}
	}
	d := connectDestForTest{family: afInet6, port: port}
	copy(d.ip6[:], ip.To16())
	return d
}

// connectBPFDecisionDest models check_connect_policy's first-match scan.
func connectBPFDecisionDest(rules []ConnectPolicyRuleBPF, defaultAllow bool, d connectDestForTest) uint32 {
	for _, r := range rules {
		if r.Family != 0 {
			if r.Family != d.family {
				continue
			}
			if d.family == afInet && r.DestIP != d.ip {
				continue
			}
			if d.family == afInet6 && r.DestIP6 != d.ip6 {
				continue
			}
		}
		if r.DestPort != 0 && r.DestPort != d.port {
			continue
		}
		return r.Action
	}
	if defaultAllow {
		return PolicyAllow
	}
	return PolicyDeny
}

// connectBPFDecision is connectBPFDecisionDest for an IPv4 destination.
func connectBPFDecision(rules []ConnectPolicyRuleBPF, defaultAllow bool, ip uint32, port uint16) uint32 {
	return connectBPFDecisionDest(rules, defaultAllow, connectDestForTest{family: afInet, ip: ip, port: port})
}

func TestConnectKernelPrecedenceIsOrderIndependentAndDenyWins(t *testing.T) {
	rng := rand.New(rand.NewSource(1352))
	const ip = uint32(10<<24 | 1)
	base := []ConnectPolicyRule{
		connectRuleForTest(PolicyAllow, ip, 0, ""),
		connectRuleForTest(PolicyDeny, ip, 22, ""),
		connectRuleForTest(PolicyAllow, ip+1, 443, ""),
		connectRuleForTest(PolicyDeny, ip+1, 443, ""),
		connectRuleForTest(PolicyAllow, ip+2, 443, ""),
	}
	load := func(rules []ConnectPolicyRule) *ConnectLsm {
		l := &ConnectLsm{}
		if err := l.LoadPolicies(rules, nil); err != nil {
			t.Fatal(err)
		}
		return l
	}
	want := load(base)
	cases := []struct {
		ip   uint32
		port uint16
		want uint32
	}{
		{ip, 22, PolicyDeny},
		{ip, 80, PolicyAllow},
		{ip + 1, 443, PolicyDeny},
		{ip + 2, 443, PolicyAllow},
		{ip + 3, 443, PolicyDeny},
	}
	for _, tc := range cases {
		if got := connectBPFDecision(want.policyRules, want.defaultPolicyResult, tc.ip, tc.port); got != tc.want {
			t.Fatalf("connect %d:%d = %d, want %d", tc.ip, tc.port, got, tc.want)
		}
	}
	for i := 0; i < precedenceShuffles; i++ {
		got := load(shuffled(rng, base))
		if !reflect.DeepEqual(got.policyRules, want.policyRules) || got.defaultPolicyResult != want.defaultPolicyResult {
			t.Fatalf("shuffle %d: loaded connect rules differ", i)
		}
	}
}

func TestProxyConnectAndMCPPrecedenceIsOrderIndependentAndDenyWins(t *testing.T) {
	rng := rand.New(rand.NewSource(1353))
	const ip = uint32(10<<24 | 1)
	connect := []ConnectPolicyRule{
		connectRuleForTest(PolicyAllow, 0, 0, "api.example.com"),
		connectRuleForTest(PolicyDeny, 0, 0, "*.example.com"),
		connectRuleForTest(PolicyAllow, 0, 0, "ok.test"),
		connectRuleForTest(PolicyAllow, ip, 0, ""),
		connectRuleForTest(PolicyDeny, ip, 22, ""),
	}
	mcp := []MCPPolicyRule{
		{Action: PolicyAllow, Server: "mcp.example.com", Tool: "run"},
		{Action: PolicyDeny, Server: "mcp.example.com", Tool: ""},
		{Action: PolicyAllow, Server: "other.example.com", Tool: ""},
	}
	for i := 0; i < precedenceShuffles; i++ {
		pc := newLegacyChecker(shuffled(rng, connect), false, shuffled(rng, mcp))
		if pc.CheckConnect("api.example.com", "", 443) {
			t.Fatalf("shuffle %d: wildcard forbid lost to an exact permit", i)
		}
		if !pc.CheckConnect("ok.test", "", 443) {
			t.Fatalf("shuffle %d: unrelated permit denied", i)
		}
		if pc.CheckConnect("", "10.0.0.1", 22) {
			t.Fatalf("shuffle %d: port forbid lost to an IP permit", i)
		}
		if !pc.CheckConnect("", "10.0.0.1", 80) {
			t.Fatalf("shuffle %d: IP permit denied", i)
		}
		if pc.CheckMCPCall("mcp.example.com", "run") {
			t.Fatalf("shuffle %d: MCP server forbid lost to a tool permit", i)
		}
		if !pc.CheckMCPCall("other.example.com", "run") {
			t.Fatalf("shuffle %d: unrelated MCP permit denied", i)
		}
	}
}
