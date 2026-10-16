package lsm

import (
	"math/rand"
	"strings"
	"testing"
)

// Parity between the legacy model (legacy_model_test.go) and the
// kernel-compiled paths. Each test generates random rule sets, compiles them
// the way the kernel loaders do (LoadPolicies: conversion, precedence sort,
// defaults, index compilation) and checks that the userspace model of the
// BPF lookup over the compiled state decides exactly like the legacy model
// on random probes. The BPF models (indexedOpenDecision, execDecision,
// connectBPFDecision) are the ones the BPF matchers are pinned to elsewhere
// in this package's tests.

func randomPathRule(rng *rand.Rand, roots []string, tails string, op int32) PolicyRule {
	path := roots[rng.Intn(len(roots))]
	for n := rng.Intn(4); n > 0; n-- {
		path += string(tails[rng.Intn(len(tails))])
	}
	if rng.Intn(6) == 0 {
		path = "/"
	}
	rule := PolicyRule{Action: int32(rng.Intn(2)), Operation: op, PathLen: int32(len(path))}
	copy(rule.Path[:], path)
	if strings.HasSuffix(path, "/") {
		rule.IsDirectory = 1
	}
	return rule
}

func randomProbe(rng *rand.Rand, roots []string, tails string) string {
	path := roots[rng.Intn(len(roots))]
	for n := rng.Intn(6); n > 0; n-- {
		path += string(tails[rng.Intn(len(tails))])
	}
	if rng.Intn(4) == 0 && len(path) > 1 {
		path = strings.TrimSuffix(path, "/")
	}
	return path
}

func TestLegacyModelOpenMatchesKernelIndex(t *testing.T) {
	rng := rand.New(rand.NewSource(1421))
	roots := []string{"/", "/etc/", "/etc", "/home/u/", "/home/u/.ssh/", "/tmp/x"}
	for iteration := 0; iteration < 5000; iteration++ {
		var rules []PolicyRule
		for i := rng.Intn(8) + 1; i > 0; i-- {
			rules = append(rules, randomPathRule(rng, roots, "ab/", int32(rng.Intn(3))))
		}
		model := newLegacyModel(&PolicySet{Open: rules})

		// Kernel pipeline: what OpenLsm.LoadPolicies compiles.
		l := &OpenLsm{}
		if err := l.LoadPolicies(ConvertToFileOpenRules(rules)); err != nil {
			t.Fatal(err)
		}
		index := compileOpenIndex(l.policyRules)
		for probe := 0; probe < 10; probe++ {
			path := randomProbe(rng, roots, "ab/")
			op := uint32(OpOpenRO + rng.Intn(2))
			kernel := indexedOpenDecision(index, l.defaultPolicyResult, path, op)
			core := model.openAllowed(path, op)
			if core != (kernel == PolicyAllow) {
				t.Fatalf("open %q op %d: model=%v kernel=%d rules=%v", path, op, core, kernel, ruleStrings(rules))
			}
		}
	}
}

func TestLegacyModelExecMatchesKernelScan(t *testing.T) {
	rng := rand.New(rand.NewSource(1422))
	roots := []string{"/", "/usr/bin/", "/usr/bin/git", "/usr/bin/rm", "/opt/"}
	argPool := []string{"push", "status", "-rf", "--force"}
	for iteration := 0; iteration < 5000; iteration++ {
		var rules []PolicyRule
		for i := rng.Intn(8) + 1; i > 0; i-- {
			rule := randomPathRule(rng, roots, "ab", OpExec)
			if rule.Action == PolicyDeny && rng.Intn(3) == 0 {
				for k := rng.Intn(2) + 1; k > 0; k-- {
					a := argPool[rng.Intn(len(argPool))]
					copy(rule.Args[rule.ArgCount][:], a)
					rule.ArgLens[rule.ArgCount] = int32(len(a))
					rule.ArgCount++
				}
			}
			rules = append(rules, rule)
		}
		model := newLegacyModel(&PolicySet{Exec: rules})

		l := &ExecLsm{}
		if err := l.LoadPolicies(ConvertToExecRules(rules)); err != nil {
			t.Fatal(err)
		}
		for probe := 0; probe < 10; probe++ {
			path := randomProbe(rng, roots, "ab")
			var args []string
			for k := rng.Intn(3); k > 0; k-- {
				args = append(args, argPool[rng.Intn(len(argPool))])
			}
			kernel := execDecision(l.policyRules, l.defaultPolicyResult, path, args)
			core := model.execAllowed(path, args)
			if core != (kernel == PolicyAllow) {
				t.Fatalf("exec %q %v: model=%v kernel=%d rules=%v", path, args, core, kernel, ruleStrings(rules))
			}
		}
	}
}

// IP rules only: hostname rules reach the kernel through DNS resolution at
// load time (and wildcards not at all), which is the documented split between
// the kernel (IP) and the proxy (hostname) connect checks.
func TestLegacyModelConnectMatchesKernelScan(t *testing.T) {
	rng := rand.New(rand.NewSource(1423))
	ips := []uint32{10<<24 | 1, 10<<24 | 2, 10<<24 | 3}
	ports := []uint16{0, 22, 443}
	for iteration := 0; iteration < 5000; iteration++ {
		var rules []PolicyRule
		for i := rng.Intn(6) + 1; i > 0; i-- {
			rules = append(rules, PolicyRule{
				Action:    int32(rng.Intn(2)),
				Operation: OpConnect,
				DestIP:    ips[rng.Intn(len(ips))],
				DestPort:  ports[rng.Intn(len(ports))],
			})
		}
		defaultAllow := rng.Intn(2) == 0
		ps := &PolicySet{Connect: rules, ConnectDefaultAllow: defaultAllow, ConnectDefaultExplicit: true}
		model := newLegacyModel(ps)

		l := &ConnectLsm{}
		override := ps.ConnectDefaultAllow
		if err := l.LoadPolicies(ConvertToConnectRules(rules), &override); err != nil {
			t.Fatal(err)
		}
		for probe := 0; probe < 10; probe++ {
			ip := ips[rng.Intn(len(ips))] + uint32(rng.Intn(2))
			port := []uint16{22, 80, 443}[rng.Intn(3)]
			kernel := connectBPFDecision(l.policyRules, l.defaultPolicyResult, ip, port)
			core := model.connectAllowed("", canonicalIPv4String(ip), port)
			if core != (kernel == PolicyAllow) {
				t.Fatalf("connect %s:%d: model=%v kernel=%d rules=%v", canonicalIPv4String(ip), port, core, kernel, ruleStrings(rules))
			}
		}
	}
}

func ruleStrings(rules []PolicyRule) []string {
	out := make([]string, len(rules))
	for i := range rules {
		out[i] = rules[i].String()
	}
	return out
}

func TestLegacyModelWildcardHostNeedsALabelBoundary(t *testing.T) {
	m := newLegacyModel(&PolicySet{Connect: []PolicyRule{hostRuleForTest(PolicyAllow, "*.example.com")}})
	for host, want := range map[string]bool{
		"api.example.com":   true,
		"a.b.example.com":   true,
		"API.Example.COM":   true,
		"example.com":       false,
		"evilexample.com":   false,
		"example.com.evil":  false,
		"api.example.com.":  true,
		"xexample.com.test": false,
	} {
		if got := m.connectAllowed(host, "", 443); got != want {
			t.Errorf("%q: allow=%v, want %v", host, got, want)
		}
	}
}

func pathRuleForTest(action int32, op int32, path string) PolicyRule {
	r := PolicyRule{Action: action, Operation: op, PathLen: int32(len(path))}
	copy(r.Path[:], path)
	if strings.HasSuffix(path, "/") {
		r.IsDirectory = 1
	}
	return r
}

func hostRuleForTest(action int32, host string) PolicyRule {
	r := PolicyRule{Action: action, Operation: OpConnect, HostnameLen: int32(len(host))}
	copy(r.Hostname[:], host)
	if strings.HasPrefix(host, "*.") {
		r.IsWildcard = 1
	}
	return r
}
