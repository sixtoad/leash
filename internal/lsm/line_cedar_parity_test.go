package lsm_test

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/strongdm/leash/internal/lsm"
	"github.com/strongdm/leash/internal/transpiler"
)

// parityRoot does not exist, so the line parser's symlink resolution leaves
// paths untouched (the Cedar transpiler never resolves symlinks).
const parityRoot = "/leash-parity-126"

type frontEndPair struct {
	name  string
	cedar string // one Cedar policy
	line  string // the equivalent line-format rule
}

func cedarRule(effect, action, resourceType, path string) string {
	return fmt.Sprintf("%s (principal, action == Action::%q, resource) when { resource in [ %s::%q ] };\n", effect, action, resourceType, path)
}

func parityPairs() []frontEndPair {
	w := parityRoot + "/work"
	return []frontEndPair{
		{"dir open", cedarRule("permit", "FileOpen", "Dir", w), "allow file.open " + w + "/"},
		{"dir open cedar trailing slash", cedarRule("permit", "FileOpen", "Dir", w+"/"), "allow file.open " + w + "/"},
		{"dir read", cedarRule("permit", "FileOpenReadOnly", "Dir", w+"/ro"), "allow file.open:ro " + w + "/ro/"},
		{"dir write (mutation grant)", cedarRule("permit", "FileOpenReadWrite", "Dir", w+"/rw"), "allow file.open:rw " + w + "/rw/"},
		{"forbid dir open (self deny)", cedarRule("forbid", "FileOpen", "Dir", w+"/secret"), "deny file.open " + w + "/secret/"},
		{"forbid dir write", cedarRule("forbid", "FileOpenReadWrite", "Dir", w+"/rw/locked"), "deny file.open:rw " + w + "/rw/locked/"},
		{"file open", cedarRule("permit", "FileOpen", "File", w+"/notes.txt"), "allow file.open " + w + "/notes.txt"},
		{"forbid file write", cedarRule("forbid", "FileOpenReadWrite", "File", w+"/rw/config"), "deny file.open:rw " + w + "/rw/config"},
		{"root dir", cedarRule("permit", "FileOpen", "Dir", "/"), "allow file.open /"},
		{"exec dir", cedarRule("permit", "ProcessExec", "Dir", parityRoot+"/bin"), "allow proc.exec " + parityRoot + "/bin/"},
		{"exec file", cedarRule("forbid", "ProcessExec", "File", parityRoot+"/bin/rm"), "deny proc.exec " + parityRoot + "/bin/rm"},
	}
}

func transpileCedar(t *testing.T, policy string) *lsm.PolicySet {
	t.Helper()
	set, _, err := transpiler.NewCedarToLeashTranspiler().TranspileFromString(policy)
	if err != nil {
		t.Fatalf("transpile: %v\n%s", err, policy)
	}
	return set
}

func parseLine(t *testing.T, line string) lsm.PolicyRule {
	t.Helper()
	rule, err := lsm.ParseRuleString(line)
	if err != nil {
		t.Fatalf("parse %q: %v", line, err)
	}
	return *rule
}

// singleFileRule returns the only file-open or exec rule of a set.
func singleFileRule(t *testing.T, set *lsm.PolicySet) lsm.PolicyRule {
	t.Helper()
	rules := append(append([]lsm.PolicyRule(nil), set.Open...), set.Exec...)
	if len(rules) != 1 {
		t.Fatalf("expected exactly one file/exec rule, got open=%d exec=%d", len(set.Open), len(set.Exec))
	}
	return rules[0]
}

func describe(r lsm.PolicyRule) string {
	return fmt.Sprintf("{action=%d op=%d path=%q len=%d dir=%d}", r.Action, r.Operation, string(r.Path[:r.PathLen]), r.PathLen, r.IsDirectory)
}

// Issue #126: the line-format parser must produce the same rules as the Cedar
// transpiler, including IsDirectory for directory rules.
func TestLineFormatMatchesCedarRulePerRule(t *testing.T) {
	t.Parallel()
	for _, pair := range parityPairs() {
		pair := pair
		t.Run(pair.name, func(t *testing.T) {
			t.Parallel()
			fromCedar := singleFileRule(t, transpileCedar(t, pair.cedar))
			fromLine := parseLine(t, pair.line)
			if fromCedar != fromLine {
				t.Fatalf("front ends disagree\n cedar %s\n line  %s", describe(fromCedar), describe(fromLine))
			}
			wantDir := int32(0)
			if strings.HasSuffix(string(fromLine.Path[:fromLine.PathLen]), "/") {
				wantDir = 1
			}
			if fromLine.IsDirectory != wantDir {
				t.Fatalf("line rule %q IsDirectory=%d, want %d", pair.line, fromLine.IsDirectory, wantDir)
			}
		})
	}
}

// The whole policy, through both front ends, compiles to identical kernel
// indexes (open, directory-self, mutation grants and self denies) and agrees
// on every probe, including the directory-self paths from #119.
func TestLineFormatMatchesCedarWholePolicy(t *testing.T) {
	t.Parallel()
	var cedar strings.Builder
	var lineOpen []lsm.PolicyRule
	for _, pair := range parityPairs() {
		cedar.WriteString(pair.cedar)
		rule := parseLine(t, pair.line)
		if rule.Operation != lsm.OpExec {
			lineOpen = append(lineOpen, rule)
		}
	}
	cedarSet := transpileCedar(t, cedar.String())
	if len(cedarSet.Open) != len(lineOpen) {
		t.Fatalf("open rule count: cedar=%d line=%d", len(cedarSet.Open), len(lineOpen))
	}
	if err := lsm.ValidateOpenRulesForTest(lineOpen); err != nil {
		t.Fatalf("kernel validation rejected line-format rules: %v", err)
	}
	if !lsm.SameKernelIndexesForTest(cedarSet.Open, lineOpen) {
		t.Fatal("Cedar and line-format policies compile to different kernel indexes")
	}

	w := parityRoot + "/work"
	probes := []string{
		"/", parityRoot, w, w + "/", w + "x", w + "/a",
		w + "/ro", w + "/ro/f", w + "/rw", w + "/rw/f", w + "/rwx",
		w + "/rw/locked", w + "/rw/locked/f", w + "/rw/config",
		w + "/secret", w + "/secret/k", w + "/secrets", w + "/notes.txt",
	}
	for _, path := range probes {
		for _, op := range []uint32{lsm.OpOpen, lsm.OpOpenRO, lsm.OpOpenRW} {
			c := lsm.OpenDecisionForTest(cedarSet.Open, path, op)
			l := lsm.OpenDecisionForTest(lineOpen, path, op)
			if c != l {
				t.Errorf("decision(%q, op=%d): cedar=%d line=%d", path, op, c, l)
			}
		}
	}
}

// A line-format directory rule covers the directory itself, as Dir:: does
// (#119), without leaking to a sibling that shares the byte prefix.
func TestLineFormatDirectoryRuleCoversDirectoryItself(t *testing.T) {
	t.Parallel()
	w := parityRoot + "/work"
	rules := []lsm.PolicyRule{parseLine(t, "allow file.open:ro "+w+"/")}
	cases := []struct {
		path string
		op   uint32
		want uint32
	}{
		{w, lsm.OpOpenRO, lsm.PolicyAllow},
		{w + "/", lsm.OpOpenRO, lsm.PolicyAllow},
		{w + "/f", lsm.OpOpenRO, lsm.PolicyAllow},
		{w, lsm.OpOpenRW, lsm.PolicyDeny},
		{w + "space", lsm.OpOpenRO, lsm.PolicyDeny},
		{parityRoot, lsm.OpOpenRO, lsm.PolicyDeny},
	}
	for _, tc := range cases {
		if got := lsm.OpenDecisionForTest(rules, tc.path, tc.op); got != tc.want {
			t.Errorf("decision(%q, op=%d) = %d, want %d", tc.path, tc.op, got, tc.want)
		}
	}
}

// Issue #135: the Cedar transpiler keeps source order on every run, and a
// forbid beats a permit on the same path and operation whichever comes first
// in the source.
func TestCedarSamePathForbidWinsInEitherSourceOrder(t *testing.T) {
	t.Parallel()
	w := parityRoot + "/work"
	permit := cedarRule("permit", "FileOpen", "Dir", w+"/shared") + cedarRule("permit", "FileOpenReadOnly", "File", w+"/notes.txt")
	forbid := cedarRule("forbid", "FileOpenReadOnly", "Dir", w+"/shared") + cedarRule("forbid", "FileOpen", "File", w+"/notes.txt")
	for name, policy := range map[string]string{"permit first": permit + forbid, "forbid first": forbid + permit} {
		first := transpileCedar(t, policy)
		for i := 0; i < 50; i++ {
			if again := transpileCedar(t, policy); !reflect.DeepEqual(again, first) {
				t.Fatalf("%s: transpile %d produced a different rule set", name, i)
			}
		}
		for _, probe := range []string{w + "/shared", w + "/shared/f", w + "/notes.txt"} {
			if got := lsm.OpenDecisionForTest(first.Open, probe, lsm.OpOpenRO); got != lsm.PolicyDeny {
				t.Errorf("%s: read %q = %d, want deny", name, probe, got)
			}
		}
		if got := lsm.OpenDecisionForTest(first.Open, w+"/shared/f", lsm.OpOpenRW); got != lsm.PolicyAllow {
			t.Errorf("%s: write under permitted dir = %d, want allow", name, got)
		}
	}
}
