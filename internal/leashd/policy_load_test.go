package leashd

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/strongdm/leash/internal/lsm"
	"github.com/strongdm/leash/internal/policy"
	"github.com/strongdm/leash/internal/proxy"
)

// leashd's own startup check rejects an unknown entity (not only syntax).
func TestPreFlightRejectsUnknownEntity(t *testing.T) {
	_, _ = provisionLeashEnv(t)
	cfg := &runtimeConfig{
		PolicyPath: writePolicyFile(t, `forbid (principal, action == Action::"FileOpen", resource in Dirr::"/etc/");`),
		ProxyPort:  "18000",
		CgroupPath: createCgroupStub(t, true),
	}
	err := preFlight(cfg)
	if err == nil || !strings.Contains(err.Error(), `Resource type "Dirr"`) {
		t.Fatalf("want the unknown entity rejected with its reason, got %v", err)
	}
}

// The FATAL line keeps a multi-line Cedar error on one line so launchers can
// extract the whole reason.
func TestFatalLine(t *testing.T) {
	got := FatalLine(errors.New("error: invalid Cedar policy\nfile: /p.cedar:1:1\n\nhint:   fix it\n"))
	want := "leash: FATAL: error: invalid Cedar policy; file: /p.cedar:1:1; hint: fix it"
	if got != want {
		t.Fatalf("FatalLine = %q, want %q", got, want)
	}
	if FatalLine(nil) != "" {
		t.Fatal("nil error must render empty")
	}
}

// A reload that fails to parse, names an unknown entity, or cannot be applied
// keeps the previous policy; a later valid reload still applies.
func TestPolicyReloadKeepsPreviousOnBadUpdate(t *testing.T) {
	path := writePolicyFile(t, `permit (principal, action == Action::"FileOpen", resource in Dir::"/tmp/");`)
	initial, err := policy.Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	var lastProxy *lsm.PolicySet
	mgr := policy.NewManager(nil, func(rules *lsm.PolicySet, _ []proxy.HeaderRewriteRule) { lastProxy = rules })
	if err := mgr.UpdateFileRules(initial.LSMPolicies, initial.HTTPRewrites); err != nil {
		t.Fatal(err)
	}
	rt := &runtimeState{cfg: &runtimeConfig{PolicyPath: path}, policyManager: mgr}
	if err := rt.startPolicyWatcher(); err != nil {
		t.Fatal(err)
	}
	defer rt.policyWatcherStop()

	openPaths := func() string {
		fileLSM, _, _, _ := mgr.Snapshot()
		var paths []string
		for _, r := range fileLSM.Open {
			paths = append(paths, string(r.Path[:r.PathLen]))
		}
		return strings.Join(paths, ",")
	}
	want := openPaths()
	if want != "/tmp/" {
		t.Fatalf("initial open rules = %q", want)
	}

	bump := time.Now()
	write := func(content string) {
		t.Helper()
		bump = bump.Add(2 * time.Second) // distinct mtime even on coarse filesystems
		if err := os.WriteFile(path, []byte(content+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, bump, bump); err != nil {
			t.Fatal(err)
		}
	}

	for _, bad := range []string{
		`permit (principal, action == Action::"FileOpen", resource in Dir::"/")`, // missing ';'
		`permit (principal, action == Action::"FileOpen", resource in Bogus::"/");`,
	} {
		write(bad)
		time.Sleep(2500 * time.Millisecond) // the watcher polls every second
		if got := openPaths(); got != want {
			t.Fatalf("bad reload %q replaced the policy: open=%q", bad, got)
		}
		if lastProxy == nil || len(lastProxy.Open) != 1 {
			t.Fatalf("proxy lost the previous policy after %q: %+v", bad, lastProxy)
		}
	}

	write(`permit (principal, action == Action::"FileOpen", resource in Dir::"/var/");`)
	deadline := time.Now().Add(5 * time.Second)
	for openPaths() != "/var/" {
		if time.Now().After(deadline) {
			t.Fatalf("valid reload never applied: open=%q", openPaths())
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// applyFileReload restores the previous file layer when the new one cannot be
// applied (here: refused for exceeding the kernel's rule limit).
func TestApplyFileReloadRestoresPrevious(t *testing.T) {
	mgr := policy.NewManager(lsm.NewLSMManager(filepath.Join(t.TempDir(), "cg"), nil, true), nil)
	big := &lsm.PolicySet{}
	for i := 0; i <= lsm.MaxPolicyRules; i++ {
		var r lsm.PolicyRule
		r.Action, r.Operation = lsm.PolicyAllow, lsm.OpOpen
		p := "/x" + strconv.Itoa(i) // distinct: the manager dedupes rules
		copy(r.Path[:], p)
		r.PathLen = int32(len(p))
		big.Open = append(big.Open, r)
	}
	err := applyFileReload(mgr, &policy.Config{LSMPolicies: big})
	if err == nil {
		t.Fatal("want the oversized reload refused")
	}
	if fileLSM, _, _, _ := mgr.Snapshot(); len(fileLSM.Open) != 0 {
		t.Fatalf("previous (empty) policy not kept: open=%d", len(fileLSM.Open))
	}
}
