package leashd

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/strongdm/leash/internal/assets"
)

func TestCgroup2RulePath(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		rel     string
		level   int
		wantErr bool
	}{
		{name: "systemd service", in: "/sys/fs/cgroup/system.slice/leash-native-issue-947-2308827811-1868195.service", rel: "system.slice/leash-native-issue-947-2308827811-1868195.service", level: 2},
		{name: "nested scope", in: "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/leash-x.scope", rel: "user.slice/user-1000.slice/user@1000.service/app.slice/leash-x.scope", level: 5},
		{name: "single level", in: "/sys/fs/cgroup/leash", rel: "leash", level: 1},
		{name: "trailing slash", in: "/sys/fs/cgroup/system.slice/foo.service/", rel: "system.slice/foo.service", level: 2},
		{name: "double slashes", in: "/sys/fs/cgroup//system.slice//foo.service", rel: "system.slice/foo.service", level: 2},
		{name: "surrounding whitespace", in: "  /sys/fs/cgroup/a/b  ", rel: "a/b", level: 2},
		{name: "docker scope", in: "/sys/fs/cgroup/system.slice/docker-abc123.scope", rel: "system.slice/docker-abc123.scope", level: 2},
		{name: "spaces allowed", in: "/sys/fs/cgroup/a b/c", rel: "a b/c", level: 2},
		{name: "empty", in: "", wantErr: true},
		{name: "root", in: "/sys/fs/cgroup", wantErr: true},
		{name: "root trailing slash", in: "/sys/fs/cgroup/", wantErr: true},
		{name: "relative input", in: "system.slice/foo.service", wantErr: true},
		{name: "outside root", in: "/tmp/cgroup", wantErr: true},
		{name: "prefix lookalike", in: "/sys/fs/cgroupfoo/bar", wantErr: true},
		{name: "dotdot escape", in: "/sys/fs/cgroup/../cgroup2/x", wantErr: true},
		{name: "double quote", in: `/sys/fs/cgroup/a"b`, wantErr: true},
		{name: "backslash", in: `/sys/fs/cgroup/foo\x2dbar.service`, wantErr: true},
		{name: "newline", in: "/sys/fs/cgroup/a\nb", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rel, level, err := cgroup2RulePath(cgroup2Root, tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got rel=%q level=%d", rel, level)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if rel != tc.rel || level != tc.level {
				t.Fatalf("got (%q, %d), want (%q, %d)", rel, level, tc.rel, tc.level)
			}
		})
	}
}

func TestCgroup2RulePathCustomRoot(t *testing.T) {
	rel, level, err := cgroup2RulePath("/mnt/cg2/", "/mnt/cg2/a/b/c")
	if err != nil || rel != "a/b/c" || level != 3 {
		t.Fatalf("got (%q, %d, %v)", rel, level, err)
	}
}

func TestNftablesScriptArgs(t *testing.T) {
	got := nftablesScriptArgs("18000", "18080", "system.slice/foo.service", 2)
	want := []string{"-s", "18000", "18080", "system.slice/foo.service", "2"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	got = nftablesScriptArgs("18000", "18080", "", 0)
	want = []string{"-s", "18000", "18080", "", ""}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// runNftScriptWithFake runs apply-nftables.sh against a fake nft that records
// each invocation's argv (one arg per line, invocations separated by "--").
// `list chain` always fails (empty ruleset); any call whose joined argv
// contains failMatch fails too, to simulate kernels lacking a feature.
func runNftScriptWithFake(t *testing.T, failMatch string, args ...string) string {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}
	dir := t.TempDir()
	logPath := filepath.Join(dir, "nft.log")
	fake := filepath.Join(dir, "nft")
	script := `#!/bin/sh
for a in "$@"; do printf '%s\n' "$a" >> "$FAKE_NFT_LOG"; done
echo -- >> "$FAKE_NFT_LOG"
case "$1 $2" in
  "list chain") exit 1 ;;
esac
if [ -n "$FAKE_FAIL" ]; then
  case "$*" in *"$FAKE_FAIL"*) exit 1 ;; esac
fi
exit 0
`
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", append([]string{"-s"}, args...)...)
	cmd.Stdin = strings.NewReader(assets.ApplyNftablesScript)
	cmd.Env = append(os.Environ(), "NFT="+fake, "FAKE_NFT_LOG="+logPath, "FAKE_FAIL="+failMatch)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("script failed: %v\n%s", err, out)
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// findInvocation returns the argv of the first recorded nft call that has an
// argument equal to needle.
func findInvocation(log, needle string) []string {
	for _, inv := range strings.Split(log, "--\n") {
		argv := strings.Split(strings.TrimSuffix(inv, "\n"), "\n")
		for _, a := range argv {
			if a == needle {
				return argv
			}
		}
	}
	return nil
}

func TestApplyNftablesScriptCgroupRuleArgv(t *testing.T) {
	log := runNftScriptWithFake(t, "", "18000", "18080", "system.slice/leash-native-x.service", "2")
	got := findInvocation(log, "cgroupv2")
	want := []string{
		"add", "rule", "inet", "leash", "out_filter",
		"socket", "cgroupv2", "level", "2", `"system.slice/leash-native-x.service"`,
		"tcp", "dport", "18080", "reject", "with", "tcp", "reset",
		"comment", `"leash:block-control-plane"`,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("cgroupv2 rule argv\n got: %q\nwant: %q", got, want)
	}
	if findInvocation(log, `"leash:block-control-plane-fallback"`) != nil {
		t.Fatalf("fallback rule applied although cgroup rule succeeded:\n%s", log)
	}
}

func TestApplyNftablesScriptDerivesLevelAndStripsSlash(t *testing.T) {
	log := runNftScriptWithFake(t, "", "18000", "18080", "/user.slice/user-1000.slice/session-3.scope")
	got := findInvocation(log, "cgroupv2")
	if len(got) < 10 || got[8] != "3" || got[9] != `"user.slice/user-1000.slice/session-3.scope"` {
		t.Fatalf("unexpected cgroupv2 argv: %q", got)
	}
}

func TestApplyNftablesScriptFallsBackWhenCgroupv2Unsupported(t *testing.T) {
	log := runNftScriptWithFake(t, "cgroupv2", "18000", "18080", "system.slice/foo.service", "2")
	if findInvocation(log, `"leash:block-control-plane-fallback"`) == nil {
		t.Fatalf("expected fallback rule when cgroupv2 match is rejected:\n%s", log)
	}
}

func TestApplyNftablesScriptNoCgroupUsesBlanketBlock(t *testing.T) {
	log := runNftScriptWithFake(t, "", "18000", "18080", "", "")
	if findInvocation(log, "cgroupv2") != nil {
		t.Fatalf("cgroupv2 rule emitted without a target cgroup:\n%s", log)
	}
	if findInvocation(log, `"leash:block-control-plane-fallback"`) == nil {
		t.Fatalf("expected namespace-wide block in degraded mode:\n%s", log)
	}
}
