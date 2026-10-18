package runner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/strongdm/leash/internal/entrypoint"
)

// badPolicies are policies leashd cannot load. Each must abort the run.
var badPolicies = []struct {
	name   string
	cedar  string // "" means the file does not exist
	reason string // substring the printed reason must contain
}{
	{
		name:   "syntax error",
		cedar:  `permit (principal, action in Action::"FileOpen", resource in Dir::"/")` + "\n", // missing ';'
		reason: "invalid Cedar policy",
	},
	{
		name:   "unknown entity",
		cedar:  `permit (principal, action in Action::"FileOpen", resource in Bogus::"/");` + "\n",
		reason: "invalid Cedar policy",
	},
	{
		name:   "missing file",
		reason: "no such file",
	},
}

// writeFakeBins puts docker/podman/systemd-run/systemctl stand-ins on PATH that
// only log their invocation, so a test can prove nothing was provisioned.
func writeFakeBins(t *testing.T) (calls string) {
	t.Helper()
	bin := t.TempDir()
	calls = filepath.Join(t.TempDir(), "calls.log")
	script := "#!/bin/sh\necho \"$(basename \"$0\") $*\" >> " + shellQuoteSingle(calls) + "\nexit 0\n"
	for _, name := range []string{"docker", "podman", "systemd-run", "systemctl"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return calls
}

// chdirForTest switches the working directory for one (non-parallel) test.
func chdirForTest(t *testing.T, dir string) {
	t.Helper()
	prev, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })
}

func shellQuoteSingle(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// End to end through the CLI entry point: a policy that cannot load must abort
// the run with its reason before anything is provisioned — the workload never
// runs (its marker file never appears) — under the container and native
// runtimes (issue #162).
func TestBadPolicyAbortsRunBeforeWorkload(t *testing.T) {
	for _, runtimeName := range []string{"docker", "native"} {
		for _, tc := range badPolicies {
			name := runtimeName + "/" + tc.name
			t.Run(name, func(t *testing.T) {
				calls := writeFakeBins(t)
				work := t.TempDir()
				t.Setenv("HOME", t.TempDir())
				t.Setenv("LEASH_WORK_DIR", "")
				chdirForTest(t, work)

				policyPath := filepath.Join(work, "bad.cedar")
				if tc.cedar != "" {
					if err := os.WriteFile(policyPath, []byte(tc.cedar), 0o644); err != nil {
						t.Fatal(err)
					}
				}
				marker := filepath.Join(work, "workload-ran")

				args := []string{"--runtime", runtimeName, "--policy", policyPath, "--no-interactive", "--", "sh", "-c", "touch " + shellQuoteSingle(marker)}

				err := execute("leash", args)
				if err == nil {
					t.Fatal("run must fail when the policy cannot load")
				}
				msg := err.Error()
				if !strings.Contains(msg, "failed to load") || !strings.Contains(msg, tc.reason) || !strings.Contains(msg, policyPath) {
					t.Fatalf("error must name the policy and the reason %q:\n%s", tc.reason, msg)
				}
				if _, statErr := os.Stat(marker); statErr == nil {
					t.Fatal("the workload ran despite the bad policy")
				}
				if data, _ := os.ReadFile(calls); provisioned(string(data)) {
					t.Fatalf("the run provisioned something before rejecting the policy:\n%s", data)
				}
			})
		}
	}
}

// provisioned reports whether a fake-bin call log shows a container or scope
// being created or a workload exec'd.
func provisioned(calls string) bool {
	for _, line := range strings.Split(calls, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		if f[0] == "systemd-run" || f[1] == "run" || f[1] == "exec" || f[1] == "create" || f[1] == "start" {
			return true
		}
	}
	return false
}

// The staged copy leashd reads is validated too: with no policy configured, a
// bad cfgDir/leash.cedar left from an earlier run (or written via the UI) must
// abort rather than be handed to leashd.
func TestValidateStagedPolicyRejectsStaleBadPolicy(t *testing.T) {
	r := &runner{}
	r.cfg.cfgDir = t.TempDir()
	if err := r.validateStagedPolicy(); err != nil {
		t.Fatalf("no staged policy (leashd writes its default) must pass: %v", err)
	}
	staged := filepath.Join(r.cfg.cfgDir, "leash.cedar")
	if err := os.WriteFile(staged, []byte(badPolicies[0].cedar), 0o644); err != nil {
		t.Fatal(err)
	}
	err := r.validateStagedPolicy()
	if err == nil || !strings.Contains(err.Error(), "invalid Cedar policy") || !strings.Contains(err.Error(), staged) {
		t.Fatalf("want the staged policy rejected with its reason: %v", err)
	}
	good := `permit (principal, action in Action::"FileOpen", resource in Dir::"/");` + "\n"
	if err := os.WriteFile(staged, []byte(good), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := r.validateStagedPolicy(); err != nil {
		t.Fatalf("a valid staged policy must pass: %v", err)
	}
}

// A previous run's enforcement-ready marker in a reused share dir must be gone
// before leashd starts, or a leashd that dies early would look ready.
func TestClearStaleEnforcementMarker(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, entrypoint.EnforcementReadyFileName)
	if err := os.WriteFile(marker, []byte(`{"enforcement":"lsm"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := clearStaleEnforcementMarker(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("stale marker still present: %v", err)
	}
	if err := clearStaleEnforcementMarker(dir); err != nil {
		t.Fatalf("absent marker must not error: %v", err)
	}
}
