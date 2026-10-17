package leashd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/strongdm/leash/internal/enforcerd"
	"github.com/strongdm/leash/internal/policy"
)

// Fail-closed exit for a policy change that could neither be applied nor
// rolled back (#193). By then the policy manager has set deny-all in the
// kernel and in userspace and refuses further changes; what is left is to
// stop the workload, since a kernel module whose deny-all write also failed
// has an unknown state.
var (
	killWorkloadCgroup = enforcerd.KillCgroup
	exitLeashd         = os.Exit
	// failClosedExitDelay lets the API call that triggered the failure
	// answer with its error before leashd exits.
	failClosedExitDelay = 250 * time.Millisecond
)

// policyFailedClosed is the policy manager's fail-closed handler.
//
// The workload's cgroup is killed, then leashd exits non-zero: launchers treat
// a dead leashd as fail-closed (the rootless watcher kills the target when the
// leash container stops). If the workload cannot be stopped and leashd itself
// holds the eBPF programs, leashd stays up instead: exiting would detach the
// deny-all programs and leave whatever survived unenforced.
func (rt *runtimeState) policyFailedClosed(aerr *policy.ApplyError) {
	rt.policyReady.Store(false)
	cgroup := ""
	if rt.cfg != nil {
		cgroup = strings.TrimSpace(rt.cfg.CgroupPath)
	}
	remote := rt.remote != nil
	fmt.Fprintln(os.Stderr, FatalLine(fmt.Errorf("a policy change could not be applied or rolled back; enforcement failed closed (deny-all), stopping the workload: %w", aerr)))
	fields := map[string]any{"component": aerr.Component, "error": aerr.Error()}

	stopped := false
	if cgroup == "" {
		fields["workload"] = "no workload cgroup to stop; the proxy denies everything"
	} else if err := killWorkloadCgroup(cgroup); err != nil {
		fmt.Fprintf(os.Stderr, "leash: FATAL: could not stop the workload in %s: %v\n", cgroup, err)
		fields["workload"] = "stop failed: " + err.Error()
	} else {
		stopped = true
		fields["workload"] = "stopped"
	}
	logPolicyEvent("policy.failclosed", fields)

	if !stopped && !remote {
		if cgroup == "" {
			fmt.Fprintln(os.Stderr, "leash: leashd stays up so its proxy keeps denying everything")
		} else {
			fmt.Fprintln(os.Stderr, "leash: leashd stays up so the deny-all eBPF programs it holds stay attached")
		}
		return
	}
	go func() {
		time.Sleep(failClosedExitDelay)
		exitLeashd(1)
	}()
}
