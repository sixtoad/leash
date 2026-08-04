package runner

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
)

// leash's Layer 1 enforcement is an eBPF LSM program. Those can only attach when
// "bpf" is one of the kernel's *active* LSMs, which in turn requires the kernel
// to be built with CONFIG_BPF_LSM. When that prerequisite is missing the attach
// fails deep inside the leash container with an opaque error; this preflight
// detects the condition on the client and stops early with a fix.

type bpfLSMStatus int

const (
	bpfLSMActive           bpfLSMStatus = iota // "bpf" is in the active LSM list — good to go
	bpfLSMInactiveCompiled                     // CONFIG_BPF_LSM is set, but bpf is not active
	bpfLSMNotCompiled                          // kernel built without CONFIG_BPF_LSM
	bpfLSMUnknown                              // bpf not active and the kernel config is unreadable
)

const (
	activeLSMPath = "/sys/kernel/security/lsm"
	procConfigGz  = "/proc/config.gz"
	osReleasePath = "/proc/sys/kernel/osrelease"
)

// classifyBPFLSM decides the eBPF-LSM status from the active-LSM list and the
// CONFIG_BPF_LSM value ("y"/"m"/"n", or "" when the kernel config is unreadable).
// It is pure so the decision logic can be unit-tested without a real kernel.
func classifyBPFLSM(activeLSMs []string, configBPFLSM string) bpfLSMStatus {
	for _, l := range activeLSMs {
		if strings.TrimSpace(l) == "bpf" {
			return bpfLSMActive
		}
	}
	switch configBPFLSM {
	case "y", "m":
		return bpfLSMInactiveCompiled
	case "n":
		return bpfLSMNotCompiled
	default:
		return bpfLSMUnknown
	}
}

// bpfLSMAdvice renders the actionable remedy for a non-active status. It returns
// "" for bpfLSMActive.
func bpfLSMAdvice(status bpfLSMStatus, activeLSMs []string) string {
	active := strings.Join(activeLSMs, ",")
	switch status {
	case bpfLSMInactiveCompiled:
		return fmt.Sprintf(`This kernel supports the eBPF LSM (CONFIG_BPF_LSM=y) but has not enabled it.
  active LSMs: %s  (missing "bpf")
Enable it by adding bpf to the kernel LSM list and rebooting:
  1. edit /etc/default/grub and append bpf to the lsm= list in GRUB_CMDLINE_LINUX, e.g.
       lsm=%s,bpf
  2. sudo update-grub && sudo reboot
After reboot, %s should include "bpf".`, active, active, activeLSMPath)
	case bpfLSMNotCompiled:
		return fmt.Sprintf(`This kernel was built without CONFIG_BPF_LSM.
  active LSMs: %s
This cannot be enabled at runtime — boot a kernel built with CONFIG_BPF_LSM=y and CONFIG_DEBUG_INFO_BTF=y (Linux >= 5.7).`, active)
	case bpfLSMUnknown:
		return fmt.Sprintf(`"bpf" is not among the active LSMs (%s) and the kernel config could not be read to confirm support.
If this kernel has CONFIG_BPF_LSM, add bpf to the lsm= boot parameter and reboot; otherwise boot a kernel built with CONFIG_BPF_LSM=y (Linux >= 5.7).`, active)
	default:
		return ""
	}
}

// preflightHostKernel checks whether the host kernel can host leash's eBPF LSM
// layer (Layer 1). Following leash's defense-in-depth model — where the MITM
// proxy (Layer 2) is fail-closed and independent — a missing Layer 1 is NOT
// fatal by default: leash warns loudly and continues with proxy-only
// enforcement. `--require-lsm` (or LEASH_REQUIRE_LSM) flips this to a hard stop
// for environments that mandate full enforcement.
//
// The check is only meaningful for a local Linux host-kernel runtime: the
// agent's container shares the host kernel, so /sys here describes the kernel
// leash attaches to. On macOS the kernel lives in a VM and remote daemons run
// elsewhere, so those are deferred to leashd in-guest and skipped here.
func (r *runner) preflightHostKernel() error {
	if runtime.GOOS != "linux" {
		return nil
	}
	if strings.TrimSpace(os.Getenv("DOCKER_HOST")) != "" {
		return nil // remote daemon — the kernel that matters is not this host's
	}

	active, err := readActiveLSMs()
	if err != nil {
		// securityfs not mounted / unreadable: we can't tell, so don't block —
		// leashd will surface any real attach failure from inside the container.
		return nil
	}
	status := classifyBPFLSM(active, readKernelConfigBPFLSM())
	warn, err := decideBPFLSM(status, active, r.cfg.requireLSM)
	if err != nil {
		return err
	}
	if warn != "" && r.logger != nil {
		r.logger.Printf("%s", warn)
	}
	return nil
}

// decideBPFLSM turns a status into either a fatal error (when requireLSM) or a
// loud warning (the default proxy-only degrade). For bpfLSMActive it returns
// ("", nil). Pure, so the warn-vs-fail policy is unit-testable.
func decideBPFLSM(status bpfLSMStatus, active []string, requireLSM bool) (string, error) {
	if status == bpfLSMActive {
		return "", nil
	}
	advice := bpfLSMAdvice(status, active)
	if requireLSM {
		return "", fmt.Errorf("eBPF LSM enforcement (Layer 1) is unavailable and --require-lsm is set, so leash will not start.\n%s", advice)
	}
	return "WARNING: eBPF LSM enforcement (Layer 1) is unavailable; continuing with proxy-only enforcement (Layer 2 is fail-closed). Filesystem/exec/socket policies will NOT be enforced — pass --require-lsm to require Layer 1.\n" + advice, nil
}

// LSMState is the tri-state answer to "is leash's Layer 1 (eBPF LSM) available
// on this kernel?". It is a tri-state because "we could not read the active LSM
// list" and "we read it and bpf is absent" call for different remedies, and
// collapsing them is how doctor came to print a remedy that would have
// dismantled the host's LSM stack (see unreadableLSMListAdvice).
//
// The zero value is LSMUnknown so a partially-built value never claims more
// than it knows, and the ordering (unknown < inactive < active) is not
// meaningful — compare against the constants, not with <.
type LSMState int

const (
	LSMUnknown  LSMState = iota // the active-LSM list could not be read
	LSMInactive                 // read, and "bpf" is not in it
	LSMActive                   // read, and "bpf" is in it
)

// String is the wire form used by `leash doctor --json`.
func (s LSMState) String() string {
	switch s {
	case LSMActive:
		return "active"
	case LSMInactive:
		return "inactive"
	default:
		return "unknown"
	}
}

// MarshalJSON emits the string form, so the doctor payload carries
// "active"/"inactive"/"unknown" rather than an integer whose meaning would have
// to be documented separately.
func (s LSMState) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

// unreadableLSMListAdvice is the remedy for LSMUnknown. It deliberately offers
// no `lsm=` line: the only safe lsm= value is one built from the host's real
// LSM list, and by definition we could not read it. Emitting `lsm=,bpf` here —
// which is what a nil list rendered into the bpfLSMInactiveCompiled template
// produces — tells the operator to *replace* their LSM stack, silently
// disabling AppArmor/SELinux (or leaving the host unbootable).
const unreadableLSMListAdvice = `the active LSM list (` + activeLSMPath + `) could not be read, so eBPF LSM (Layer 1) availability is unknown.
On Linux, mount securityfs (mount -t securityfs securityfs /sys/kernel/security) and re-run, or read the list as root.
Do not guess at a boot-time LSM list: that parameter replaces the kernel's list wholesale and can disable AppArmor/SELinux.`

// ProbeBPFLSM reports whether leash's Layer 1 (eBPF LSM) can attach on this
// host, plus the remedy text when it cannot ("" when it can). It is the
// exported seam for `leash doctor` (internal/doctor).
//
// The classification and the advice deliberately stay here, next to the code a
// real run uses, so the self-check cannot drift from leash's actual
// requirement — drift is exactly what issue #23 asks us to eliminate for walk.
//
// Note that this is the list-based check (is "bpf" among the active LSMs), not
// an attachability probe; doctor reports that distinction rather than hiding it
// (follow-up issue #52).
func ProbeBPFLSM() (state LSMState, advice string) {
	lsms, err := readActiveLSMs()
	return decideLSMState(lsms, err, readKernelConfigBPFLSM())
}

// decideLSMState is the pure half of ProbeBPFLSM, so the "list unreadable"
// branch is testable without unmounting securityfs.
//
// readErr is threaded in rather than swallowed at the call site: the previous
// version turned a read failure into an empty list and let classifyBPFLSM run
// on it, which reports bpfLSMInactiveCompiled whenever CONFIG_BPF_LSM=y — and
// bpfLSMAdvice then renders that empty list into `lsm=,bpf`.
func decideLSMState(activeLSMs []string, readErr error, configBPFLSM string) (LSMState, string) {
	if readErr != nil {
		return LSMUnknown, unreadableLSMListAdvice
	}
	status := classifyBPFLSM(activeLSMs, configBPFLSM)
	if status == bpfLSMActive {
		return LSMActive, ""
	}
	return LSMInactive, bpfLSMAdvice(status, activeLSMs)
}

func readActiveLSMs() ([]string, error) {
	data, err := os.ReadFile(activeLSMPath)
	if err != nil {
		return nil, err
	}
	return strings.Split(strings.TrimSpace(string(data)), ","), nil
}

// readKernelConfigBPFLSM returns the CONFIG_BPF_LSM value ("y"/"m"/"n"), or ""
// when the kernel config can't be located/read. It tries /proc/config.gz first,
// then /boot/config-<release>.
func readKernelConfigBPFLSM() string {
	if f, err := os.Open(procConfigGz); err == nil {
		defer f.Close()
		if gz, gzErr := gzip.NewReader(f); gzErr == nil {
			defer gz.Close()
			if v, ok := parseConfigValue(gz, "CONFIG_BPF_LSM"); ok {
				return v
			}
		}
	}
	if release := kernelRelease(); release != "" {
		if f, err := os.Open("/boot/config-" + release); err == nil {
			defer f.Close()
			if v, ok := parseConfigValue(f, "CONFIG_BPF_LSM"); ok {
				return v
			}
		}
	}
	return ""
}

// parseConfigValue scans a kernel config stream for `key=<value>` (returning the
// value) or the canonical `# key is not set` line (returning "n").
func parseConfigValue(r io.Reader, key string) (string, bool) {
	prefix := key + "="
	notSet := "# " + key + " is not set"
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, prefix) {
			return strings.Trim(strings.TrimPrefix(line, prefix), `"`), true
		}
		if line == notSet {
			return "n", true
		}
	}
	return "", false
}

func kernelRelease() string {
	data, err := os.ReadFile(osReleasePath)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
