package runner

import (
	"bufio"
	"compress/gzip"
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

// bpfLSMError renders an actionable error for a non-active status. It returns
// nil for bpfLSMActive.
func bpfLSMError(status bpfLSMStatus, activeLSMs []string) error {
	active := strings.Join(activeLSMs, ",")
	switch status {
	case bpfLSMInactiveCompiled:
		return fmt.Errorf(`leash needs the eBPF LSM, which this kernel supports (CONFIG_BPF_LSM=y) but has not enabled.
  active LSMs: %s  (missing "bpf")
Enable it by adding bpf to the kernel LSM list and rebooting:
  1. edit /etc/default/grub and append bpf to the lsm= list in GRUB_CMDLINE_LINUX, e.g.
       lsm=%s,bpf
  2. sudo update-grub && sudo reboot
After reboot, %s should include "bpf".`, active, active, activeLSMPath)
	case bpfLSMNotCompiled:
		return fmt.Errorf(`leash needs the eBPF LSM, but this kernel was built without CONFIG_BPF_LSM.
  active LSMs: %s
This cannot be enabled at runtime — boot a kernel built with CONFIG_BPF_LSM=y and CONFIG_DEBUG_INFO_BTF=y (Linux >= 5.7).`, active)
	case bpfLSMUnknown:
		return fmt.Errorf(`leash needs the eBPF LSM, but "bpf" is not among the active LSMs (%s) and the kernel config could not be read to confirm support.
If this kernel has CONFIG_BPF_LSM, add bpf to the lsm= boot parameter and reboot; otherwise boot a kernel built with CONFIG_BPF_LSM=y (Linux >= 5.7).`, active)
	default:
		return nil
	}
}

// preflightHostKernel verifies the host kernel can host leash's eBPF LSM layer.
// It is only meaningful for a local Linux host-kernel runtime: the agent's
// container shares the host kernel, so /sys here describes the kernel leash
// attaches to. On macOS the kernel lives in a VM and remote daemons run
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
	if status == bpfLSMActive {
		return nil
	}
	return bpfLSMError(status, active)
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
