package doctor

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/strongdm/leash/internal/macext"
)

// The macOS half of probe.go: the only part of the darwin path that touches the
// machine. Same rule as the rest of the package — every check here is a lookup
// with no policy in it, and darwin.go decides what the answers mean.
//
// There is no build tag, and this file must not use a _darwin.go suffix: Go
// treats that suffix as an implicit build constraint. The probes are ordinary
// exec/HTTP/stat calls that compile everywhere, and gating them on runtime.GOOS
// instead keeps the whole file reachable from tests on any host — which matters
// more here than usual, because the interesting states (extension activated but
// disconnected, FDA denied) cannot be produced on a developer's Mac on demand.

// DefaultDarwinDaemonAddr is where the `leash --darwin` daemon listens by
// default (internal/darwind: --ws-port 18080).
const DefaultDarwinDaemonAddr = "127.0.0.1:18080"

// DefaultLeashCLIPath mirrors darwind's defaultLeashCLIPath — the companion
// binary `leash --darwin` execs to launch a workload.
const DefaultLeashCLIPath = "/Applications/Leash.app/Contents/Resources/leashcli"

// darwinProbeTimeout bounds every network call in the macOS probe. doctor is a
// self-check a provisioner runs in a gate: a daemon that accepts a connection
// and never answers must produce a verdict, not a hang.
const darwinProbeTimeout = 2 * time.Second

// Seams. They are vars rather than parameters so the probe keeps the same
// zero-configuration shape as the rest of the package, and so a test can drive
// the states a real Mac will not reproduce on demand.
var (
	// systemExtensionsList runs the same command the Leash.app GUI and the
	// --darwin preflight use, so all three read one source of truth.
	systemExtensionsList = func() (string, error) {
		out, err := exec.Command("/usr/bin/systemextensionsctl", "list").CombinedOutput()
		return string(out), err
	}

	// darwinHTTPGet fetches one URL from the local daemon.
	darwinHTTPGet = func(url string) (int, []byte, error) {
		client := &http.Client{Timeout: darwinProbeTimeout}
		resp, err := client.Get(url)
		if err != nil {
			return 0, nil, err
		}
		defer func() { _ = resp.Body.Close() }()
		// Bounded: doctor is reading a small health document, and an
		// unbounded read from a misidentified port is a way to hang.
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return resp.StatusCode, body, err
	}

	statFile = func(path string) error {
		_, err := os.Stat(path)
		return err
	}
)

// probeDarwin fills the macOS facts. On any other platform it returns the zero
// DarwinHost with Checked false, which darwin.go reports as "this is not a Mac"
// rather than as a broken macOS install.
func probeDarwin(opts ProbeOptions) DarwinHost {
	if runtime.GOOS != "darwin" {
		return DarwinHost{}
	}
	return probeDarwinFacts(opts)
}

// probeDarwinFacts is probeDarwin without the platform gate, which is what
// makes the macOS matrix testable off macOS — and, more to the point, testable
// at all: "activated but disconnected" and "FDA denied" are states a developer
// cannot conjure on their own Mac on demand, so the only way they are ever
// exercised is through the seams above.
func probeDarwinFacts(opts ProbeOptions) DarwinHost {
	d := DarwinHost{
		Checked:      true,
		DaemonAddr:   darwinDaemonAddr(opts),
		LeashCLIPath: leashCLIPath(opts),
	}

	// Activation, from systemextensionsctl. One invocation for all three
	// extensions: they come out of the same table, and three calls could
	// disagree with each other if the user is approving one while doctor runs.
	out, err := systemExtensionsList()
	if err != nil {
		// Includes EX_NOPERM (69) without admin rights. Every state stays
		// unknown — the command never answered, so nothing about installation
		// was established.
		d.ExtensionsDetail = summariseCommandFailure(out, err)
	} else {
		d.ESExtension = macext.Parse(out, macext.EndpointSecurityExtensionID())
		d.FilterExtension = macext.Parse(out, macext.NetworkFilterExtensionID())
		d.ProxyExtension = macext.Parse(out, macext.TransparentProxyExtensionID())
	}

	// The daemon, and through it the two facts only it can see. /healthz first,
	// so "the daemon is down" and "the daemon is old" stay distinguishable:
	// without the split, a build predating /health/darwin would report as
	// unreachable and send the operator to start a daemon already running.
	if err := pingDarwinDaemon(d.DaemonAddr); err != nil {
		d.DaemonError = err.Error()
	} else {
		d.DaemonUp = true
		health, err := fetchDarwinHealth(d.DaemonAddr)
		if err != nil {
			d.HealthError = err.Error()
		} else {
			d.ComponentsKnown = true
			d.Components = health.Components
			d.FullDiskAccess = macext.ParseFDA(health.FullDiskAccess)
		}
	}

	d.LeashCLIPresent = statFile(d.LeashCLIPath) == nil
	return d
}

// darwinDaemonAddr resolves where to look for the daemon: the explicit flag
// first, then LEASH_LISTEN (which is what the daemon itself reads), then the
// default. A bare port or ":18080" is completed to loopback, because doctor has
// to dial it and the daemon's own bind syntax allows the host to be omitted.
func darwinDaemonAddr(opts ProbeOptions) string {
	addr := strings.TrimSpace(opts.DarwinDaemonAddr)
	if addr == "" {
		addr = strings.TrimSpace(os.Getenv("LEASH_LISTEN"))
	}
	if addr == "" {
		return DefaultDarwinDaemonAddr
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		// Not host:port at all — most likely a bare port, which is what
		// `--ws-port 18080` hands around.
		return net.JoinHostPort("127.0.0.1", addr)
	}
	if strings.TrimSpace(host) == "" || host == "0.0.0.0" || host == "::" {
		// A wildcard bind is reachable on loopback, and loopback is the only
		// interface doctor may assume it can talk to.
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

func leashCLIPath(opts ProbeOptions) string {
	if path := strings.TrimSpace(opts.LeashCLIPath); path != "" {
		return path
	}
	return DefaultLeashCLIPath
}

// pingDarwinDaemon reports whether the daemon is answering HTTP, not merely
// whether something holds the port. A bare TCP dial would call any listener a
// leash daemon.
func pingDarwinDaemon(addr string) error {
	status, _, err := darwinHTTPGet(fmt.Sprintf("http://%s/healthz", addr))
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("/healthz answered HTTP %d", status)
	}
	return nil
}

// fetchDarwinHealth reads the daemon's macOS readiness document. A 404 is
// called out by name: it is what a daemon built before this endpoint existed
// returns, and "upgrade the daemon" is a different remedy from "the daemon is
// broken".
func fetchDarwinHealth(addr string) (macext.DaemonHealth, error) {
	status, body, err := darwinHTTPGet(fmt.Sprintf("http://%s/health/darwin", addr))
	if err != nil {
		return macext.DaemonHealth{}, err
	}
	if status == http.StatusNotFound {
		return macext.DaemonHealth{}, errors.New("HTTP 404: this daemon predates the /health/darwin endpoint")
	}
	if status != http.StatusOK {
		return macext.DaemonHealth{}, fmt.Errorf("HTTP %d", status)
	}
	var health macext.DaemonHealth
	if err := json.Unmarshal(body, &health); err != nil {
		return macext.DaemonHealth{}, fmt.Errorf("could not decode the health document: %w", err)
	}
	return health, nil
}

// summariseCommandFailure turns a failed exec into one line: the error, plus
// whatever the command said, trimmed to the first line. systemextensionsctl's
// EX_NOPERM message is the actionable part, and a multi-line dump inside a
// JSON issue is not.
func summariseCommandFailure(out string, err error) string {
	msg := err.Error()
	if first := firstLine(out); first != "" {
		msg = fmt.Sprintf("%s (%s)", msg, first)
	}
	return msg
}

func firstLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
