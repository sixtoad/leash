package leashd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/strongdm/leash/internal/assets"
	"github.com/strongdm/leash/internal/authz"
	cedarutil "github.com/strongdm/leash/internal/cedar"
	"github.com/strongdm/leash/internal/enforcement"
	"github.com/strongdm/leash/internal/enforcerd"
	"github.com/strongdm/leash/internal/entrypoint"
	"github.com/strongdm/leash/internal/httpserver"
	"github.com/strongdm/leash/internal/idmap"
	"github.com/strongdm/leash/internal/leashd/listen"
	"github.com/strongdm/leash/internal/lsm"
	"github.com/strongdm/leash/internal/policy"
	"github.com/strongdm/leash/internal/proxy"
	"github.com/strongdm/leash/internal/telemetry/otel"
	"github.com/strongdm/leash/internal/telemetry/statsig"
	"github.com/strongdm/leash/internal/ui"
	websockethub "github.com/strongdm/leash/internal/websocket"
)

const (
	defaultBootstrapTimeout = 2 * time.Minute
)

type stringFlag struct {
	value string
	set   bool
}

func (s *stringFlag) String() string {
	return s.value
}

func (s *stringFlag) Set(value string) error {
	s.value = value
	s.set = true
	return nil
}

// Main runs the leash daemon runtime using the provided argv slice.
// When args is empty, os.Args is used.
func Main(args []string) error {
	if len(args) == 0 {
		args = os.Args
	}

	if extra := strings.TrimSpace(os.Getenv("LEASH_EXTRA_ARGS")); extra != "" {
		args = append(args, splitExtraArgs(extra)...)
	}

	cfg, err := parseConfig(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if raw := strings.TrimSpace(os.Getenv(idmap.Env)); raw != "" {
		specs, err := idmap.Decode(raw)
		if err != nil {
			return fmt.Errorf("decode idmapped mount bootstrap: %w", err)
		}
		if err := idmap.Apply(specs); err != nil {
			return fmt.Errorf("apply idmapped mount bootstrap: %w", err)
		}
	}

	sessionID := strings.TrimSpace(os.Getenv("LEASH_SESSION_ID"))
	workspaceHash := strings.TrimSpace(os.Getenv("LEASH_WORKSPACE_HASH"))
	statsig.Start(context.Background(), statsig.StartPayload{
		Mode:        "leashd",
		SessionID:   sessionID,
		WorkspaceID: workspaceHash,
	})
	defer statsig.Stop(context.Background())

	// Every launcher must wait for the same post-attach signal. Container mode
	// previously observed bootstrap.ready, which is written before the LSM attach
	// goroutines settle and let the workload race ahead unenforced.
	if err := lsm.SetAuditConfig(cfg.Audit); err != nil {
		return err
	}
	enableEnforcementReady(cfg)
	if cfg.HostMode {
		enableHostMode()
	}

	// An LSM attach failure exits leashd before the attempt is reported
	// settled (fail-closed), so no launcher is ever released past it.
	lsm.SetRequireLSM(true)

	// Clear any stale readiness markers before anything can fail: a leashd that
	// exits during preflight (e.g. a policy that does not parse) must never
	// leave a previous run's enforcement-ready marker for a launcher to accept.
	leashDir := getLeashDirFromEnv()
	if err := clearReadyMarkers(leashDir); err != nil {
		return fmt.Errorf("prepare readiness markers: %w", err)
	}

	// Observe SIGINT/SIGTERM through one sticky process-wide latch from the
	// start: the LSM attach goroutines (spawned by the initial policy load in
	// initRuntime) and every later wait share it, so a stop request at any phase
	// shuts leashd down instead of being swallowed by whichever listener
	// happened to be registered (#143).
	lsm.InstallShutdownHandler()

	if err := preFlight(cfg); err != nil {
		return err
	}

	if err := entrypoint.InflateBinaries(leashDir); err != nil {
		return err
	}

	rt, err := initRuntime(cfg, leashDir)
	if err != nil {
		return err
	}
	defer rt.Close()

	return rt.Run()
}

// logPolicyEvent emits compact structured event logs: event=<name> key=value ...
func logPolicyEvent(event string, fields map[string]any) {
	buf := "event=" + event
	for k, v := range fields {
		buf += " " + k + "=" + fmt.Sprint(v)
	}
	log.Printf(buf)
	if event == "policy.update" {
		statsig.RecordPolicyUpdate(fields)
	}
}

type runtimeConfig struct {
	LogPath          string
	PolicyPath       string
	ProxyPort        string
	WebBind          string
	WebDisabled      bool
	HistorySize      int
	BulkMaxEvents    int
	BulkMaxBytes     int
	CgroupPath       string
	BootstrapTimeout time.Duration
	HostMode         bool
	LSMOnly          bool
	// EnforcerSocket, when set, is the leash enforcer daemon's socket: the
	// eBPF LSM programs are attached by the daemon instead of by leashd
	// (rootless runs, docs/ROOTLESS.md).
	EnforcerSocket string
	// EnforcerBroker, when set, is the leash client's broker socket: leashd
	// receives its daemon connection from the client instead of dialing
	// EnforcerSocket (rootless Docker, whose containers cannot keep the
	// caller's leash group).
	EnforcerBroker string
	// Audit is the eBPF audit posture: ring buffer size and lossless mode
	// (issue #241).
	Audit           lsm.AuditConfig
	MCPConfig       proxy.MCPConfig
	TelemetryConfig otel.Config
}

// viaEnforcerDaemon reports whether the eBPF LSM is attached by the leash
// enforcer daemon (rootless runs) rather than by this process.
func (c *runtimeConfig) viaEnforcerDaemon() bool {
	return c.EnforcerSocket != "" || c.EnforcerBroker != ""
}

type runtimeState struct {
	cfg               *runtimeConfig
	logger            *lsm.SharedLogger
	wsHub             *websockethub.WebSocketHub
	headerRewriter    *proxy.HeaderRewriter
	mitmProxy         *proxy.MITMProxy
	lsmManager        *lsm.LSMManager
	policyManager     *policy.Manager
	decisions         *policy.Decisions // the engine shared by the proxy and the authz socket
	authzServer       *authz.Server     // plugin authz sockets (#142); nil when no plugin asked for one
	remote            *remoteKernel     // the enforcer daemon session (rootless); nil when leashd attaches itself
	remotePrograms    int               // programs the daemon attached
	remoteErr         error             // why the daemon did not attach
	policyWatcherStop func()
	policyReady       atomic.Bool
	closeOnce         sync.Once
	bootstrapPath     string
	telemetryProvider *otel.Provider
}

// parseConfig reads CLI flags and environment hints to build the runtime configuration.
func parseConfig(args []string) (*runtimeConfig, error) {
	name := commandName(args)
	fs := flag.NewFlagSet(name, flag.ContinueOnError)

	defaultLogPath := strings.TrimSpace(os.Getenv("LEASH_LOG"))
	logPath := fs.String("log", defaultLogPath, "Event log file path (optional)")

	// The container fallback (/cfg/leash.cedar) is applied post-parse so host
	// mode can substitute a host-appropriate default instead.
	policyPath := fs.String("policy", strings.TrimSpace(os.Getenv("LEASH_POLICY")), "Cedar policy file path")
	hostMode := fs.Bool("host", leashdEnvTruthy("LEASH_HOST"), "Run as a host process (no container): host-appropriate path defaults; enforcement needs CAP_BPF and an active bpf LSM. See docs/LEASHD-HOST-MODE.md")
	lsmOnly := fs.Bool("lsm-only", leashdEnvTruthy("LEASH_LSM_ONLY"), "Enforce with the eBPF LSM only (file/exec/network-connect); skip the L7 MITM proxy and its netfilter. Used by native until netns egress lands.")
	_ = fs.Bool("require-lsm", false, "Accepted for compatibility; no effect. leash always refuses to run the workload unenforced if the eBPF LSM can't attach.")

	proxyPort := fs.String("proxy-port", "18000", "Proxy port")
	listenFlag := &stringFlag{}
	fs.Var(listenFlag, "listen", "Serve Control UI and API on the provided address (e.g. :18080, 127.0.0.1:18080). Leave blank to disable.")
	fs.Var(listenFlag, "l", "Alias for --listen")

	historySize := fs.Int("history-size", 25000, "Number of events to keep in memory for new connections")
	bulkMaxEvents := fs.Int("ws-bulk-max-events", 2000, "Max events to include in initial WebSocket bulk message (0 = unlimited)")
	bulkMaxBytes := fs.Int("ws-bulk-max-bytes", 1_000_000, "Max bytes to include in initial WebSocket bulk message (0 = unlimited)")
	defaultCgroupPath := strings.TrimSpace(os.Getenv("LEASH_CGROUP_PATH"))
	cgroupFlag := fs.String("cgroup", defaultCgroupPath, "Cgroup path to monitor")
	enforcerSocket := fs.String("enforcer-socket", strings.TrimSpace(os.Getenv(enforcerd.EnvSocket)), "Attach the eBPF LSM through the leash enforcer daemon listening on this socket (rootless runs) instead of loading it in this process")
	enforcerBroker := fs.String("enforcer-broker", strings.TrimSpace(os.Getenv(enforcerd.EnvBroker)), "Attach the eBPF LSM through the leash enforcer daemon, using the connection the leash client hands over on this broker socket (rootless Docker)")
	auditRingKB := fs.String("audit-ringbuf-kb", strings.TrimSpace(os.Getenv(lsm.EnvAuditRingBufferKB)), "Size of each eBPF LSM object's audit ring buffer in KiB (power of two, 64..262144; default 1024). Records that do not fit are counted and reported as audit.dropped")
	auditLossless := fs.Bool("audit-lossless", leashdEnvTruthy(lsm.EnvAuditLossless), "Lossless audit: deny an operation whose audit record cannot be written (ring buffer full) instead of deciding it without a record")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s [flags]\n\n", name)
		fmt.Fprintf(fs.Output(), "Flags:\n")
		fs.PrintDefaults()
		fmt.Fprintf(fs.Output(), "\nEnvironment:\n  LEASH_CGROUP_PATH       Default value for --cgroup\n  LEASH_LISTEN            Default value for --listen (blank disables Control UI)\n  LEASH_EXTRA_ARGS        Additional CLI arguments\n  LEASH_REQUIRE_LSM       Accepted for compatibility; no effect (fail-closed is the only posture)\n")
	}

	var flagArgs []string
	if len(args) > 1 {
		flagArgs = args[1:]
	}
	if err := fs.Parse(flagArgs); err != nil {
		return nil, err
	}

	if len(fs.Args()) > 0 {
		return nil, fmt.Errorf("unexpected extra arguments: %v", fs.Args())
	}

	listenCfg := listen.Default()
	if listenFlag.set {
		parsed, err := listen.Parse(listenFlag.value)
		if err != nil {
			return nil, fmt.Errorf("parse --listen: %w", err)
		}
		listenCfg = parsed
	} else if raw, ok := os.LookupEnv("LEASH_LISTEN"); ok {
		parsed, err := listen.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("parse LEASH_LISTEN: %w", err)
		}
		listenCfg = parsed
	}

	timeout := defaultBootstrapTimeout
	if raw := strings.TrimSpace(os.Getenv("LEASH_BOOTSTRAP_TIMEOUT")); raw != "" {
		parsed, err := parseBootstrapTimeout(raw)
		if err != nil {
			return nil, fmt.Errorf("parse LEASH_BOOTSTRAP_TIMEOUT: %w", err)
		}
		if parsed <= 0 {
			return nil, fmt.Errorf("LEASH_BOOTSTRAP_TIMEOUT must be positive")
		}
		timeout = parsed
	}

	auditCfg := lsm.AuditConfig{Lossless: *auditLossless}
	if v := strings.TrimSpace(*auditRingKB); v != "" {
		size, err := lsm.ParseAuditRingBufferKB(v)
		if err != nil {
			return nil, fmt.Errorf("parse --audit-ringbuf-kb: %w", err)
		}
		auditCfg.RingBufferBytes = size
	}

	cfg := &runtimeConfig{
		LogPath:          strings.TrimSpace(*logPath),
		PolicyPath:       resolvePolicyPath(strings.TrimSpace(*policyPath), *hostMode),
		ProxyPort:        strings.TrimSpace(*proxyPort),
		WebBind:          listenCfg.Address(),
		WebDisabled:      listenCfg.Disable,
		HistorySize:      *historySize,
		BulkMaxEvents:    *bulkMaxEvents,
		BulkMaxBytes:     *bulkMaxBytes,
		CgroupPath:       strings.TrimSpace(*cgroupFlag),
		BootstrapTimeout: timeout,
		HostMode:         *hostMode,
		LSMOnly:          *lsmOnly,
		EnforcerSocket:   strings.TrimSpace(*enforcerSocket),
		EnforcerBroker:   strings.TrimSpace(*enforcerBroker),
		Audit:            auditCfg,
	}
	cfg.MCPConfig = loadMCPConfigFromEnv()
	cfg.TelemetryConfig = otel.LoadConfigFromEnv()

	return cfg, nil
}

// resolvePolicyPath applies the default policy location when none was given. In
// container mode that is the image's /cfg/leash.cedar; in host mode there is no
// /cfg, so default under the host shared dir (LEASH_DIR, or its /leash
// fallback) instead of an unwritable container path.
func resolvePolicyPath(explicit string, hostMode bool) string {
	if explicit != "" {
		return explicit
	}
	if hostMode {
		return filepath.Join(getLeashDirFromEnv(), "leash.cedar")
	}
	return "/cfg/leash.cedar"
}

// leashdEnvTruthy reports whether an env var is set to a truthy value
// (1/true/yes/on, case-insensitive). Used for boolean flag defaults.
func leashdEnvTruthy(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func preFlight(cfg *runtimeConfig) error {
	if cfg == nil {
		return fmt.Errorf("runtime configuration required")
	}
	policyPath := strings.TrimSpace(cfg.PolicyPath)
	if policyPath == "" {
		return fmt.Errorf("policy file path required")
	}
	if err := policy.EnsureDefaultCedarFile(policyPath); err != nil {
		return err
	}
	if _, err := policy.Parse(policyPath); err != nil {
		var detail *cedarutil.ErrorDetail
		if errors.As(err, &detail) {
			return errors.New(formatCedarErrorForCLI(detail))
		}
		return fmt.Errorf("failed to parse Cedar policy: %w", err)
	}

	if strings.TrimSpace(cfg.CgroupPath) == "" {
		// No scopable cgroup (e.g. Docker Desktop Kubernetes, where the
		// container's private cgroup namespace reports "0::/"): kernel BPF-LSM
		// enforcement cannot be scoped to the target, so the run is refused —
		// leash never runs a workload with only the L7 proxy enforcing. See
		// issue #67.
		return fmt.Errorf("no cgroup path: eBPF LSM enforcement (file/exec/connect) cannot be scoped to the workload; refusing to run it unenforced (%s)", enforcement.FailClosedRemedy)
	}
	info, err := os.Stat(cfg.CgroupPath)
	if err != nil {
		return fmt.Errorf("invalid cgroup path %q: %w", cfg.CgroupPath, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("invalid cgroup path %q: not a directory", cfg.CgroupPath)
	}
	controllersPath := filepath.Join(cfg.CgroupPath, "cgroup.controllers")
	if _, err := os.Stat(controllersPath); err != nil {
		return fmt.Errorf("invalid cgroup path %q: %v", cfg.CgroupPath, err)
	}

	logPath := strings.TrimSpace(cfg.LogPath)
	if logPath != "" {
		dir := filepath.Dir(logPath)
		if dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return fmt.Errorf("failed to create log directory %q: %w", dir, err)
			}
		}
		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return fmt.Errorf("failed to access log file %q: %w", logPath, err)
		}
		if err := f.Close(); err != nil {
			return fmt.Errorf("failed to close log file %q: %w", logPath, err)
		}
	}

	if strings.TrimSpace(cfg.ProxyPort) == "" {
		return fmt.Errorf("proxy port required")
	}
	port, err := strconv.Atoi(cfg.ProxyPort)
	if err != nil || port <= 0 || port > 65535 {
		return fmt.Errorf("invalid proxy port %q", cfg.ProxyPort)
	}

	if runtime.GOOS == "linux" {
		if _, err := exec.LookPath("mount"); err != nil {
			return fmt.Errorf("mount command not found: %w", err)
		}
		if _, err := findIptables(); err != nil {
			return err
		}
	}

	privateDir := strings.TrimSpace(os.Getenv("LEASH_PRIVATE_DIR"))
	if privateDir == "" {
		return fmt.Errorf("LEASH_PRIVATE_DIR environment variable is required")
	}
	info, err = os.Stat(privateDir)
	if err != nil {
		return fmt.Errorf("validate LEASH_PRIVATE_DIR %q: %w", privateDir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("LEASH_PRIVATE_DIR %q is not a directory", privateDir)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		if err := os.Chmod(privateDir, 0o700); err != nil {
			log.Printf("Warning: expected LEASH_PRIVATE_DIR=%s permissions 0700 but found %o; chmod failed: %v", privateDir, perm, err)
			return fmt.Errorf("LEASH_PRIVATE_DIR %q must have permission 0700 (got %o)", privateDir, perm)
		}
		log.Printf("Warning: adjusted LEASH_PRIVATE_DIR permissions from %o to 0700", perm)
	}
	keyPath := filepath.Join(privateDir, "ca-key.pem")
	if keyInfo, err := os.Stat(keyPath); err == nil {
		if keyInfo.IsDir() {
			return fmt.Errorf("CA key path %q is a directory", keyPath)
		}
		if keyPerm := keyInfo.Mode().Perm(); keyPerm != 0o600 {
			return fmt.Errorf("CA key %q must have permission 0600 (got %o)", keyPath, keyPerm)
		}
	}

	publicDir := getLeashDirFromEnv()
	log.Printf("leashd_mounts public=%s private=%s", publicDir, privateDir)

	return nil
}

func initRuntime(cfg *runtimeConfig, leashDir string) (*runtimeState, error) {
	logger, err := lsm.NewSharedLogger(cfg.LogPath)
	if err != nil {
		return nil, err
	}

	wsHub := websockethub.NewWebSocketHub(logger, cfg.HistorySize, cfg.BulkMaxEvents, cfg.BulkMaxBytes)
	go wsHub.Run()
	logger.SetBroadcaster(wsHub)

	// An eBPF LSM attach failure is fatal (fail-closed). With the enforcer
	// daemon the programs live in the daemon: the local
	// manager keeps the compiled tables but attaches nothing.
	lsmCgroup := cfg.CgroupPath
	if cfg.viaEnforcerDaemon() {
		lsmCgroup = ""
	}
	lsmManager := lsm.NewLSMManager(lsmCgroup, logger, true)
	lsmManager.SetContainerRootfs(!cfg.HostMode)
	lsm.BumpMemlockRlimit()

	headerRewriter := proxy.NewHeaderRewriter()
	headerRewriter.SetSharedLogger(logger)

	telemetryProvider, err := otel.Setup(context.Background(), cfg.TelemetryConfig)
	if err != nil {
		logger.Close()
		return nil, fmt.Errorf("failed to initialize telemetry: %w", err)
	}
	cfg.MCPConfig.Telemetry = telemetryProvider.MCP()

	initialPolicy, err := policy.Parse(cfg.PolicyPath)
	if err != nil {
		logger.Close()
		var detail *cedarutil.ErrorDetail
		if errors.As(err, &detail) {
			return nil, errors.New(formatCedarErrorForCLI(detail))
		}
		return nil, fmt.Errorf("failed to parse Cedar policy: %w", err)
	}

	// One engine per policy change, shared by the proxy and the authz socket (#142).
	decisions := &policy.Decisions{}
	initialEngine := decisions.Publish(initialPolicy.Compilation.Engine)

	// n.b. This kicks off certificate creation.
	mitmProxy, err := proxy.NewMITMProxy(cfg.ProxyPort, headerRewriter, initialEngine, logger, cfg.MCPConfig)
	if err != nil {
		logger.Close()
		return nil, fmt.Errorf("failed to create MITM proxy: %w", err)
	}

	if strings.TrimSpace(leashDir) == "" {
		leashDir = getLeashDirFromEnv()
	}

	state := &runtimeState{
		cfg:               cfg,
		logger:            logger,
		wsHub:             wsHub,
		headerRewriter:    headerRewriter,
		mitmProxy:         mitmProxy,
		lsmManager:        lsmManager,
		decisions:         decisions,
		bootstrapPath:     filepath.Join(leashDir, entrypoint.BootstrapReadyFileName),
		telemetryProvider: telemetryProvider,
	}

	policyManager := policy.NewManager(lsmManager, func(active *cedarutil.Compilation) {
		state.headerRewriter.SetRules(active.HTTPRules)
		state.decisions.Publish(active.Engine, state.mitmProxy.SetEngine)
	})

	if cfg.viaEnforcerDaemon() {
		state.remote = newRemoteKernel(cfg.EnforcerSocket, cfg.CgroupPath, func(line string) {
			_ = logger.Write(line)
			noteRemoteAuditLine(line)
		})
		if cfg.EnforcerBroker != "" {
			state.remote.socket = cfg.EnforcerBroker
			state.remote.dial = enforcerd.DialBroker
		}
		policyManager.SetRemoteKernel(state.remote.update)
	}

	if err := policyManager.UpdateFileRules(initialPolicy.LSMPolicies, initialPolicy.HTTPRewrites); err != nil {
		state.Close()
		return nil, fmt.Errorf("failed to load file policies: %w", err)
	}
	headerRewriter.SetRules(initialPolicy.HTTPRewrites)
	state.policyManager = policyManager
	// A failed initial load is returned above (leashd exits FATAL and every
	// launcher fails closed). From here on, a change that cannot be applied
	// or rolled back stops the workload (#193).
	policyManager.SetFailClosedHandler(state.policyFailedClosed)

	if err := state.startAuthz(); err != nil {
		state.Close()
		return nil, err
	}

	logPolicyEvent("policy.restore", map[string]any{
		"source":        "file",
		"lsm_open":      len(initialPolicy.LSMPolicies.Open),
		"lsm_exec":      len(initialPolicy.LSMPolicies.Exec),
		"lsm_connect":   len(initialPolicy.LSMPolicies.Connect),
		"http_rewrites": len(initialPolicy.HTTPRewrites),
	})

	state.policyReady.Store(false)

	return state, nil
}

func (rt *runtimeState) Run() error {
	if err := rt.startFrontend(); err != nil {
		return err
	}

	// The daemon attaches before the bootstrap, as leashd's own initial
	// policy load does in a rootful run: the bootstrap (leash-entry, the CA
	// install) is governed by the policy too.
	if rt.remote != nil {
		rt.remotePrograms, rt.remoteErr = rt.remote.attach(rt.policyManager.Active)
		defer rt.remote.detach() // every exit path, including an aborted bootstrap
		if rt.remoteErr != nil {
			st := enforcement.Describe(false, !rt.cfg.LSMOnly)
			st.Reason = rt.remoteErr.Error()
			cerr := st.Check()
			fmt.Fprintf(os.Stderr, "leash: FATAL: %v\n", cerr)
			logPolicyEvent("enforcement.level", statusFields(st))
			return cerr
		}
	}

	if err := rt.waitForBootstrap(); err != nil {
		if errors.Is(err, errShutdownBeforeBootstrap) {
			logPolicyEvent("bootstrap.abort", map[string]any{"reason": "shutdown requested"})
			return nil
		}
		return err
	}

	return rt.activate()
}

// errShutdownBeforeBootstrap reports that SIGINT/SIGTERM arrived while leashd
// was still waiting for the bootstrap marker.
var errShutdownBeforeBootstrap = errors.New("shutdown requested before bootstrap")

func (rt *runtimeState) activate() error {
	if skipEnforcement() {
		logPolicyEvent("bootstrap.activate", map[string]any{"status": "skipped"})
		rt.policyReady.Store(true)
		writeEnforcementReadyMarker(getLeashDirFromEnv(), enforcement.Status{
			Enforcement: enforcement.LevelNone,
			Layer1:      enforcement.LayerDisabled,
			Layer2:      enforcement.LayerDisabled,
			RequireLSM:  true,
		})
		waitForShutdown()
		return nil
	}

	if err := rt.startPolicyWatcher(); err != nil {
		return err
	}

	// LSM-only mode (native, until netns egress lands): enforce with the eBPF
	// LSM alone; skip the netfilter REDIRECT + L7 MITM proxy, which need the
	// workload's own netns. file/exec/network-connect are still enforced.
	if !rt.cfg.LSMOnly {
		if err := rt.configureNetwork(); err != nil {
			return err
		}

		go func() {
			if err := rt.mitmProxy.Run(); err != nil {
				log.Fatal(err)
			}
		}()
	}

	if rt.remote != nil {
		return rt.activateRemote()
	}

	// Release a host launcher only once ALL LSM programs have attached (or
	// failed) — before LoadAndStart blocks. The initial policy load already
	// spawned the attach goroutines.
	rt.lsmManager.StartSettleWatch()

	if err := rt.lsmManager.LoadAndStart(); err != nil {
		return err
	}

	logPolicyEvent("bootstrap.activate", map[string]any{"status": "ok"})
	rt.policyReady.Store(true)
	// Note: LoadAndStart blocks until shutdown, so the actual enforcement-ready
	// signal is fired from the LSM settle hook installed in Main (host mode).
	return nil
}

// activateRemote attaches the eBPF LSM through the enforcer daemon, publishes
// the enforcement level, and holds the session until shutdown. Losing the
// session (the daemon or its worker went away) is fatal: the workload would
// no longer be kernel-enforced.
func (rt *runtimeState) activateRemote() error {
	programs, err := rt.remotePrograms, rt.remoteErr
	if err != nil {
		st := enforcement.Describe(false, !rt.cfg.LSMOnly)
		st.Reason = err.Error()
		cerr := st.Check()
		fmt.Fprintf(os.Stderr, "leash: FATAL: %v\n", cerr)
		logPolicyEvent("enforcement.level", statusFields(st))
		return cerr
	}
	st := enforcement.Describe(true, !rt.cfg.LSMOnly)
	st.Layer1Via = enforcement.Layer1ViaEnforcerDaemon
	log.Printf("leash: eBPF LSM attached by the enforcer daemon (%d programs) on %s", programs, rt.cfg.CgroupPath)
	writeEnforcementReadyMarker(getLeashDirFromEnv(), st)
	logPolicyEvent("bootstrap.activate", map[string]any{"status": "ok", "layer1Via": st.Layer1Via})
	rt.policyReady.Store(true)

	lsm.InstallShutdownHandler()
	select {
	case <-lsm.ShutdownRequested():
		rt.remote.detach()
		return nil
	case <-rt.remote.ended():
		select {
		case <-lsm.ShutdownRequested():
			return nil // teardown raced the session end
		default:
		}
		lost := fmt.Errorf("kernel enforcement lost: %v; refusing to keep the workload running unenforced", rt.remote.err())
		fmt.Fprintf(os.Stderr, "leash: FATAL: %v\n", lost)
		return lost
	}
}

func (rt *runtimeState) waitForBootstrap() error {
	path := rt.bootstrapPath
	if strings.TrimSpace(path) == "" {
		path = filepath.Join(getLeashDirFromEnv(), entrypoint.BootstrapReadyFileName)
		rt.bootstrapPath = path
	}

	deadline := time.Now().Add(rt.cfg.BootstrapTimeout)
	logPolicyEvent("bootstrap.wait", map[string]any{
		"path":    path,
		"timeout": rt.cfg.BootstrapTimeout.String(),
	})

	for {
		info, err := os.Stat(path)
		if err == nil {
			meta, metaErr := readBootstrapMetadata(path)
			if metaErr != nil {
				logPolicyEvent("bootstrap.ready", map[string]any{"path": path, "error": metaErr.Error()})
			} else {
				meta["mtime"] = info.ModTime().UTC().Format(time.RFC3339Nano)
				logPolicyEvent("bootstrap.ready", meta)
			}
			return nil
		}
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("check bootstrap marker: %w", err)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("bootstrap marker %s not observed within %s", path, rt.cfg.BootstrapTimeout)
		}
		select {
		case <-lsm.ShutdownRequested():
			// The launcher is tearing down before bootstrap: exit now instead of
			// waiting out the bootstrap timeout (#143).
			return errShutdownBeforeBootstrap
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func readBootstrapMetadata(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	data = bytes.TrimSpace(data)
	meta := map[string]any{"path": path}
	if len(data) == 0 {
		return meta, nil
	}
	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		return meta, err
	}
	for k, v := range payload {
		meta[k] = v
	}
	return meta, nil
}

func waitForShutdown() {
	lsm.InstallShutdownHandler()
	<-lsm.ShutdownRequested()
}

// startAuthz serves the plugin authz sockets the runner described in
// LEASH_AUTHZ_PLUGINS, answering from the same Decider the proxy uses. A
// malformed description fails startup; a socket that cannot be bound is
// logged and its plugin fails closed.
// authzProcCgroup reads a peer's /proc/<pid>/cgroup for the authz workload
// check; nil reads the real file (tests override it).
var authzProcCgroup func(pid int) ([]byte, error)

func (rt *runtimeState) startAuthz() error {
	grants, err := authz.ParseGrants(os.Getenv(authz.EnvPlugins))
	if err != nil {
		return err
	}
	if len(grants) == 0 {
		return nil
	}
	// The workload runs as the plugin's uid; without its cgroup leashd could
	// not tell a workload peer from the plugin. Fail closed (#142).
	if strings.TrimSpace(rt.cfg.CgroupPath) == "" {
		return errors.New("authz: plugins with authz= need the workload cgroup (--cgroup / LEASH_CGROUP_PATH) so leashd can refuse workload peers; refusing to serve the authz sockets without one")
	}
	rt.authzServer = authz.New(authz.Config{
		Grants:     grants,
		Source:     rt.decisions.Current,
		Logger:     rt.logger,
		BoxCgroup:  rt.cfg.CgroupPath,
		ProcCgroup: authzProcCgroup,
	})
	if err := rt.authzServer.Start(); err != nil {
		log.Printf("authz: %v", err)
	}
	ids := make([]string, 0, len(grants))
	for _, g := range grants {
		ids = append(ids, g.ID)
	}
	logPolicyEvent("authz.start", map[string]any{"plugins": strings.Join(ids, ",")})
	return nil
}

func (rt *runtimeState) Close() {
	rt.closeOnce.Do(func() {
		if rt.telemetryProvider != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = rt.telemetryProvider.Shutdown(ctx)
		}
		if rt.policyWatcherStop != nil {
			rt.policyWatcherStop()
		}
		if rt.authzServer != nil {
			_ = rt.authzServer.Close()
		}
		if rt.logger != nil {
			_ = rt.logger.Close()
		}
	})
}

func (rt *runtimeState) startFrontend() error {
	uiFS, err := fs.Sub(ui.Dir, "dist")
	if err != nil {
		return fmt.Errorf("failed to load embedded UI: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api", rt.wsHub.HandleWebSocket)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/health/policy", func(w http.ResponseWriter, r *http.Request) {
		if !rt.policyReady.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("not ready"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})
	title := ui.ComposeTitle(os.Getenv("LEASH_PROJECT"), os.Getenv("LEASH_COMMAND"))
	mux.Handle("/", ui.NewSPAHandlerWithTitle(http.FS(uiFS), title))

	api := newPolicyAPI(rt.policyManager, rt.cfg.PolicyPath, rt.wsHub, rt.mitmProxy, rt.wsHub)
	api.register(mux)

	// Suggestion API for raw suggestions preview
	suggest := newSuggestAPI(rt.policyManager, rt.wsHub)
	suggest.register(mux)

	if rt.cfg.WebDisabled {
		logPolicyEvent("frontend.disabled", map[string]any{"addr": ""})
		log.Printf("control UI disabled: no listen address configured (LEASH_LISTEN empty)")
		return nil
	}

	server := httpserver.NewWebServer(rt.cfg.WebBind, mux)

	go func(addr string, srv *http.Server) {
		logPolicyEvent("frontend.start", map[string]any{"addr": addr})
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("web server failed: %v", err)
		}
	}(rt.cfg.WebBind, server)

	return nil
}

// applyFileReload applies a reloaded policy file, keeping the previous policy
// when it cannot be applied. The manager refuses a set that does not compile
// or that the kernel would reject before changing anything, and rolls every
// component (kernel modules, enforcer daemon, proxy) back to the previous
// policy when applying fails partway (#193); if that rollback fails it fails
// closed and stops the workload. So a bad reload never leaves the workload on
// a partial, empty or more permissive policy, and there is nothing to restore
// here.
func applyFileReload(mgr *policy.Manager, newCfg *policy.Config) error {
	if mgr == nil || newCfg == nil {
		return fmt.Errorf("policy reload: no policy manager or config")
	}
	return mgr.UpdateFileRules(newCfg.LSMPolicies, newCfg.HTTPRewrites)
}

func (rt *runtimeState) startPolicyWatcher() error {
	cancel, err := policy.WatchCedar(rt.cfg.PolicyPath, time.Second, func(newCfg *policy.Config) {
		if err := applyFileReload(rt.policyManager, newCfg); err != nil {
			if errors.Is(err, policy.ErrFailedClosed) {
				logPolicyEvent("policy.update", map[string]any{"source": "file", "error": err.Error(), "kept": "deny-all"})
				log.Printf("leash: policy reload failed and enforcement failed closed: %v", err)
				return
			}
			logPolicyEvent("policy.update", map[string]any{"source": "file", "error": err.Error(), "kept": "previous"})
			log.Printf("leash: policy reload rejected, keeping the previous policy: %v", err)
			return
		}
		logPolicyEvent("policy.update", map[string]any{
			"source":        "file",
			"lsm_open":      len(newCfg.LSMPolicies.Open),
			"lsm_exec":      len(newCfg.LSMPolicies.Exec),
			"lsm_connect":   len(newCfg.LSMPolicies.Connect),
			"http_rewrites": len(newCfg.HTTPRewrites),
		})
		rt.policyReady.Store(true)
	}, func(detail *cedarutil.ErrorDetail) {
		if detail == nil {
			return
		}
		rt.policyReady.Store(false)
		logPolicyEvent("policy.update", map[string]any{
			"source":     "file",
			"error":      detail.Message,
			"line":       detail.Line,
			"column":     detail.Column,
			"code":       detail.Code,
			"suggestion": detail.Suggestion,
		})
		log.Printf("%s", formatCedarErrorForCLI(detail))
		// WatchCedar never applies an update that fails to compile.
		log.Printf("leash: policy reload rejected, keeping the previous policy")
	})
	if err != nil {
		return fmt.Errorf("failed to watch Cedar policy file: %w", err)
	}
	rt.policyWatcherStop = cancel
	return nil
}

func (rt *runtimeState) configureNetwork() error {
	if runtime.GOOS != "linux" {
		log.Printf("iptables configuration skipped on %s", runtime.GOOS)
		return nil
	}

	// Extract leashd control plane port from WebBind (e.g., ":18080" or "127.0.0.1:18080")
	var leashPort string
	if rt.cfg.WebBind != "" {
		_, port, err := net.SplitHostPort(rt.cfg.WebBind)
		if err == nil {
			leashPort = port
		}
	}

	fmt.Fprintf(os.Stderr, "leash: applying network interception rules\n")
	if err := applyNetworkRules(rt.cfg.ProxyPort, leashPort, rt.cfg.CgroupPath); err != nil {
		return err
	}

	// Best-effort mounts and environment probe
	fmt.Fprintf(os.Stderr, "leash: mounting securityfs\n")
	secfs := exec.Command("mount", "-t", "securityfs", "securityfs", "/sys/kernel/security")
	secfs.Stdout = os.Stdout
	secfs.Stderr = os.Stderr
	if err := secfs.Run(); err != nil {
		log.Printf("Warning: Failed to mount securityfs: %v", err)
	}

	// Print LSM list if available so operators can confirm BPF LSM
	if data, err := os.ReadFile("/sys/kernel/security/lsm"); err == nil {
		lsmList := strings.TrimSpace(string(data))
		logPolicyEvent("env.lsm", map[string]any{"lsm": lsmList})
		if !strings.Contains(lsmList, "bpf") {
			log.Printf("Warning: BPF LSM not present in LSM list; exec/file/connect LSM may fail to attach")
		}
	} else {
		log.Printf("Warning: Unable to read /sys/kernel/security/lsm: %v", err)
	}

	fmt.Fprintf(os.Stderr, "leash: mounting tracefs\n")
	tracefs := exec.Command("mount", "-t", "tracefs", "tracefs", "/sys/kernel/tracing")
	tracefs.Stdout = os.Stdout
	tracefs.Stderr = os.Stderr
	if err := tracefs.Run(); err != nil {
		log.Printf("Warning: Failed to mount tracefs: %v", err)
	}
	return nil
}

const proxyMark = "0x2000"

func clearReadyMarkers(dir string) error {
	if dir == "" {
		dir = "/leash"
	}
	for _, name := range []string{entrypoint.BootstrapReadyFileName, entrypoint.EnforcementReadyFileName} {
		marker := filepath.Join(dir, name)
		if err := os.Remove(marker); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func skipEnforcement() bool {
	if strings.TrimSpace(os.Getenv("LEASH_E2E")) != "1" {
		return false
	}
	return strings.TrimSpace(os.Getenv("LEASH_BOOTSTRAP_SKIP_ENFORCE")) != ""
}

// iptablesBinaryName declares the command name used to locate iptables binaries.
// Tests override this to simulate hosts where iptables is absent without mutating the real filesystem.
var iptablesBinaryName = "iptables"

// ip6tablesBinaryName allows optional IPv6 interception if available.
var ip6tablesBinaryName = "ip6tables"

// nftables binary name
var nftBinaryName = "nft"

// applyNetworkRules attempts nftables first (v4+v6) then falls back to iptables/ip6tables.
// leashPort and cgroupPath are used to block target container from reaching leashd control plane.
// cgroupPath is the absolute cgroup directory; it is converted to a
// cgroup2-root-relative path before being handed to the rule scripts.
func applyNetworkRules(port, leashPort, cgroupPath string) error {
	if port == "" {
		port = "18000"
	}
	// The kernel cgroup matchers (nft `socket cgroupv2`, xt_cgroup `--path`)
	// want a path relative to the cgroup2 root, not the absolute directory
	// leashd monitors. If it cannot be expressed that way, pass no cgroup so
	// the scripts apply the namespace-wide control-plane block instead.
	ruleCgroup, ruleLevel := "", 0
	if strings.TrimSpace(cgroupPath) != "" {
		rel, level, err := cgroup2RulePath(cgroup2Root, cgroupPath)
		if err != nil {
			log.Printf("Warning: cannot scope control-plane isolation to cgroup (%v); blocking all local access to the control plane port", err)
		} else {
			ruleCgroup, ruleLevel = rel, level
		}
	}
	// Try nftables first if available
	if _, err := findNft(); err == nil {
		if err := applyNftablesRules(port, leashPort, ruleCgroup, ruleLevel); err == nil {
			return nil
		} else {
			log.Printf("Warning: nftables apply failed; falling back to iptables: %v", err)
		}
	}
	// Fallback: iptables + ip6tables (best-effort)
	return applyIptablesRules(port, leashPort, ruleCgroup)
}

// cgroupPath must already be relative to the cgroup2 root (see cgroup2RulePath).
func applyIptablesRules(port, leashPort, cgroupPath string) error {
	if port == "" {
		port = "18000"
	}
	if _, err := findIptables(); err != nil {
		return err
	}

	shell := "/bin/sh"
	if _, err := exec.LookPath(shell); err != nil {
		return fmt.Errorf("shell not found: %w", err)
	}

	cmd := exec.Command(shell, "-s", port, leashPort, cgroupPath)
	cmd.Stdin = strings.NewReader(assets.ApplyIptablesScript)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), "PROXY_MARK="+proxyMark)
	if err := cmd.Run(); err != nil {
		return err
	}

	// Best-effort IPv6 support: run ip6tables rules if ip6tables exists
	if p, _ := findIp6tables(); p != "" {
		v6 := exec.Command(shell, "-s", port, leashPort, cgroupPath)
		v6.Stdin = strings.NewReader(assets.ApplyIp6tablesScript)
		v6.Stdout = os.Stdout
		v6.Stderr = os.Stderr
		v6.Env = append(os.Environ(), "PROXY_MARK="+proxyMark)
		if err := v6.Run(); err != nil {
			log.Printf("Warning: failed to apply ip6tables rules: %v", err)
		}
	} else {
		log.Printf("ip6tables not found; skipping IPv6 interception")
	}
	return nil
}

// findIptables locates the iptables binary by searching PATH first,
// then common sbin locations used in minimal containers.
func findIptables() (string, error) {
	// PATH first
	if p, err := exec.LookPath(iptablesBinaryName); err == nil {
		return p, nil
	}
	// Fallback dirs
	candidates := []string{
		filepath.Join("/usr/sbin", iptablesBinaryName),
		filepath.Join("/sbin", iptablesBinaryName),
	}
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0 {
			return c, nil
		}
	}
	return "", fmt.Errorf("iptables not found (checked PATH, /usr/sbin, /sbin)")
}

// applyNftablesRules runs the embedded nftables script to configure v4+v6.
// cgroupPath must be relative to the cgroup2 root and cgroupLevel its depth
// (see cgroup2RulePath); an empty cgroupPath selects the namespace-wide block.
func applyNftablesRules(port, leashPort, cgroupPath string, cgroupLevel int) error {
	if port == "" {
		port = "18000"
	}
	if _, err := findNft(); err != nil {
		return err
	}
	shell := "/bin/sh"
	if _, err := exec.LookPath(shell); err != nil {
		return fmt.Errorf("shell not found: %w", err)
	}
	cmd := exec.Command(shell, nftablesScriptArgs(port, leashPort, cgroupPath, cgroupLevel)...)
	cmd.Stdin = strings.NewReader(assets.ApplyNftablesScript)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), "PROXY_MARK="+proxyMark)
	return cmd.Run()
}

// findNft locates the nft binary by searching PATH first, then common sbin directories.
func findNft() (string, error) {
	if p, err := exec.LookPath(nftBinaryName); err == nil {
		return p, nil
	}
	candidates := []string{
		filepath.Join("/usr/sbin", nftBinaryName),
		filepath.Join("/sbin", nftBinaryName),
	}
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0 {
			return c, nil
		}
	}
	return "", fmt.Errorf("nft not found (checked PATH, /usr/sbin, /sbin)")
}

// findIp6tables locates the ip6tables binary. Returns empty string if not found.
func findIp6tables() (string, error) {
	// PATH first
	if p, err := exec.LookPath(ip6tablesBinaryName); err == nil {
		return p, nil
	}
	candidates := []string{
		filepath.Join("/usr/sbin", ip6tablesBinaryName),
		filepath.Join("/sbin", ip6tablesBinaryName),
	}
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0 {
			return c, nil
		}
	}
	return "", fmt.Errorf("ip6tables not found (checked PATH, /usr/sbin, /sbin)")
}

func formatCedarErrorForCLI(detail *cedarutil.ErrorDetail) string {
	return cedarutil.FormatForCLI(detail)
}

func splitExtraArgs(raw string) []string {
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return nil
	}
	return fields
}

func commandName(args []string) string {
	if len(args) == 0 {
		return "leash"
	}
	if strings.TrimSpace(args[0]) == "" {
		return "leash"
	}
	return args[0]
}

func parseBootstrapTimeout(raw string) (time.Duration, error) {
	if d, err := time.ParseDuration(raw); err == nil {
		return d, nil
	}
	seconds, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q", raw)
	}
	return time.Duration(seconds) * time.Second, nil
}
