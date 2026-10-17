//go:build darwin

package darwind

import (
	"encoding/json"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/strongdm/leash/internal/lsm"
	"github.com/strongdm/leash/internal/macsync"
	"github.com/strongdm/leash/internal/messages"
)

// macKernel is the macOS "kernel" of policy.Manager: what LSMManager is on
// Linux. Every policy the manager makes active is compiled to the macOS
// tables (the kernel tables, by the same compiler) and pushed to the
// extensions; a policy that cannot be compiled for macOS is rejected by the
// manager like a kernel refusal, and the previous policy stays active, in
// the extensions, the proxy and the engine alike.
type macKernel struct {
	rt         *runtimeState
	protection macsync.Protection
}

func (k *macKernel) UpdateRuntimeRules(ps *lsm.PolicySet) error {
	tables, err := macsync.CompileTables(ps, k.protection)
	if err != nil {
		return err
	}
	k.install(tables)
	return nil
}

// EnforcesKernelPolicy is true: the extensions enforce the kernel tables, so
// the kernel limits (rule counts, path lengths) apply on macOS too.
func (k *macKernel) EnforcesKernelPolicy() bool { return true }

// FailClosed installs tables that deny every open, mutation, exec and
// connection (leash's protected paths and ports included).
func (k *macKernel) FailClosed() error {
	tables, err := macsync.CompileTables(&lsm.PolicySet{ConnectDefaultExplicit: true}, k.protection)
	if err != nil {
		return err
	}
	k.install(tables)
	return nil
}

func (k *macKernel) install(tables *macsync.MacPolicyTables) {
	if k.rt.macSync == nil {
		return
	}
	k.rt.macSync.SetTables(tables)
	logPolicyEvent("mac.policy.tables", map[string]any{
		"version":         tables.Version,
		"file_exact":      len(tables.File.Exact),
		"file_prefix":     len(tables.File.Prefix),
		"file_default":    tables.File.DefaultAllow,
		"exec_rules":      len(tables.Exec.Rules),
		"exec_default":    tables.Exec.DefaultAllow,
		"network_rules":   len(tables.Network.Rules),
		"network_default": tables.Network.DefaultAllow,
		"protected_paths": len(tables.Protected.Paths),
	})
	k.rt.broadcastTables(tables)
}

// darwinProtection names leash's own state, which a leashed workload may
// never touch whatever the policy says: the state directory (policy file,
// daemon log, server state), the private directory (the MITM CA key), the
// policy file itself, and the daemon's two listening ports.
func darwinProtection(cfg *runtimeConfig) macsync.Protection {
	var p macsync.Protection
	add := func(path string) {
		path = strings.TrimSpace(path)
		if path == "" {
			return
		}
		if abs, err := filepath.Abs(path); err == nil {
			path = abs
		}
		// Endpoint Security reports real paths: resolve symlinks
		// (/var/folders -> /private/var/folders) where the path exists.
		if real, err := filepath.EvalSymlinks(path); err == nil {
			path = real
		}
		p.Paths = append(p.Paths, path)
	}
	if dir, err := execStateDir(); err == nil {
		add(dir)
	}
	add(os.Getenv("LEASH_PRIVATE_DIR"))
	if cfg != nil {
		add(cfg.PolicyPath)
		for _, addr := range []string{cfg.WebBind, ":" + cfg.ProxyPort} {
			if _, port, err := net.SplitHostPort(addr); err == nil {
				if n, err := strconv.Atoi(port); err == nil && n > 0 && n < 65536 {
					p.Ports = append(p.Ports, uint16(n))
				}
			}
		}
	}
	return p
}

// broadcastTables pushes the tables to every connected client.
func (rt *runtimeState) broadcastTables(tables *macsync.MacPolicyTables) {
	if rt.wsHub == nil || tables == nil {
		return
	}
	data, err := tablesEnvelope(tables)
	if err != nil {
		log.Printf("macsync: failed to encode policy tables: %v", err)
		return
	}
	clients := rt.snapshotMacClients()
	for _, client := range clients {
		if err := rt.wsHub.SendToClient(client.ID, data); err != nil {
			log.Printf("macsync: failed to send policy tables to %s: %v", client.ID, err)
		}
	}
	log.Printf("macsync: broadcasted policy tables %s to %d clients", tables.Version, len(clients))
}

func tablesEnvelope(tables *macsync.MacPolicyTables) ([]byte, error) {
	env, err := messages.WrapPayload("", "", messages.TypeMacPolicyTables, 1, tables)
	if err != nil {
		return nil, err
	}
	return json.Marshal(env)
}

// tablesPayload is the tables as the generic map sendResponse carries.
func tablesPayload(tables *macsync.MacPolicyTables) (map[string]any, error) {
	data, err := json.Marshal(tables)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	err = json.Unmarshal(data, &out)
	return out, err
}
