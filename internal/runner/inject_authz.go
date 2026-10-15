package runner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/strongdm/leash/internal/authz"
	wire "github.com/strongdm/leash/pkg/authz"
)

// Plugin authorization socket wiring (#142).
//
// An --inject-service spec with authz=<Ns>[+<Ns>...] asks leashd for a private
// authz socket for that plugin. The runner creates a per-run directory
// (root-owned, 0711) with one 0700 subdirectory per plugin, owned by the uid
// the plugin runs as; leashd binds <dir>/<id>/authz.sock there and serves it
// from the live policy. The plugin finds it via LEASH_AUTHZ_SOCKET. The
// directory is mounted into the leashd container only, never into the
// workload.

const authzSocketName = "authz.sock"

var unsafePluginIDChars = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// authzID is the plugin's authz identity: id= when given, else the plugin
// binary's base name made safe.
func (svc injectService) authzID() string {
	if svc.id != "" {
		return svc.id
	}
	base := unsafePluginIDChars.ReplaceAllString(filepath.Base(svc.plugin), "-")
	base = strings.Trim(base, "-.")
	if len(base) > 64 {
		base = base[:64]
	}
	return base
}

// parseAuthzNamespaces parses the authz= value: '+'-separated Cedar namespaces.
func parseAuthzNamespaces(v string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, ns := range strings.Split(v, "+") {
		ns = strings.TrimSpace(ns)
		if err := authz.ValidateNamespace(ns); err != nil {
			return nil, fmt.Errorf("--inject-service authz: %w", err)
		}
		if !seen[ns] {
			seen[ns] = true
			out = append(out, ns)
		}
	}
	return out, nil
}

// prepareAuthz creates the authz socket directories once per run. It is
// idempotent; the native launcher calls it before starting leashd and the
// container launcher before spawning plugins.
func (r *runner) prepareAuthz() error {
	if r.authzPrepared {
		return r.authzErr
	}
	r.authzPrepared = true
	r.authzErr = r.doPrepareAuthz()
	return r.authzErr
}

func (r *runner) doPrepareAuthz() error {
	var svcs []injectService
	for _, svc := range r.opts.injectServices {
		if len(svc.authz) > 0 {
			svcs = append(svcs, svc)
		}
	}
	if len(svcs) == 0 {
		return nil
	}
	// /tmp, not $TMPDIR: unix socket paths are limited to ~104 bytes.
	dir, err := os.MkdirTemp("/tmp", "leash-authz-")
	if err != nil {
		return fmt.Errorf("authz: create socket dir: %w", err)
	}
	r.authzDir = dir
	if err := os.Chmod(dir, 0o711); err != nil {
		return fmt.Errorf("authz: chmod %s: %w", dir, err)
	}
	uid, gid := os.Getuid(), os.Getgid()
	if r.workloadUser() != "" {
		if u, g := r.workloadUIDGID(); u >= 0 {
			uid, gid = u, g
		}
	}
	for _, svc := range svcs {
		id := svc.authzID()
		sub := filepath.Join(dir, id)
		if err := os.Mkdir(sub, 0o700); err != nil {
			return fmt.Errorf("authz: create %s: %w", sub, err)
		}
		if uid != os.Getuid() {
			if err := os.Chown(sub, uid, gid); err != nil {
				return fmt.Errorf("authz: chown %s: %w", sub, err)
			}
		}
		r.authzGrants = append(r.authzGrants, authz.PluginGrant{
			ID:         id,
			Socket:     filepath.Join(sub, authzSocketName),
			UID:        uid,
			Namespaces: svc.authz,
		})
	}
	return nil
}

func (r *runner) authzGrant(svc injectService) (authz.PluginGrant, bool) {
	if len(svc.authz) == 0 {
		return authz.PluginGrant{}, false
	}
	id := svc.authzID()
	for _, g := range r.authzGrants {
		if g.ID == id {
			return g, true
		}
	}
	return authz.PluginGrant{}, false
}

// authzPluginEnv is the environment that points one plugin at its socket.
func (r *runner) authzPluginEnv(svc injectService) []string {
	g, ok := r.authzGrant(svc)
	if !ok {
		return nil
	}
	return []string{wire.EnvSocket + "=" + g.Socket, wire.EnvPluginID + "=" + g.ID}
}

// authzLeashdEnv is the environment that tells leashd which sockets to serve.
func (r *runner) authzLeashdEnv() ([]string, error) {
	if len(r.authzGrants) == 0 {
		return nil, nil
	}
	payload, err := json.Marshal(r.authzGrants)
	if err != nil {
		return nil, err
	}
	return []string{authz.EnvPlugins + "=" + string(payload)}, nil
}

// authzDockerArgs mounts the socket directory into the leashd container at the
// same path and passes the grants.
func (r *runner) authzDockerArgs() ([]string, error) {
	env, err := r.authzLeashdEnv()
	if err != nil || len(env) == 0 {
		return nil, err
	}
	return []string{"-v", r.authzDir + ":" + r.authzDir, "-e", env[0]}, nil
}

// teardownAuthz removes the socket directory.
func (r *runner) teardownAuthz() {
	if r.authzDir != "" {
		_ = os.RemoveAll(r.authzDir)
	}
}
