package leashd

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/strongdm/leash/internal/authz"
	cedarutil "github.com/strongdm/leash/internal/cedar"
	"github.com/strongdm/leash/internal/engine"
	"github.com/strongdm/leash/internal/policy"
	wire "github.com/strongdm/leash/pkg/authz"
)

// leashd serves the sockets LEASH_AUTHZ_PLUGINS describes from the same
// Decisions the proxy is fed, so a policy change reaches both at once.
func TestStartAuthzServesFromThePolicyManager(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "lzd")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "authz.sock")
	payload, _ := json.Marshal([]authz.PluginGrant{{ID: "gate", Socket: sock, UID: os.Getuid(), Namespaces: []string{"Action"}}})
	t.Setenv(authz.EnvPlugins, string(payload))

	// authz= needs the workload cgroup: without one leashd refuses to serve.
	if err := (&runtimeState{cfg: &runtimeConfig{}, decisions: &policy.Decisions{}}).startAuthz(); err == nil || !strings.Contains(err.Error(), "cgroup") {
		t.Fatalf("authz without a cgroup must fail closed, got %v", err)
	}
	authzProcCgroup = func(int) ([]byte, error) { return []byte("0::/user.slice/plugin\n"), nil }
	t.Cleanup(func() { authzProcCgroup = nil })
	rt := &runtimeState{cfg: &runtimeConfig{CgroupPath: "/sys/fs/cgroup/leash/box"}, decisions: &policy.Decisions{}}
	var proxyEngine *engine.Engine
	manager := policy.NewManager(nil, func(active *cedarutil.Compilation) {
		rt.decisions.Publish(active.Engine, func(e *engine.Engine) { proxyEngine = e })
	})
	if err := rt.startAuthz(); err != nil {
		t.Fatal(err)
	}
	defer rt.authzServer.Close()

	comp, err := cedarutil.CompileString("runtime.cedar", `permit (principal, action == Action::"NetworkConnect", resource) when { resource in [Host::"api.example.com"] };`)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.SetRuntimeRules(comp.Policies, comp.HTTPRules); err != nil {
		t.Fatal(err)
	}
	c := wire.New(sock)
	defer c.Close()
	for _, host := range []string{"api.example.com", "other.example.com"} {
		d := c.Check(context.Background(), wire.Request{Action: wire.UID("Action", "NetworkConnect"), Resource: wire.UID("Host", host)})
		if d.Err != nil {
			t.Fatal(d.Err)
		}
		if want := proxyEngine.CheckConnect(host, "", 0); d.Allowed() != want {
			t.Errorf("%s: socket=%v proxy=%v", host, d.Allowed(), want)
		}
	}

	t.Setenv(authz.EnvPlugins, `[{"id":"../bad"}]`)
	if err := (&runtimeState{cfg: &runtimeConfig{CgroupPath: "/sys/fs/cgroup/leash/box"}, decisions: &policy.Decisions{}}).startAuthz(); err == nil {
		t.Fatal("malformed LEASH_AUTHZ_PLUGINS must fail startup")
	}
}
