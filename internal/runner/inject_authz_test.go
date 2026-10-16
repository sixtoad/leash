package runner

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/strongdm/leash/internal/authz"
	cedarutil "github.com/strongdm/leash/internal/cedar"
	"github.com/strongdm/leash/internal/policy"
	wire "github.com/strongdm/leash/pkg/authz"
)

func TestParseInjectServiceAuthz(t *testing.T) {
	svc, err := parseInjectService("plugin=/opt/walk/leash-plugin-secretbroker,env=DBUS,socket=/tmp/sb/bus,authz=Secret+Walk::Secret+Secret")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(svc.authz, []string{"Secret", "Walk::Secret"}) || svc.authzID() != "leash-plugin-secretbroker" {
		t.Fatalf("parsed %+v id=%q", svc, svc.authzID())
	}
	svc, err = parseInjectService("plugin=p,env=X,socket=/tmp/s.sock,authz=CodeIndex+Action,id=code-indexer")
	if err != nil || svc.authzID() != "code-indexer" {
		t.Fatalf("id= not honoured: %+v %v", svc, err)
	}
	for name, spec := range map[string]string{
		"bad namespace":    "plugin=p,env=X,socket=/tmp/s.sock,authz=Se-cret",
		"empty namespace":  "plugin=p,env=X,socket=/tmp/s.sock,authz=",
		"bad id":           "plugin=p,env=X,socket=/tmp/s.sock,authz=Secret,id=../x",
		"id without authz": "plugin=p,env=X,socket=/tmp/s.sock,id=x",
		"duplicate authz":  "plugin=p,env=X,socket=/tmp/s.sock,authz=A,authz=B",
	} {
		if _, err := parseInjectService(spec); err == nil {
			t.Errorf("%s: accepted %q", name, spec)
		}
	}
}

func TestInjectAuthzRejectsDuplicateIDs(t *testing.T) {
	r := &runner{opts: options{injectServices: []injectService{
		{plugin: "/a/broker", env: "A", socket: "/tmp/a.sock", authz: []string{"Secret"}},
		{plugin: "/b/broker", env: "B", socket: "/tmp/b.sock", authz: []string{"Secret"}},
	}}}
	if err := r.checkInjectDuplicates("native"); err == nil || !strings.Contains(err.Error(), "authz id") {
		t.Fatalf("expected duplicate authz id error, got %v", err)
	}
}

// End to end through the runner/leashd contract: the runner prepares the
// socket directory and hands the plugin its socket env; leashd (here the
// authz server built from the runner's LEASH_AUTHZ_PLUGINS) serves it; the
// plugin's client gets decisions from the live policy.
func TestInjectAuthzRunnerToLeashdContract(t *testing.T) {
	dir := t.TempDir()
	envDump := filepath.Join(dir, "plugin.env")
	plugin := filepath.Join(dir, "authz-plugin.sh")
	script := "#!/bin/sh\n" +
		"if [ -n \"$LEASH_AUTHZ_SOCKET\" ]; then env | grep '^LEASH_AUTHZ_' > \"" + envDump + "\"; fi\n" +
		": > \"$LEASH_INJECT_SOCKET\"\n" +
		"exec sleep 30\n"
	if err := os.WriteFile(plugin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	r := &runner{cfg: config{logDir: dir}, opts: options{injectServices: []injectService{
		{plugin: plugin, env: "HELPER", socket: filepath.Join(dir, "helper.sock"), authz: []string{"Secret"}, id: "secretbroker"},
		{plugin: plugin, env: "OTHER", socket: filepath.Join(dir, "other.sock")},
	}}}
	if err := r.spawnInjectServicesContainer(context.Background()); err != nil {
		t.Fatal(err)
	}
	authzDir := r.authzDir
	defer func() {
		r.teardownInjectedPlugins()
		if _, err := os.Stat(authzDir); !os.IsNotExist(err) {
			t.Errorf("authz dir not removed on teardown: %v", err)
		}
	}()

	// Only the authz-enabled plugin has a grant, in a 0700 dir under a 0711 one.
	if len(r.authzGrants) != 1 {
		t.Fatalf("grants = %+v", r.authzGrants)
	}
	grant := r.authzGrants[0]
	if fi, err := os.Stat(r.authzDir); err != nil || fi.Mode().Perm() != 0o711 {
		t.Fatalf("authz dir mode: %v %v", fi.Mode(), err)
	}
	if fi, err := os.Stat(filepath.Dir(grant.Socket)); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("plugin dir mode: %v %v", fi.Mode(), err)
	}

	// The leashd container gets the dir mount and the grants; the workload
	// container args do not mention the authz dir.
	dockerArgs, err := r.authzDockerArgs()
	if err != nil || len(dockerArgs) != 4 || dockerArgs[1] != r.authzDir+":"+r.authzDir {
		t.Fatalf("leashd docker args = %q, %v", dockerArgs, err)
	}
	if strings.Contains(strings.Join(r.injectedDockerArgs, " "), r.authzDir) {
		t.Fatalf("authz dir leaked into the workload container args: %q", r.injectedDockerArgs)
	}

	// The plugin saw its socket and id.
	var dumped []byte
	for i := 0; i < 100; i++ {
		if dumped, _ = os.ReadFile(envDump); len(dumped) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(string(dumped), wire.EnvSocket+"="+grant.Socket) || !strings.Contains(string(dumped), wire.EnvPluginID+"=secretbroker") {
		t.Fatalf("plugin env:\n%s", dumped)
	}

	// leashd side: parse what the runner passed and serve it.
	env, err := r.authzLeashdEnv()
	if err != nil || len(env) != 1 {
		t.Fatalf("leashd env = %q, %v", env, err)
	}
	grants, err := authz.ParseGrants(strings.TrimPrefix(env[0], authz.EnvPlugins+"="))
	if err != nil {
		t.Fatal(err)
	}
	decisions := &policy.Decisions{}
	comp, err := cedarutil.CompileString("test.cedar",
		`permit (principal == Plugin::"secretbroker", action == Secret::Action::"Read", resource == Secret::Item::"gemini");`)
	if err != nil {
		t.Fatal(err)
	}
	decisions.Publish(comp.Engine)
	srv := authz.New(authz.Config{Grants: grants, Source: decisions.Current})
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	c := wire.New(grant.Socket)
	defer c.Close()
	if d := c.Check(context.Background(), wire.Request{Action: wire.UID("Secret::Action", "Read"), Resource: wire.UID("Secret::Item", "gemini")}); !d.Allowed() {
		t.Fatalf("granted secret denied: %+v", d)
	}
	if d := c.Check(context.Background(), wire.Request{Action: wire.UID("Secret::Action", "Read"), Resource: wire.UID("Secret::Item", "ssh")}); d.Allowed() {
		t.Fatalf("ungranted secret allowed: %+v", d)
	}
}
