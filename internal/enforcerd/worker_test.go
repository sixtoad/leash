//go:build unix

package enforcerd

import (
	"reflect"
	"strconv"
	"strings"
	"testing"

	cedarutil "github.com/strongdm/leash/internal/cedar"
	"github.com/strongdm/leash/internal/lsm"
	"github.com/strongdm/leash/internal/policy"
)

// The daemon must enforce exactly the kernel tables leashd would load in a
// rootful run. leashd sends the active policy's strict text
// (Compilation.StrictText); the daemon compiles it with the same pipeline.
// For every policy shape — strict, legacy (rewritten), the default, a
// mixture of layers — the tables must be identical.
func TestSessionPolicyCompilesToLeashdKernelTables(t *testing.T) {
	policies := map[string]string{
		"default": policy.DefaultCedar(),
		"legacy": `permit (principal, action == Action::"ProcessExec", resource) when { resource in [ Dir::"/" ] };
forbid (principal, action == Action::"ProcessExec", resource == File::"/bin/rm");
permit (principal, action == Action::"ProcessExec", resource == File::"/bin/rm/x");
permit (principal, action in [Action::"FileOpen", Action::"FileOpenReadOnly"], resource) when { resource in [ Dir::"/" ] };
forbid (principal, action == Action::"FileOpen", resource) when { resource in [ Dir::"/etc/ssh/" ] };
permit (principal, action == Action::"NetworkConnect", resource) when { resource in [ Host::"example.com", Host::"10.0.0.1:443" ] };
forbid (principal, action == Action::"NetworkConnect", resource == Host::"10.0.0.2");`,
		"strict": `@leash_semantics("cedar")
permit (principal, action == Action::"FileOpenReadOnly", resource) when { resource in Dir::"/" };
@leash_semantics("cedar")
permit (principal, action == Action::"FileOpenReadWrite", resource) when { resource in [Dir::"/tmp/", Dir::"/work/"] };
@leash_semantics("cedar")
forbid (principal, action in Action::"FileOpen", resource == File::"/etc/leash-denied");
@leash_semantics("cedar")
permit (principal, action == Action::"ProcessExec", resource) when { resource in Dir::"/" } unless { resource in FilePrefix::"/usr/bin/nc" };
@leash_semantics("cedar")
permit (principal, action == Action::"NetworkConnect", resource) when { resource in [Host::"example.com", Host::"*:53", Host::"[fd00:6::1]:8443"] };
@leash_semantics("cedar")
forbid (principal, action == Action::"NetworkConnect", resource in Host::"fd00:6::2");
@leash_semantics("cedar")
permit (principal, action == Action::"McpCall", resource);`,
		"empty-strict": `@leash_semantics("cedar")
permit (principal, action == Action::"McpCall", resource);`,
	}
	for name, text := range policies {
		t.Run(name, func(t *testing.T) {
			comp, err := cedarutil.CompileString(name+".cedar", text)
			if err != nil {
				t.Fatal(err)
			}
			got, err := compileSessionPolicy(comp.StrictText)
			if err != nil {
				t.Fatalf("the daemon refused leashd's policy: %v", err)
			}
			assertSameTables(t, comp.Policies, got)
		})
	}

	// Layers: a legacy file plus a strict runtime layer, merged by the
	// policy manager; the daemon receives the merge's strict text.
	file, err := cedarutil.CompileString("file.cedar", policies["legacy"])
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := cedarutil.CompileString("runtime.cedar", `@leash_semantics("cedar")
forbid (principal, action == Action::"FileOpenReadOnly", resource == File::"/etc/hostname");`)
	if err != nil {
		t.Fatal(err)
	}
	merged, err := cedarutil.CompileLayers([]cedarutil.Layer{cedarutil.LayerOf(file.Policies, nil), cedarutil.LayerOf(runtime.Policies, nil)})
	if err != nil {
		t.Fatal(err)
	}
	got, err := compileSessionPolicy(merged.StrictText)
	if err != nil {
		t.Fatal(err)
	}
	assertSameTables(t, merged.Policies, got)
}

func assertSameTables(t *testing.T, want, got *lsm.PolicySet) {
	t.Helper()
	w, g := want.Clone(), got.Clone()
	w.Source, g.Source = nil, nil
	if !reflect.DeepEqual(w.Open, g.Open) || !reflect.DeepEqual(w.Exec, g.Exec) || !reflect.DeepEqual(w.Connect, g.Connect) ||
		w.ConnectDefaultAllow != g.ConnectDefaultAllow || w.ConnectDefaultExplicit != g.ConnectDefaultExplicit {
		t.Fatalf("kernel tables differ:\nleashd: open=%d exec=%d connect=%d default=%v/%v\ndaemon: open=%d exec=%d connect=%d default=%v/%v",
			len(w.Open), len(w.Exec), len(w.Connect), w.ConnectDefaultAllow, w.ConnectDefaultExplicit,
			len(g.Open), len(g.Exec), len(g.Connect), g.ConnectDefaultAllow, g.ConnectDefaultExplicit)
	}
}

func TestSessionPolicyRejectsWhatLeashdRejects(t *testing.T) {
	for name, text := range map[string]string{
		"syntax":          `permit (principal, action, resource`,
		"principal":       `@leash_semantics("cedar") permit (principal == User::"x", action == Action::"ProcessExec", resource);`,
		"not enforceable": `@leash_semantics("cedar") permit (principal, action == Action::"ProcessExec", resource) when { context.x == 1 };`,
	} {
		if _, err := compileSessionPolicy(text); err == nil {
			t.Errorf("%s: compiled, want a refusal", name)
		}
	}
	var b strings.Builder
	for i := 0; i < 70; i++ {
		b.WriteString(`@leash_semantics("cedar") forbid (principal, action == Action::"ProcessExec", resource == File::"/usr/local/bin/nope`)
		b.WriteString(strconv.Itoa(i))
		b.WriteString("\");\n")
	}
	b.WriteString(`@leash_semantics("cedar") permit (principal, action == Action::"ProcessExec", resource) when { resource in Dir::"/" };`)
	if _, err := compileSessionPolicy(b.String()); err == nil || !strings.Contains(err.Error(), "limits") {
		t.Fatalf("over the kernel's exec rule limit: %v", err)
	}
}

func TestHostTable(t *testing.T) {
	h := &hostTable{}
	h.set(map[string][]string{"example.com": {"93.184.215.14", "not-an-ip"}})
	ips, err := h.lookup("example.com")
	if err != nil || len(ips) != 1 || ips[0].String() != "93.184.215.14" {
		t.Fatalf("lookup = %v, %v", ips, err)
	}
	if _, err := h.lookup("other.example"); err == nil {
		t.Fatal("a host the client did not resolve must fail (the loader skips it, as an unresolvable name)")
	}
}

func TestServiceUnitIsLeastPrivilege(t *testing.T) {
	unit := ServiceUnitText(InstallBin)
	for _, want := range []string{
		"User=" + ServiceUser,
		"AmbientCapabilities=CAP_BPF CAP_PERFMON\n",
		"CapabilityBoundingSet=CAP_BPF CAP_PERFMON\n",
		"NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=yes", "PrivateNetwork=yes",
		"PrivateDevices=yes", "RestrictAddressFamilies=AF_UNIX\n", "RestrictNamespaces=yes",
		"SystemCallFilter=@system-service bpf\n", "MemoryDenyWriteExecute=yes",
		"ExecStart=" + InstallBin + " daemon run",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("service unit lacks %q", want)
		}
	}
	for _, bad := range []string{"CAP_SYS_ADMIN", "CAP_NET_ADMIN", "CAP_DAC", "User=root", "@privileged"} {
		if strings.Contains(unit, bad) {
			t.Errorf("service unit must not contain %q (bpf is in @privileged: denying it would break the daemon)", bad)
		}
	}
	sock := SocketUnitText()
	for _, want := range []string{"ListenStream=" + DefaultSocketPath, "SocketGroup=" + GroupName, "SocketMode=0660", "SocketUser=root"} {
		if !strings.Contains(sock, want) {
			t.Errorf("socket unit lacks %q", want)
		}
	}
}
