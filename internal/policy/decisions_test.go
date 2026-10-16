package policy

import (
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/strongdm/leash/internal/cedar"
	"github.com/strongdm/leash/internal/engine"
	"github.com/strongdm/leash/internal/lsm"
)

func TestDecisionsPublishIsOrderedAndShared(t *testing.T) {
	var d Decisions
	if d.Current() != nil {
		t.Fatal("snapshot before first publish")
	}
	var saw []*engine.Engine
	var mu sync.Mutex
	consume := func(e *engine.Engine) {
		mu.Lock()
		saw = append(saw, e)
		mu.Unlock()
	}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e, _ := engine.New(nil)
			d.Publish(e, consume)
		}()
	}
	wg.Wait()
	snap := d.Current()
	if snap.Generation != 50 {
		t.Fatalf("generation = %d, want 50", snap.Generation)
	}
	if saw[len(saw)-1] != snap.Engine {
		t.Fatal("consumers and Current disagree on the active engine")
	}
}

func mustCompile(t *testing.T, name, text string) *cedar.Compilation {
	t.Helper()
	comp, err := cedar.CompileString(name, text)
	if err != nil {
		t.Fatalf("compile %s: %v", name, err)
	}
	return comp
}

// The proxy and the authz socket answer from the same engine: a policy
// change through the Manager reaches both in one Publish.
func TestManagerPublishesOneEngine(t *testing.T) {
	var decisions Decisions
	var proxyEngine *engine.Engine
	m := NewManager(nil, func(active *cedar.Compilation) {
		decisions.Publish(active.Engine, func(e *engine.Engine) { proxyEngine = e })
	})
	comp := mustCompile(t, "runtime.cedar", `permit (principal, action == Action::"NetworkConnect", resource) when { resource in [Host::"api.example.com"] };`)
	if err := m.SetRuntimeRules(comp.Policies, comp.HTTPRules); err != nil {
		t.Fatal(err)
	}
	snap := decisions.Current()
	if snap == nil || snap.Engine != proxyEngine || snap.Engine != m.Active().Engine {
		t.Fatal("proxy did not receive the published engine")
	}
	if !snap.Engine.DecideConnect("api.example.com", "", 443).Allow || snap.Engine.DecideConnect("other.example.com", "", 443).Allow {
		t.Fatal("runtime policy not visible to the engine")
	}
}

// Legacy most-specific-wins crosses layers: a runtime permit nested under a
// file forbid still wins, as the legacy rule merge did.
func TestManagerRewritesLegacyLayersTogether(t *testing.T) {
	m := NewManager(nil, nil)
	file := mustCompile(t, "leash.cedar", `forbid (principal, action == Action::"FileOpen", resource) when { resource in [Dir::"/work/"] };`)
	runtime := mustCompile(t, "runtime.cedar", `permit (principal, action == Action::"FileOpen", resource) when { resource in [Dir::"/work/ok/"] };`)
	if err := m.UpdateFileRules(file.Policies, file.HTTPRules); err != nil {
		t.Fatal(err)
	}
	if err := m.SetRuntimeRules(runtime.Policies, runtime.HTTPRules); err != nil {
		t.Fatal(err)
	}
	active := m.Active()
	if active.Rewrite == nil || len(active.Rewrite.Exceptions) != 1 {
		t.Fatalf("the file forbid must gain the runtime permit as an exception: %+v", active.Rewrite)
	}
	if !active.Engine.DecideOpen("/work/ok/a", engine.ActionFileOpenReadWrite).Allow || active.Engine.DecideOpen("/work/a", engine.ActionFileOpenReadWrite).Allow {
		t.Fatal("cross-layer specificity lost")
	}
	if !active.Engine.DecideMCP("any", "tool").Allow {
		t.Fatal("legacy layers keep the MCP default allow")
	}
	// The kernel tables are compiled from the merge, not concatenated.
	rules, _ := m.GetActiveRules()
	k := map[string]bool{}
	for _, r := range rules.Open {
		k[r.String()] = true
	}
	// (The forbid is the default deny: pruned.)
	if !k["allow file.open /work/ok/"] || len(rules.Open) != 1 {
		t.Fatalf("kernel rules: %v", rules.Open)
	}
}

// A strict layer keeps strict defaults: a legacy runtime layer merged with it
// does not bring the legacy MCP default allow.
func TestManagerStrictFileWithLegacyRuntime(t *testing.T) {
	m := NewManager(nil, nil)
	file := mustCompile(t, "leash.cedar", `@leash_semantics("cedar")
permit (principal, action == Action::"NetworkConnect", resource in Host::"api.example.com");`)
	runtime := mustCompile(t, "runtime.cedar", `permit (principal, action == Action::"ProcessExec", resource) when { resource in [Dir::"/bin/"] };
permit (principal, action == Action::"FileOpenReadOnly", resource) when { resource in [Dir::"/"] };`)
	if err := m.UpdateFileRules(file.Policies, file.HTTPRules); err != nil {
		t.Fatal(err)
	}
	if err := m.SetRuntimeRules(runtime.Policies, runtime.HTTPRules); err != nil {
		t.Fatal(err)
	}
	e := m.Active().Engine
	if e.DecideMCP("mcp.example.com", "search").Allow {
		t.Fatal("strict file: MCP is default deny even with a legacy runtime layer")
	}
	if !e.DecideOpen("/etc/hosts", engine.ActionFileOpenReadOnly).Allow || e.DecideOpen("/etc/hosts", engine.ActionFileOpenReadWrite).Allow {
		t.Fatal("strict file: a legacy read-only \"/\" must not bring the legacy all-modes default allow")
	}
	if !e.DecideExec("/bin/ls").Allow || !e.DecideConnect("api.example.com", "", 443).Allow {
		t.Fatal("both layers apply")
	}
}

// A change that does not compile is rejected whole; the previous policy
// stays active.
func TestManagerRejectsAChangeThatDoesNotCompile(t *testing.T) {
	m := NewManager(nil, nil)
	good := mustCompile(t, "leash.cedar", `@leash_semantics("cedar")
permit (principal, action in Action::"FileOpen", resource in Dir::"/x/");`)
	if err := m.UpdateFileRules(good.Policies, good.HTTPRules); err != nil {
		t.Fatal(err)
	}
	// A layer the kernel cannot enforce: a file policy reading the context.
	before := m.Active()
	bad := &lsm.PolicySet{Source: &lsm.PolicySource{Name: "runtime.cedar", Text: `@leash_semantics("cedar")
forbid (principal, action in Action::"FileOpen", resource in Dir::"/x/a/") when { context.tty == true };
permit (principal, action in Action::"FileOpen", resource in File::"/x/a/");`}}
	err := m.SetRuntimeRules(bad, nil)
	if !errors.Is(err, ErrCompile) || !strings.Contains(err.Error(), "not enforceable by the kernel") {
		t.Fatalf("got %v", err)
	}
	if m.Active() != before {
		t.Fatal("a rejected change must leave the active policy in place")
	}
	if _, _, rt, _ := m.Snapshot(); rt.Source != nil {
		t.Fatal("a rejected change must not be committed")
	}
}

func TestManagerRuntimeOnly(t *testing.T) {
	m := NewManager(nil, nil)
	file := mustCompile(t, "leash.cedar", `permit (principal, action == Action::"ProcessExec", resource) when { resource in [Dir::"/bin/"] };`)
	allow := mustCompile(t, "permit-all.cedar", DefaultCedar())
	if err := m.UpdateFileRules(file.Policies, nil); err != nil {
		t.Fatal(err)
	}
	if err := m.SetRuntimeOnly(true); err != nil {
		t.Fatal(err)
	}
	if err := m.SetRuntimeRules(allow.Policies, nil); err != nil {
		t.Fatal(err)
	}
	if !m.Active().Engine.DecideExec("/opt/x").Allow {
		t.Fatal("runtime-only permit-all")
	}
	if err := m.SetRuntimeOnly(false); err != nil {
		t.Fatal(err)
	}
	if err := m.SetRuntimeRules(&lsm.PolicySet{}, nil); err != nil {
		t.Fatal(err)
	}
	if m.Active().Engine.DecideExec("/opt/x").Allow || !m.Active().Engine.DecideExec("/bin/ls").Allow {
		t.Fatal("back to the file layer")
	}
}
