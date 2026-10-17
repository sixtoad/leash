package leashd

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	cedarutil "github.com/strongdm/leash/internal/cedar"
	"github.com/strongdm/leash/internal/enforcerd"
	"github.com/strongdm/leash/internal/lsm"
	"github.com/strongdm/leash/internal/policy"
)

// scriptedDaemon answers every request OK and records it.
type scriptedDaemon struct {
	mu   sync.Mutex
	reqs []enforcerd.Request
	conn net.Conn
	// refuse, when set, returns a non-empty error for a request to refuse.
	refuse func(enforcerd.Request) string
}

func (d *scriptedDaemon) setRefuse(f func(enforcerd.Request) string) {
	d.mu.Lock()
	d.refuse = f
	d.mu.Unlock()
}

func (d *scriptedDaemon) serve(conn net.Conn) {
	d.conn = conn
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 64*1024), enforcerd.MaxLineBytes)
	for sc.Scan() {
		var r enforcerd.Request
		_ = json.Unmarshal(sc.Bytes(), &r)
		d.mu.Lock()
		d.reqs = append(d.reqs, r)
		refuse := d.refuse
		d.mu.Unlock()
		m := enforcerd.Message{V: 1, Type: enforcerd.TypeResult, OK: true}
		if r.Op == enforcerd.OpAttach {
			m.Session, m.Programs = "s1", 3
		}
		if refuse != nil {
			if msg := refuse(r); msg != "" {
				m = enforcerd.Message{V: 1, Type: enforcerd.TypeResult, Error: msg}
			}
		}
		data, _ := json.Marshal(m)
		_, _ = conn.Write(append(data, '\n'))
	}
}

func (d *scriptedDaemon) end(reason string) {
	data, _ := json.Marshal(enforcerd.Message{V: 1, Type: enforcerd.TypeEnded, Error: reason})
	_, _ = d.conn.Write(append(data, '\n'))
}

func (d *scriptedDaemon) requests() []enforcerd.Request {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]enforcerd.Request(nil), d.reqs...)
}

func newTestRemote(t *testing.T) (*remoteKernel, *scriptedDaemon, *[]string) {
	t.Helper()
	d := &scriptedDaemon{}
	var mu sync.Mutex
	events := &[]string{}
	k := newRemoteKernel("/run/leash-enforcer/enforcerd.sock", "/sys/fs/cgroup/user.slice/x", func(l string) {
		mu.Lock()
		*events = append(*events, l)
		mu.Unlock()
	})
	k.lookup = func(host string) ([]net.IP, error) {
		switch host {
		case "example.com":
			return []net.IP{net.ParseIP("2606:2800::1"), net.ParseIP("93.184.215.14")}, nil
		}
		return nil, errors.New("no such host")
	}
	k.dial = func(ctx context.Context, socket string, onEvent func(string)) (*enforcerd.Client, error) {
		a, b := net.Pipe()
		go d.serve(b)
		return enforcerd.NewClient(a, onEvent), nil
	}
	return k, d, events
}

const remotePolicy = `@leash_semantics("cedar")
permit (principal, action == Action::"FileOpenReadOnly", resource) when { resource in Dir::"/" };
@leash_semantics("cedar")
permit (principal, action == Action::"ProcessExec", resource) when { resource in Dir::"/" };
@leash_semantics("cedar")
permit (principal, action == Action::"NetworkConnect", resource) when { resource in [Host::"example.com", Host::"unresolvable.example", Host::"10.0.0.1:443"] };`

func TestRemoteKernelAttachSendsActivePolicyAndResolvedHosts(t *testing.T) {
	k, d, _ := newTestRemote(t)
	comp, err := cedarutil.CompileString("leash.cedar", remotePolicy)
	if err != nil {
		t.Fatal(err)
	}
	// A policy change before the attach is not sent: the attach carries the
	// policy active at that moment.
	if err := k.update(comp); err != nil {
		t.Fatal(err)
	}
	programs, err := k.attach(func() *cedarutil.Compilation { return comp })
	if err != nil || programs != 3 {
		t.Fatalf("attach = %d, %v", programs, err)
	}
	reqs := d.requests()
	if len(reqs) != 1 || reqs[0].Op != enforcerd.OpAttach {
		t.Fatalf("requests = %+v", reqs)
	}
	if reqs[0].Policy != comp.StrictText || reqs[0].Cgroup != "/sys/fs/cgroup/user.slice/x" {
		t.Fatalf("attach carried the wrong policy or cgroup: %+v", reqs[0])
	}
	if got := reqs[0].Hosts; len(got) != 1 || len(got["example.com"]) != 2 || got["example.com"][0] != "2606:2800::1" || got["example.com"][1] != "93.184.215.14" {
		t.Fatalf("resolved hosts = %v, want example.com's IPv6 and IPv4 addresses (the kernel matches both)", got)
	}

	next, err := cedarutil.CompileString("leash.cedar", remotePolicy+`
@leash_semantics("cedar")
forbid (principal, action == Action::"FileOpenReadOnly", resource == File::"/etc/hostname");`)
	if err != nil {
		t.Fatal(err)
	}
	if err := k.update(next); err != nil {
		t.Fatal(err)
	}
	reqs = d.requests()
	if len(reqs) != 2 || reqs[1].Op != enforcerd.OpUpdate || reqs[1].Policy != next.StrictText {
		t.Fatalf("update not forwarded: %+v", reqs)
	}
	k.detach()
	k.detach() // idempotent
	if reqs = d.requests(); len(reqs) != 3 || reqs[2].Op != enforcerd.OpDetach {
		t.Fatalf("detach not sent once: %+v", reqs)
	}
	if err := k.update(next); err != nil {
		t.Fatal("update after detach is a no-op")
	}
}

func TestRemoteKernelReportsSessionLoss(t *testing.T) {
	k, d, _ := newTestRemote(t)
	if k.ended() != nil {
		t.Fatal("no session before attach")
	}
	comp, _ := cedarutil.CompileString("leash.cedar", remotePolicy)
	if _, err := k.attach(func() *cedarutil.Compilation { return comp }); err != nil {
		t.Fatal(err)
	}
	d.end("the daemon stopped")
	select {
	case <-k.ended():
	case <-time.After(5 * time.Second):
		t.Fatal("session loss not reported")
	}
	if err := k.err(); err == nil || !strings.Contains(err.Error(), "the daemon stopped") {
		t.Fatalf("err = %v", err)
	}
}

func TestRemoteKernelDialFailureNamesTheFix(t *testing.T) {
	k, _, _ := newTestRemote(t)
	k.dial = func(ctx context.Context, socket string, onEvent func(string)) (*enforcerd.Client, error) {
		return nil, errors.New("dial unix /run/leash-enforcer/enforcerd.sock: connect: permission denied")
	}
	_, err := k.attach(func() *cedarutil.Compilation { return nil })
	if err == nil || !strings.Contains(err.Error(), "leash group") {
		t.Fatalf("attach = %v", err)
	}
}

// With the daemon as the kernel, policy changes are validated against the
// kernel's limits before they are committed, and a daemon failure is an LSM
// update failure (so a file reload rolls back).
func TestPolicyManagerRemoteKernel(t *testing.T) {
	mgr := policy.NewManager(lsm.NewLSMManager("", nil, true), nil)
	var sent []string
	fail := false
	mgr.SetRemoteKernel(func(c *cedarutil.Compilation) error {
		if fail {
			return errors.New("daemon refused")
		}
		sent = append(sent, c.StrictText)
		return nil
	})
	comp, err := cedarutil.CompileString("leash.cedar", remotePolicy)
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.UpdateFileRules(comp.Policies, nil); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 1 || !strings.Contains(sent[0], "example.com") {
		t.Fatalf("remote kernel got %v", sent)
	}
	var b strings.Builder
	for i := 0; i < 70; i++ {
		b.WriteString(`@leash_semantics("cedar") forbid (principal, action == Action::"ProcessExec", resource == File::"/usr/local/bin/n` + string(rune('a'+i%26)) + string(rune('a'+i/26)) + "\");\n")
	}
	big, err := cedarutil.CompileString("big.cedar", remotePolicy+"\n"+b.String())
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.UpdateFileRules(big.Policies, nil); !errors.Is(err, policy.ErrRejected) {
		t.Fatalf("over-limit policy with a remote kernel: %v, want ErrRejected", err)
	}
	if len(sent) != 1 {
		t.Fatal("a rejected policy must not reach the daemon")
	}
	fail = true
	if err := mgr.UpdateFileRules(comp.Policies, nil); err == nil || !strings.Contains(err.Error(), "enforcer daemon") {
		t.Fatalf("daemon failure: %v", err)
	}
}
