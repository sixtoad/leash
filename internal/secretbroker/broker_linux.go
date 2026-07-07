//go:build linux

package secretbroker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/prop"
)

const (
	ssName       = "org.freedesktop.secrets"
	ssServicePth = "/org/freedesktop/secrets"
	ssCollPth    = "/org/freedesktop/secrets/collection/login"
	ssSessionPth = "/org/freedesktop/secrets/session/shadow"
	ifaceService = "org.freedesktop.Secret.Service"
	ifaceColl    = "org.freedesktop.Secret.Collection"
	ifaceItem    = "org.freedesktop.Secret.Item"
	ifaceSession = "org.freedesktop.Secret.Session"
)

// secret is the org.freedesktop.Secret.Item Secret struct: (session, params,
// value, content_type). Phase 1 supports only the "plain" session, so Value is
// the cleartext secret.
type secret struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string
}

// linuxBroker runs a private dbus-daemon and exports a shadow Secret Service on
// it that live-proxies the real keyring, serving only allow-listed items.
type linuxBroker struct {
	daemon   *exec.Cmd
	priv     *dbus.Conn // the private (shadow) bus the sandbox connects to
	real     *dbus.Conn // the host's real session bus (proxy target)
	realSess dbus.ObjectPath
	sockPath string
	dir      string
	allow    *Allowlist
}

// Start launches the private bus + shadow service. sockPath is where the private
// bus listens (chosen by the launcher so it can inject it into the sandbox); if
// empty, a temp path is used. The returned Broker's SocketPath is what the
// launcher exposes to the box as DBUS_SESSION_BUS_ADDRESS.
func Start(ctx context.Context, allow *Allowlist, sockPath string) (Broker, error) {
	if allow == nil || !allow.Enabled() {
		return nil, errors.New("secretbroker: no secrets allow-listed")
	}
	var dir string
	if sockPath == "" {
		d, err := os.MkdirTemp("", "leash-secretbus-")
		if err != nil {
			return nil, fmt.Errorf("secretbroker: temp dir: %w", err)
		}
		dir, sockPath = d, filepath.Join(d, "bus")
	} else if err := os.MkdirAll(filepath.Dir(sockPath), 0o755); err != nil {
		return nil, fmt.Errorf("secretbroker: socket dir: %w", err)
	}
	b := &linuxBroker{dir: dir, sockPath: sockPath, allow: allow}

	for _, step := range []func(context.Context) error{b.startDaemon, b.connect, b.exportShadow} {
		if err := step(ctx); err != nil {
			b.Close()
			return nil, err
		}
	}
	return b, nil
}

func (b *linuxBroker) SocketPath() string { return b.sockPath }

func (b *linuxBroker) startDaemon(ctx context.Context) error {
	addr := "unix:path=" + b.sockPath
	// A private, isolated session bus for the box; --address overrides the
	// session config's listen address.
	b.daemon = exec.CommandContext(ctx, "dbus-daemon", "--session",
		"--address="+addr, "--nofork", "--nopidfile")
	if err := b.daemon.Start(); err != nil {
		return fmt.Errorf("secretbroker: start dbus-daemon: %w", err)
	}
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(b.sockPath); err == nil {
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return errors.New("secretbroker: dbus-daemon socket did not appear")
}

func (b *linuxBroker) connect(_ context.Context) error {
	priv, err := dbus.Dial("unix:path=" + b.sockPath)
	if err != nil {
		return fmt.Errorf("secretbroker: dial shadow bus: %w", err)
	}
	if err := priv.Auth(nil); err != nil {
		return fmt.Errorf("secretbroker: auth shadow bus: %w", err)
	}
	if err := priv.Hello(); err != nil {
		return fmt.Errorf("secretbroker: hello shadow bus: %w", err)
	}
	b.priv = priv

	real, err := dbus.ConnectSessionBus()
	if err != nil {
		return fmt.Errorf("secretbroker: connect real keyring bus: %w", err)
	}
	b.real = real

	// Open a plain session on the real bus for proxied GetSecret calls.
	var out dbus.Variant
	var sess dbus.ObjectPath
	if err := b.realSvc().Call(ifaceService+".OpenSession", 0, "plain", dbus.MakeVariant("")).
		Store(&out, &sess); err != nil {
		return fmt.Errorf("secretbroker: open real session: %w", err)
	}
	b.realSess = sess
	return nil
}

func (b *linuxBroker) exportShadow(_ context.Context) error {
	if err := b.priv.Export(&service{b: b}, ssServicePth, ifaceService); err != nil {
		return err
	}
	if err := b.priv.Export(&collection{b: b}, ssCollPth, ifaceColl); err != nil {
		return err
	}
	if err := b.priv.Export(&session{}, ssSessionPth, ifaceSession); err != nil {
		return err
	}
	// Service + Collection properties go-keyring reads (unlocked, so no prompt).
	spec := map[string]map[string]*prop.Prop{
		ifaceService: {"Collections": ro([]dbus.ObjectPath{ssCollPth})},
	}
	if _, err := prop.Export(b.priv, ssServicePth, spec); err != nil {
		return err
	}
	collSpec := map[string]map[string]*prop.Prop{
		ifaceColl: {"Locked": ro(false), "Label": ro("shadow")},
	}
	if _, err := prop.Export(b.priv, ssCollPth, collSpec); err != nil {
		return err
	}
	reply, err := b.priv.RequestName(ssName, dbus.NameFlagDoNotQueue)
	if err != nil {
		return fmt.Errorf("secretbroker: request name: %w", err)
	}
	if reply != dbus.RequestNameReplyPrimaryOwner {
		return errors.New("secretbroker: could not own org.freedesktop.secrets on the shadow bus")
	}
	return nil
}

func ro(v interface{}) *prop.Prop {
	return &prop.Prop{Value: v, Writable: false, Emit: prop.EmitFalse}
}

func (b *linuxBroker) realSvc() dbus.BusObject { return b.real.Object(ssName, ssServicePth) }

// realItemAttrs reads an item's attributes from the real bus (to filter).
func (b *linuxBroker) realItemAttrs(item dbus.ObjectPath) map[string]string {
	v, err := b.real.Object(ssName, item).GetProperty(ifaceItem + ".Attributes")
	if err != nil {
		return nil
	}
	attrs, _ := v.Value().(map[string]string)
	return attrs
}

// realSearch proxies SearchItems to the real service, keeps only allow-listed
// items, and exports a proxy Item object for each so the caller can GetSecret it.
func (b *linuxBroker) realSearch(attrs map[string]string) []dbus.ObjectPath {
	var unlocked, locked []dbus.ObjectPath
	if err := b.realSvc().Call(ifaceService+".SearchItems", 0, attrs).Store(&unlocked, &locked); err != nil {
		return nil
	}
	out := make([]dbus.ObjectPath, 0, len(unlocked)+len(locked))
	for _, it := range append(unlocked, locked...) {
		if !b.allow.AllowsAttributes(b.realItemAttrs(it)) {
			continue
		}
		_ = b.priv.Export(&item{b: b, path: it}, it, ifaceItem)
		_, _ = prop.Export(b.priv, it, map[string]map[string]*prop.Prop{
			ifaceItem: {"Locked": ro(false), "Label": ro("shadow")},
		})
		out = append(out, it)
	}
	return out
}

// getSecret fetches an allowed item's secret from the real bus (plain) and
// re-wraps it under the caller's session.
func (b *linuxBroker) getSecret(path, callerSession dbus.ObjectPath) (secret, bool) {
	if !b.allow.AllowsAttributes(b.realItemAttrs(path)) {
		return secret{}, false
	}
	var real secret
	if err := b.real.Object(ssName, path).Call(ifaceItem+".GetSecret", 0, b.realSess).Store(&real); err != nil {
		return secret{}, false
	}
	real.Session = callerSession
	return real, true
}

func (b *linuxBroker) Close() error {
	if b.priv != nil {
		_ = b.priv.Close()
	}
	if b.real != nil {
		_ = b.real.Close()
	}
	if b.daemon != nil && b.daemon.Process != nil {
		_ = b.daemon.Process.Kill()
		_ = b.daemon.Wait()
	}
	if b.dir != "" {
		_ = os.RemoveAll(b.dir)
	}
	return nil
}

// --- exported shadow D-Bus objects ---

type service struct{ b *linuxBroker }

// OpenSession — Phase 1 supports "plain" only: empty output, our fixed session.
func (s *service) OpenSession(_ string, _ dbus.Variant) (dbus.Variant, dbus.ObjectPath, *dbus.Error) {
	return dbus.MakeVariant(""), ssSessionPth, nil
}

func (s *service) SearchItems(attrs map[string]string) ([]dbus.ObjectPath, []dbus.ObjectPath, *dbus.Error) {
	return s.b.realSearch(attrs), nil, nil // served items are reported unlocked
}

func (s *service) Unlock(objects []dbus.ObjectPath) ([]dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	return objects, dbus.ObjectPath("/"), nil // nothing to prompt; we serve unlocked
}

func (s *service) ReadAlias(_ string) (dbus.ObjectPath, *dbus.Error) { return ssCollPth, nil }

func (s *service) GetSecrets(items []dbus.ObjectPath, session dbus.ObjectPath) (map[dbus.ObjectPath]secret, *dbus.Error) {
	out := map[dbus.ObjectPath]secret{}
	for _, it := range items {
		if sec, ok := s.b.getSecret(it, session); ok {
			out[it] = sec
		}
	}
	return out, nil
}

type collection struct{ b *linuxBroker }

func (c *collection) SearchItems(attrs map[string]string) ([]dbus.ObjectPath, *dbus.Error) {
	return c.b.realSearch(attrs), nil
}

type item struct {
	b    *linuxBroker
	path dbus.ObjectPath
}

func (i *item) GetSecret(session dbus.ObjectPath) (secret, *dbus.Error) {
	sec, ok := i.b.getSecret(i.path, session)
	if !ok {
		return secret{}, dbus.MakeFailedError(errors.New("secret not permitted"))
	}
	return sec, nil
}

type session struct{}

func (s *session) Close() *dbus.Error { return nil }
