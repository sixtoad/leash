package networkpin

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestNames(t *testing.T) {
	got, err := Names([]string{"Storage.Example", "a.test", "storage.example"})
	if err != nil || !reflect.DeepEqual(got, []string{"a.test", "storage.example"}) {
		t.Fatalf("%v %v", got, err)
	}
	for _, name := range []string{"", "*", "*.test", "a.test:443", "127.0.0.1", "::1", "a.test.", "a..test", "-a.test", "a-.test", " a.test", "a.test\n", "a_1.test", strings.Repeat("a", 64) + ".test"} {
		if _, err := Names([]string{name}); err == nil {
			t.Errorf("accepted %q", name)
		}
	}
	names := make([]string, MaxHosts+1)
	for i := range names {
		names[i] = strings.Repeat("a", i+1) + ".test"
	}
	if _, err := Names(names); err == nil {
		t.Fatal("accepted too many names")
	}
}

func fixture(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	hosts := filepath.Join(dir, "hosts")
	nss := filepath.Join(dir, "nsswitch.conf")
	if err := os.WriteFile(hosts, []byte("127.0.0.1\tlocalhost\n# retained\n192.0.2.99 old.test alias.test # alias\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nss, []byte("hosts: files dns\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return hosts, nss
}
func lookup(_ context.Context, network, host string) ([]netip.Addr, error) {
	if network != "ip4" {
		return nil, errors.New("wrong network")
	}
	return []netip.Addr{netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")}, nil
}

func TestPinReplacesSelectedAliasesPreservesOthers(t *testing.T) {
	hosts, nss := fixture(t)
	mappings, err := Pin(context.Background(), hosts, nss, []string{"old.test"}, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(mappings, []Mapping{{Host: "old.test", Addresses: []string{"192.0.2.1", "192.0.2.2"}}}) {
		t.Fatalf("%+v", mappings)
	}
	data, _ := os.ReadFile(hosts)
	want := "127.0.0.1\tlocalhost\n# retained\n192.0.2.99\talias.test # alias\n# Leash pinned network hosts (container lifetime)\n192.0.2.1\told.test\n192.0.2.2\told.test\n"
	if string(data) != want {
		t.Fatalf("got %q want %q", data, want)
	}
}

func TestPinFailureDoesNotWrite(t *testing.T) {
	cases := map[string]Lookup{
		"later lookup fails": func(ctx context.Context, n, h string) ([]netip.Addr, error) {
			if h == "z.test" {
				return nil, errors.New("DNS failed")
			}
			return lookup(ctx, n, h)
		},
		"empty": func(context.Context, string, string) ([]netip.Addr, error) { return nil, nil },
		"IPv6": func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("2001:db8::1")}, nil
		},
		"unspecified": func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("0.0.0.0")}, nil
		},
		"timeout": func(ctx context.Context, n, h string) ([]netip.Addr, error) { <-ctx.Done(); return nil, ctx.Err() },
	}
	for name, fn := range cases {
		t.Run(name, func(t *testing.T) {
			hosts, nss := fixture(t)
			before, _ := os.ReadFile(hosts)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			if _, err := Pin(ctx, hosts, nss, []string{"a.test", "z.test"}, fn); err == nil {
				t.Fatal("expected failure")
			}
			after, _ := os.ReadFile(hosts)
			if string(before) != string(after) {
				t.Fatalf("hosts modified on failure: %q", after)
			}
		})
	}
}

func TestNSSFailClosed(t *testing.T) {
	for _, s := range []string{"", "hosts: dns files", "hosts: files [SUCCESS=continue] dns", "hosts: resolve files", "hosts: files dns\nhosts: dns files", "hosts: files dns\nhosts: files dns", "hosts: files dns\nhosts : dns files"} {
		if err := CheckNSS([]byte(s)); err == nil {
			t.Errorf("accepted %q", s)
		}
	}
	for _, s := range []string{"hosts: files dns", "hosts: files", "hosts : files dns", "hosts: files mdns4_minimal [NOTFOUND=return] dns"} {
		if err := CheckNSS([]byte(s)); err != nil {
			t.Errorf("rejected %q: %v", s, err)
		}
	}
}

func TestPinRejectsUnsafeFiles(t *testing.T) {
	t.Run("symlink", func(t *testing.T) {
		hosts, nss := fixture(t)
		link := hosts + ".link"
		if err := os.Symlink(hosts, link); err != nil {
			t.Fatal(err)
		}
		if _, err := Pin(context.Background(), link, nss, []string{"a.test"}, lookup); err == nil {
			t.Fatal("followed symlink")
		}
	})
	t.Run("directory", func(t *testing.T) {
		hosts, nss := fixture(t)
		if _, err := Pin(context.Background(), filepath.Dir(hosts), nss, []string{"a.test"}, lookup); err == nil {
			t.Fatal("accepted directory")
		}
	})
	t.Run("oversize", func(t *testing.T) {
		hosts, nss := fixture(t)
		if err := os.WriteFile(hosts, []byte(strings.Repeat("x", MaxHostsBytes+1)), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Pin(context.Background(), hosts, nss, []string{"a.test"}, lookup); err == nil {
			t.Fatal("accepted oversized hosts")
		}
	})
	t.Run("missing NSS", func(t *testing.T) {
		hosts, nss := fixture(t)
		if err := os.Remove(nss); err != nil {
			t.Fatal(err)
		}
		if _, err := Pin(context.Background(), hosts, nss, []string{"a.test"}, lookup); err == nil {
			t.Fatal("accepted missing NSS")
		}
	})
}

func TestResolveAddressBound(t *testing.T) {
	fn := func(context.Context, string, string) ([]netip.Addr, error) {
		out := make([]netip.Addr, MaxAddresses+1)
		ip := netip.MustParseAddr("192.0.2.1")
		for i := range out {
			out[i] = ip
			ip = ip.Next()
		}
		return out, nil
	}
	if _, err := Resolve(context.Background(), []string{"a.test"}, fn); err == nil {
		t.Fatal("accepted too many addresses")
	}
}
