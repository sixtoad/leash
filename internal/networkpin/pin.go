// Package networkpin freezes explicitly selected Docker registry names for one
// container lifetime. It supplies resolution consistency, never network authority.
package networkpin

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const MaxHosts = 32
const MaxAddresses = 256
const MaxHostsBytes = 1 << 20
const Timeout = 10 * time.Second

type Mapping struct {
	Host      string   `json:"host"`
	Addresses []string `json:"addresses"`
}
type Lookup func(context.Context, string, string) ([]netip.Addr, error)

func Names(raw []string) ([]string, error) {
	if len(raw) == 0 {
		return nil, errors.New("at least one exact hostname is required")
	}
	seen := map[string]bool{}
	for _, name := range raw {
		name = strings.ToLower(name)
		if len(name) == 0 || len(name) > 253 {
			return nil, fmt.Errorf("invalid exact hostname %q", name)
		}
		if _, err := netip.ParseAddr(name); err == nil {
			return nil, fmt.Errorf("address literal %q is not a hostname", name)
		}
		for _, label := range strings.Split(name, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return nil, fmt.Errorf("invalid exact hostname %q", name)
			}
			for _, c := range label {
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
					return nil, fmt.Errorf("invalid exact hostname %q", name)
				}
			}
		}
		seen[name] = true
		if len(seen) > MaxHosts {
			return nil, fmt.Errorf("at most %d pinned hostnames are supported", MaxHosts)
		}
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out, nil
}

// Resolve completes and validates the entire snapshot before the caller writes.
func Resolve(ctx context.Context, raw []string, lookup Lookup) ([]Mapping, error) {
	names, err := Names(raw)
	if err != nil {
		return nil, err
	}
	var out []Mapping
	total := 0
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		addresses, err := lookup(ctx, "ip4", name)
		if err != nil {
			return nil, fmt.Errorf("resolve %s: %w", name, err)
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		unique := map[string]bool{}
		for _, addr := range addresses {
			if !addr.Is4() || addr.IsUnspecified() || addr.IsMulticast() {
				return nil, fmt.Errorf("resolve %s returned invalid IPv4 address %s", name, addr)
			}
			unique[addr.String()] = true
		}
		if len(unique) == 0 {
			return nil, fmt.Errorf("resolve %s returned no IPv4 addresses", name)
		}
		total += len(unique)
		if total > MaxAddresses {
			return nil, fmt.Errorf("pinned addresses exceed %d", MaxAddresses)
		}
		mapping := Mapping{Host: name}
		for addr := range unique {
			mapping.Addresses = append(mapping.Addresses, addr)
		}
		sort.Strings(mapping.Addresses)
		out = append(out, mapping)
	}
	return out, nil
}

// CheckNSS refuses configurations that could bypass the snapshot for libc or Go.
func CheckNSS(data []byte) error {
	found := false
	for _, line := range strings.Split(string(data), "\n") {
		database, config, ok := strings.Cut(strings.SplitN(line, "#", 2)[0], ":")
		if !ok || strings.TrimSpace(database) != "hosts" {
			continue
		}
		if found {
			return errors.New("network host pinning does not support duplicate nsswitch hosts entries")
		}
		found = true
		fields := strings.Fields(config)
		if len(fields) == 0 || fields[0] != "files" {
			return errors.New("network host pinning requires nsswitch hosts: files first")
		}
		if len(fields) > 1 && strings.HasPrefix(fields[1], "[") {
			return errors.New("network host pinning does not support nsswitch files action overrides")
		}
	}
	if !found {
		return errors.New("network host pinning requires an explicit nsswitch hosts: files first entry")
	}
	return nil
}

func Render(original []byte, mappings []Mapping) ([]byte, error) {
	if len(original) > MaxHostsBytes {
		return nil, errors.New("hosts file exceeds size limit")
	}
	selected := map[string]bool{}
	for _, m := range mappings {
		selected[m.Host] = true
	}
	var out strings.Builder
	for _, line := range strings.SplitAfter(string(original), "\n") {
		if line == "" {
			continue
		}
		body, comment, hasComment := strings.Cut(strings.TrimSuffix(line, "\n"), "#")
		fields := strings.Fields(body)
		if len(fields) < 2 {
			out.WriteString(line)
			continue
		}
		kept := []string{fields[0]}
		changed := false
		for _, name := range fields[1:] {
			if selected[strings.ToLower(name)] {
				changed = true
			} else {
				kept = append(kept, name)
			}
		}
		if !changed {
			out.WriteString(line)
			continue
		}
		if len(kept) > 1 {
			out.WriteString(strings.Join(kept, "\t"))
			if hasComment {
				out.WriteString(" #" + comment)
			}
			out.WriteByte('\n')
		} else if hasComment {
			out.WriteString("#" + comment + "\n")
		}
	}
	if out.Len() > 0 && !strings.HasSuffix(out.String(), "\n") {
		out.WriteByte('\n')
	}
	out.WriteString("# Leash pinned network hosts (container lifetime)\n")
	for _, m := range mappings {
		for _, addr := range m.Addresses {
			fmt.Fprintf(&out, "%s\t%s\n", addr, m.Host)
		}
	}
	if out.Len() > MaxHostsBytes {
		return nil, errors.New("pinned hosts file exceeds size limit")
	}
	return []byte(out.String()), nil
}

// Pin changes only a regular, non-symlink hosts file after every lookup succeeds.
// The runner verifies Docker owns the file and holds the workload until success.
func Pin(ctx context.Context, hostsPath, nssPath string, names []string, lookup Lookup) ([]Mapping, error) {
	nss, err := os.ReadFile(nssPath)
	if err != nil {
		return nil, fmt.Errorf("read name service configuration: %w", err)
	}
	if err = CheckNSS(nss); err != nil {
		return nil, err
	}
	fd, err := unix.Open(hostsPath, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open Docker hosts file: %w", err)
	}
	f := os.NewFile(uintptr(fd), hostsPath)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("Docker hosts file must be regular")
	}
	original, err := io.ReadAll(io.LimitReader(f, MaxHostsBytes+1))
	if err != nil {
		return nil, err
	}
	if len(original) > MaxHostsBytes {
		return nil, errors.New("hosts file exceeds size limit")
	}
	mappings, err := Resolve(ctx, names, lookup)
	if err != nil {
		return nil, err
	}
	data, err := Render(original, mappings)
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if _, err = f.Seek(0, 0); err != nil {
		return nil, err
	}
	if _, err = f.Write(data); err != nil {
		return nil, err
	}
	if err = f.Truncate(int64(len(data))); err != nil {
		return nil, err
	}
	if err = f.Sync(); err != nil {
		return nil, err
	}
	if err = f.Close(); err != nil {
		return nil, err
	}
	return mappings, nil
}

func PinDefault(ctx context.Context, names []string) ([]Mapping, error) {
	return Pin(ctx, "/etc/hosts", "/etc/nsswitch.conf", names, net.DefaultResolver.LookupNetIP)
}
