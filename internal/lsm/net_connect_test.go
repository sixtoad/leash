package lsm

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unsafe"
)

const asymmetricIPv4 = uint32(0xc0a80101) // 192.168.1.1

func TestConnectAddressAndPortABIOffsets(t *testing.T) {
	var policy ConnectPolicyRuleBPF
	if got := unsafe.Offsetof(policy.Family); got != 8 {
		t.Fatalf("ConnectPolicyRuleBPF.Family offset = %d, want 8", got)
	}
	if got := unsafe.Offsetof(policy.DestIP); got != 12 {
		t.Fatalf("ConnectPolicyRuleBPF.DestIP offset = %d, want 12", got)
	}
	if got := unsafe.Offsetof(policy.DestIP6); got != 16 {
		t.Fatalf("ConnectPolicyRuleBPF.DestIP6 offset = %d, want 16", got)
	}
	if got := unsafe.Offsetof(policy.DestPort); got != 32 {
		t.Fatalf("ConnectPolicyRuleBPF.DestPort offset = %d, want 32", got)
	}
	if got := unsafe.Sizeof(policy); got != 36 {
		t.Fatalf("ConnectPolicyRuleBPF size = %d, want 36", got)
	}

	var event ConnectEvent
	if got := unsafe.Offsetof(event.DestIP); got != 48 {
		t.Fatalf("ConnectEvent.DestIP offset = %d, want 48", got)
	}
	if got := unsafe.Offsetof(event.DestPort); got != 52 {
		t.Fatalf("ConnectEvent.DestPort offset = %d, want 52", got)
	}
	if got := unsafe.Offsetof(event.DestIP6); got != 188 {
		t.Fatalf("ConnectEvent.DestIP6 offset = %d, want 188", got)
	}
	if got := unsafe.Sizeof(event); got != 208 {
		t.Fatalf("ConnectEvent size = %d, want 208", got)
	}
}

func TestConnectPolicyMapAddressAndPortNativeValues(t *testing.T) {
	policy := ConnectPolicyRuleBPF{Family: afInet, DestIP: asymmetricIPv4, DestPort: 443}
	raw := unsafe.Slice((*byte)(unsafe.Pointer(&policy)), int(unsafe.Sizeof(policy)))
	if got := binary.NativeEndian.Uint32(raw[8:12]); got != afInet {
		t.Fatalf("serialized policy family = %d, want %d", got, afInet)
	}
	if got := binary.NativeEndian.Uint32(raw[12:16]); got != asymmetricIPv4 {
		t.Fatalf("serialized policy IP = %#08x, want %#08x", got, asymmetricIPv4)
	}
	if got := binary.NativeEndian.Uint16(raw[32:34]); got != 443 {
		t.Fatalf("serialized policy port = %d, want 443", got)
	}
}

func TestConnectBPFHooksCanonicalizeSockaddrFields(t *testing.T) {
	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source")
	}
	source, err := os.ReadFile(filepath.Join(filepath.Dir(testFile), "bpf", "lsm_connect.bpf.c"))
	if err != nil {
		t.Fatalf("read connect BPF source: %v", err)
	}

	text := string(source)
	connectStart := strings.Index(text, `SEC("lsm/socket_connect")`)
	sendmsgStart := strings.Index(text, `SEC("lsm/socket_sendmsg")`)
	if connectStart < 0 || sendmsgStart <= connectStart {
		t.Fatal("connect and sendmsg hook sections not found")
	}
	hooks := map[string]string{
		"socket_connect": text[connectStart:sendmsgStart],
		"socket_sendmsg": text[sendmsgStart:],
	}
	for name, body := range hooks {
		t.Run(name, func(t *testing.T) {
			// Both hooks decide through the shared classifier, which reads
			// IPv4 and IPv6 sockaddrs.
			if !strings.Contains(body, "decide_destination(sock, ") {
				t.Fatal("hook does not decide through decide_destination")
			}
			// Both hooks receive a kernel copy of the sockaddr; a user read
			// fails at runtime.
			if strings.Contains(body, "bpf_probe_read_user") {
				t.Fatal("sockaddr is read with bpf_probe_read_user; it is a kernel pointer at this hook")
			}
		})
	}
	for _, want := range []string{
		"d->ip = bpf_ntohl(a4.sin_addr.s_addr)", // IPv4 address, canonical
		"d->port = bpf_ntohs(a4.sin_port)",      // IPv4 port, host order
		"d->port = bpf_ntohs(a6.sin6_port)",     // IPv6 port, host order
		"d->ip = bpf_ntohl(a6.sin6_addr[3])",    // IPv4-mapped IPv6 -> IPv4 path
	} {
		if !strings.Contains(text, want) {
			t.Errorf("read_inet_dest is missing %q", want)
		}
	}
	if strings.Contains(text, "bpf_probe_read_user") {
		t.Error("the connect program reads a user pointer; every sockaddr at these hooks is a kernel copy")
	}
}

func TestLiteralConnectPolicyUsesCanonicalAddressAndPort(t *testing.T) {
	rule, err := ParseRuleString("allow net.send 192.168.1.1:443")
	if err != nil {
		t.Fatalf("parse literal policy: %v", err)
	}
	if rule.DestIP != asymmetricIPv4 {
		t.Fatalf("literal policy IP = %#08x, want %#08x", rule.DestIP, asymmetricIPv4)
	}
	if rule.DestPort != 443 {
		t.Fatalf("literal policy port = %d, want 443", rule.DestPort)
	}

	loader, err := NewConnectLsm("/test", nil)
	if err != nil {
		t.Fatalf("new connect LSM: %v", err)
	}
	defaultDeny := false
	if err := loader.LoadPolicies(ConvertToConnectRules([]PolicyRule{*rule}), &defaultDeny); err != nil {
		t.Fatalf("load literal policy: %v", err)
	}
	if len(loader.policyRules) != 1 {
		t.Fatalf("loaded policy count = %d, want 1", len(loader.policyRules))
	}
	loaded := loader.policyRules[0]
	if loaded.DestIP != asymmetricIPv4 || loaded.DestPort != 443 {
		t.Fatalf("BPF map value = ip %#08x port %d, want ip %#08x port 443", loaded.DestIP, loaded.DestPort, asymmetricIPv4)
	}

	checker := newLegacyChecker(ConvertToConnectRules([]PolicyRule{*rule}), false, nil)
	if !checker.CheckConnect("", "192.168.1.1", 443) {
		t.Fatal("literal policy did not match its canonical address and port")
	}
	if checker.CheckConnect("", "1.1.168.192", 443) {
		t.Fatal("literal policy unexpectedly matched the byte-reversed address")
	}
}

func TestDNSCacheUsesCanonicalIPv4Key(t *testing.T) {
	loader, err := NewConnectLsm("/test", nil)
	if err != nil {
		t.Fatalf("new connect LSM: %v", err)
	}
	loader.UpdateDNSCache(asymmetricIPv4, "resolver.test")

	cache := loader.GetDNSCache()
	if got := cache[asymmetricIPv4]; got != "resolver.test" {
		t.Fatalf("canonical DNS cache entry = %q, want resolver.test", got)
	}
	if _, ok := cache[0x0101a8c0]; ok {
		t.Fatal("DNS cache contains a byte-reversed compatibility key")
	}
}

func TestConnectEventUpdatesDNSCacheWithCanonicalIPv4Key(t *testing.T) {
	loader, err := NewConnectLsm("/test", nil)
	if err != nil {
		t.Fatalf("new connect LSM: %v", err)
	}
	event := ConnectEvent{DestIP: asymmetricIPv4}
	copy(event.Comm[:], "agent")
	copy(event.DestHostname[:], "resolver.test")

	var encoded bytes.Buffer
	if err := binary.Write(&encoded, binary.LittleEndian, &event); err != nil {
		t.Fatalf("encode event: %v", err)
	}
	data := encoded.Bytes()
	data = append(data, make([]byte, int(unsafe.Sizeof(event))-len(data))...)
	loader.handleEvent(data)

	cache := loader.GetDNSCache()
	if got := cache[asymmetricIPv4]; got != "resolver.test" {
		t.Fatalf("event DNS cache entry = %q, want resolver.test", got)
	}
	if _, ok := cache[0x0101a8c0]; ok {
		t.Fatal("event DNS cache contains a byte-reversed compatibility key")
	}
}

func TestConnectEventFormatsCanonicalTCPAndUDPAddresses(t *testing.T) {
	tests := []struct {
		name     string
		family   uint32
		protocol uint32
		port     uint16
		want     string
	}{
		{name: "tcp", protocol: 6, port: 443, want: `protocol=tcp addr="192.168.1.1:443"`},
		{name: "udp-dns", protocol: 17, port: 53, want: `protocol=udp addr="192.168.1.1:53"`},
		{name: "tcp6", family: afInet6, protocol: 6, port: 443, want: `protocol=tcp addr="[2001:db8::1]:443"`},
		{name: "udp6-any-port", family: afInet6, protocol: 17, want: `protocol=udp addr="2001:db8::1"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logPath := filepath.Join(t.TempDir(), "events.log")
			logger, err := NewSharedLogger(logPath)
			if err != nil {
				t.Fatalf("new logger: %v", err)
			}
			t.Cleanup(func() { _ = logger.Close() })

			loader, err := NewConnectLsm("/test", logger)
			if err != nil {
				t.Fatalf("new connect LSM: %v", err)
			}
			event := ConnectEvent{
				PID:      42,
				CgroupID: 99,
				Family:   afInet,
				Protocol: tt.protocol,
				DestIP:   asymmetricIPv4,
				DestPort: tt.port,
			}
			if tt.family == afInet6 {
				event.Family, event.DestIP = afInet6, 0
				copy(event.DestIP6[:], net.ParseIP("2001:db8::1").To16())
			}
			copy(event.Comm[:], "agent")

			rawEvent := unsafe.Slice((*byte)(unsafe.Pointer(&event)), int(unsafe.Sizeof(event)))
			loader.handleEvent(append([]byte(nil), rawEvent...))

			entry, err := os.ReadFile(logPath)
			if err != nil {
				t.Fatalf("read event log: %v", err)
			}
			if !strings.Contains(string(entry), tt.want) {
				t.Fatalf("event log %q does not contain %q", entry, tt.want)
			}
			if strings.Contains(string(entry), "1.1.168.192") {
				t.Fatalf("event log contains byte-reversed address: %q", entry)
			}
		})
	}
}

// The kernel emits struct connect_event with C alignment: result at 56 and
// dest_hostname at 60. handleEvent decodes with binary.Read, which inserts no
// padding, so the Go struct must carry it explicitly or a denied event's
// result bytes leak into the hostname (logged as hostname="\xEF\xBF\xBD").
func TestConnectEventDecodesKernelLayout(t *testing.T) {
	var event ConnectEvent
	if got := unsafe.Offsetof(event.Result); got != 56 {
		t.Fatalf("ConnectEvent.Result offset = %d, want 56", got)
	}
	if got := unsafe.Offsetof(event.DestHostname); got != 60 {
		t.Fatalf("ConnectEvent.DestHostname offset = %d, want 60", got)
	}

	for _, tt := range []struct {
		name, hostname, want, reject string
	}{
		{name: "no-dns-entry", want: `addr="192.168.1.1:443" decision=denied`, reject: "hostname="},
		{name: "dns-entry", hostname: "resolver.test", want: `hostname="resolver.test" decision=denied`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// Build the record byte-for-byte as the BPF program lays it out.
			raw := make([]byte, 208)
			binary.NativeEndian.PutUint32(raw[0:], 42)
			copy(raw[24:40], "agent")
			binary.NativeEndian.PutUint32(raw[40:], 2)
			binary.NativeEndian.PutUint32(raw[44:], 6)
			binary.NativeEndian.PutUint32(raw[48:], asymmetricIPv4)
			binary.NativeEndian.PutUint16(raw[52:], 443)
			binary.NativeEndian.PutUint32(raw[56:], uint32(0xfffffff3)) // -EACCES
			copy(raw[60:], tt.hostname)

			logPath := filepath.Join(t.TempDir(), "events.log")
			logger, err := NewSharedLogger(logPath)
			if err != nil {
				t.Fatalf("new logger: %v", err)
			}
			t.Cleanup(func() { _ = logger.Close() })
			loader, err := NewConnectLsm("/test", logger)
			if err != nil {
				t.Fatalf("new connect LSM: %v", err)
			}
			loader.handleEvent(raw)

			entry, err := os.ReadFile(logPath)
			if err != nil {
				t.Fatalf("read event log: %v", err)
			}
			if !strings.Contains(string(entry), tt.want) {
				t.Fatalf("event log %q does not contain %q", entry, tt.want)
			}
			if tt.reject != "" && strings.Contains(string(entry), tt.reject) {
				t.Fatalf("event log %q unexpectedly contains %q", entry, tt.reject)
			}
		})
	}
}
