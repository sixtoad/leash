package lsm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

// The connect map value and ring-buffer event ABI (#78). One explicit layout
// per struct, listed here once and checked four ways: the Go structs
// (offsets, sizes, no implicit padding), the C _Static_asserts in
// lsm_connect.bpf.c, the BTF of the compiled object, and hand-built byte
// fixtures through the real serialization paths.

type abiField struct {
	c      string // field name in lsm_connect.bpf.c
	offset uintptr
	size   uintptr
}

var connectPolicyRuleABI = []abiField{
	{"action", 0, 4},
	{"operation", 4, 4},
	{"family", 8, 4},
	{"dest_ip", 12, 4},
	{"dest_ip6", 16, 16},
	{"dest_port", 32, 2},
	{"_pad0", 34, 2},
}

const connectPolicyRuleSize = 36

var connectEventABI = []abiField{
	{"pid", 0, 4},
	{"tgid", 4, 4},
	{"timestamp", 8, 8},
	{"cgroup_id", 16, 8},
	{"comm", 24, 16},
	{"family", 40, 4},
	{"protocol", 44, 4},
	{"dest_ip", 48, 4},
	{"dest_port", 52, 2},
	{"sock_type", 54, 2},
	{"result", 56, 4},
	{"dest_hostname", 60, 128},
	{"dest_ip6", 188, 16},
	{"_pad1", 204, 4},
}

const connectEventSize = 208

// checkGoLayout: the Go struct has exactly the ABI's fields, in order, at
// the ABI's offsets and sizes, and no implicit padding (so binary.Read and
// binary.Write, which skip none, agree with the in-memory layout).
func checkGoLayout(t *testing.T, typ reflect.Type, abi []abiField, size uintptr) {
	t.Helper()
	if typ.NumField() != len(abi) {
		t.Fatalf("%s has %d fields, the ABI %d", typ, typ.NumField(), len(abi))
	}
	var sum uintptr
	for i, want := range abi {
		f := typ.Field(i)
		if f.Offset != want.offset || f.Type.Size() != want.size {
			t.Errorf("%s.%s (C %s): offset %d size %d, want offset %d size %d", typ, f.Name, want.c, f.Offset, f.Type.Size(), want.offset, want.size)
		}
		sum += f.Type.Size()
	}
	if typ.Size() != size {
		t.Errorf("sizeof(%s) = %d, want %d", typ, typ.Size(), size)
	}
	if sum != typ.Size() {
		t.Errorf("%s has %d bytes of implicit padding; name every padding byte", typ, typ.Size()-sum)
	}
	if bs := binary.Size(reflect.New(typ).Interface()); bs != int(size) {
		t.Errorf("binary.Size(%s) = %d, want %d", typ, bs, size)
	}
}

func TestConnectABIGoLayout(t *testing.T) {
	checkGoLayout(t, reflect.TypeOf(ConnectPolicyRuleBPF{}), connectPolicyRuleABI, connectPolicyRuleSize)
	checkGoLayout(t, reflect.TypeOf(ConnectEvent{}), connectEventABI, connectEventSize)

	// Named fields, by name, for readers of the table above.
	var r ConnectPolicyRuleBPF
	var e ConnectEvent
	for name, got := range map[string][2]uintptr{
		"rule.Family":        {unsafe.Offsetof(r.Family), 8},
		"rule.DestIP":        {unsafe.Offsetof(r.DestIP), 12},
		"rule.DestIP6":       {unsafe.Offsetof(r.DestIP6), 16},
		"rule.DestPort":      {unsafe.Offsetof(r.DestPort), 32},
		"event.Result":       {unsafe.Offsetof(e.Result), 56},
		"event.DestHostname": {unsafe.Offsetof(e.DestHostname), 60},
		"event.DestIP6":      {unsafe.Offsetof(e.DestIP6), 188},
	} {
		if got[0] != got[1] {
			t.Errorf("%s offset = %d, want %d", name, got[0], got[1])
		}
	}
}

// The C source asserts the same table at compile time (clang evaluates the
// _Static_asserts whenever the object is regenerated).
func TestConnectABIStaticAssertsMatchTable(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("bpf", "lsm_connect.bpf.c"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	for name, abi := range map[string][]abiField{"connect_policy_rule": connectPolicyRuleABI, "connect_event": connectEventABI} {
		for _, f := range abi {
			want := "CONNECT_ABI(" + name + ", " + f.c + ", " + itoa(f.offset) + ");"
			if !strings.Contains(text, want) {
				t.Errorf("lsm_connect.bpf.c lacks %s", want)
			}
		}
	}
	for _, want := range []string{
		"sizeof(struct connect_policy_rule) == " + itoa(connectPolicyRuleSize),
		"sizeof(struct connect_event) == " + itoa(connectEventSize),
	} {
		if !strings.Contains(text, want) {
			t.Errorf("lsm_connect.bpf.c lacks _Static_assert(%s)", want)
		}
	}
}

func itoa(v uintptr) string { return strconv.Itoa(int(v)) }

// connectSpecOrSkip returns the compiled connect object's spec; it exists
// where bpf2go generated it (Linux builds), and is absent (stub loader) or
// empty (build overlay) elsewhere.
func connectSpecOrSkip(t *testing.T) *ebpf.CollectionSpec {
	t.Helper()
	spec, err := loadLsmConnect()
	if err != nil || spec == nil || spec.Types == nil {
		t.Skipf("compiled connect object not available here (%v)", err)
	}
	return spec
}

// BTF evidence: the object clang produced has the ABI's member offsets and
// sizes, and the map value size is the Go struct's.
func TestConnectABIMatchesCompiledBTF(t *testing.T) {
	spec := connectSpecOrSkip(t)
	for name, abi := range map[string]struct {
		fields []abiField
		size   uint32
	}{
		"connect_policy_rule": {connectPolicyRuleABI, connectPolicyRuleSize},
		"connect_event":       {connectEventABI, connectEventSize},
	} {
		var st *btf.Struct
		if err := spec.Types.TypeByName(name, &st); err != nil {
			if name == "connect_event" {
				// clang emits BTF only for types reachable from maps, globals
				// and function prototypes; a ring-buffer record is none of
				// them. Its clang evidence is the _Static_asserts.
				t.Logf("BTF struct %s: %v (checked by the _Static_asserts)", name, err)
				continue
			}
			t.Fatalf("BTF struct %s: %v", name, err)
		}
		if st.Size != abi.size {
			t.Errorf("BTF sizeof(%s) = %d, want %d", name, st.Size, abi.size)
		}
		if len(st.Members) != len(abi.fields) {
			t.Fatalf("BTF %s has %d members, the ABI %d", name, len(st.Members), len(abi.fields))
		}
		for i, m := range st.Members {
			want := abi.fields[i]
			size, err := btf.Sizeof(m.Type)
			if err != nil {
				t.Fatal(err)
			}
			if m.Name != want.c || uintptr(m.Offset.Bytes()) != want.offset || uintptr(size) != want.size {
				t.Errorf("BTF %s.%s: offset %d size %d, want %s at %d size %d", name, m.Name, m.Offset.Bytes(), size, want.c, want.offset, want.size)
			}
		}
	}
	rules := spec.Maps["connect_policy_rules"]
	if rules == nil || rules.ValueSize != uint32(unsafe.Sizeof(ConnectPolicyRuleBPF{})) {
		t.Fatalf("connect_policy_rules map value size = %v, want %d", rules, unsafe.Sizeof(ConnectPolicyRuleBPF{}))
	}
}

// Fixtures built byte by byte from the ABI table, in host byte order (map
// values and ring-buffer records are host-order memory).
func ruleFixtureIPv4() []byte {
	b := make([]byte, connectPolicyRuleSize)
	binary.NativeEndian.PutUint32(b[0:], PolicyAllow)
	binary.NativeEndian.PutUint32(b[4:], OpConnect)
	binary.NativeEndian.PutUint32(b[8:], afInet)
	binary.NativeEndian.PutUint32(b[12:], asymmetricIPv4) // canonical a<<24|b<<16|c<<8|d (#74)
	binary.NativeEndian.PutUint16(b[32:], 443)
	return b
}

func ruleFixtureIPv6() []byte {
	b := make([]byte, connectPolicyRuleSize)
	binary.NativeEndian.PutUint32(b[0:], PolicyDeny)
	binary.NativeEndian.PutUint32(b[4:], OpConnect)
	binary.NativeEndian.PutUint32(b[8:], afInet6)
	copy(b[16:32], net.ParseIP("2001:db8::1").To16()) // network byte order
	binary.NativeEndian.PutUint16(b[32:], 22)
	return b
}

// capturePutter records each map Put as the bytes encoding/binary (what
// cilium/ebpf falls back to for structs) produces, and checks that they are
// the in-memory bytes (what cilium/ebpf copies when it can).
type capturePutter struct {
	t    *testing.T
	vals [][]byte
}

func (c *capturePutter) Put(key, value interface{}) error {
	r, ok := value.(*ConnectPolicyRuleBPF)
	if !ok {
		return nil
	}
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.NativeEndian, r); err != nil {
		c.t.Fatal(err)
	}
	mem := unsafe.Slice((*byte)(unsafe.Pointer(r)), unsafe.Sizeof(*r))
	if !bytes.Equal(buf.Bytes(), mem) {
		c.t.Fatalf("binary.Write bytes %x differ from memory %x", buf.Bytes(), mem)
	}
	c.vals = append(c.vals, buf.Bytes())
	return nil
}

type nopPutter struct{}

func (nopPutter) Put(key, value interface{}) error { return nil }

// The connect_policy_rules values written by LoadPolicies + writePolicyMaps
// are the fixtures, byte for byte.
func TestConnectPolicyMapSerializationMatchesFixture(t *testing.T) {
	v4, err := ParseRuleString("allow net.send 192.168.1.1:443")
	if err != nil {
		t.Fatal(err)
	}
	v6, err := ParseRuleString("deny net.send [2001:db8::1]:22")
	if err != nil {
		t.Fatal(err)
	}
	l := &ConnectLsm{}
	deny := false
	if err := l.LoadPolicies(ConvertToConnectRules([]PolicyRule{*v4, *v6}), &deny); err != nil {
		t.Fatal(err)
	}
	rules := &capturePutter{t: t}
	if err := l.writePolicyMaps(func(name string) connectMapPutter {
		if name == "connect_policy_rules" {
			return rules
		}
		return nopPutter{}
	}); err != nil {
		t.Fatal(err)
	}
	// Denies sort first (#135).
	want := [][]byte{ruleFixtureIPv6(), ruleFixtureIPv4()}
	if len(rules.vals) != len(want) {
		t.Fatalf("wrote %d rules, want %d", len(rules.vals), len(want))
	}
	for i := range want {
		if !bytes.Equal(rules.vals[i], want[i]) {
			t.Errorf("rule %d bytes\n got %x\nwant %x", i, rules.vals[i], want[i])
		}
	}
}

// With a kernel: the bytes cilium/ebpf stores in the real map (created from
// the compiled object's spec) are the fixtures. Needs CAP_BPF.
func TestConnectPolicyKernelMapBytes(t *testing.T) {
	spec := connectSpecOrSkip(t)
	m, err := ebpf.NewMap(spec.Maps["connect_policy_rules"].Copy())
	if err != nil {
		if errors.Is(err, os.ErrPermission) || strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("creating a BPF map needs CAP_BPF: %v", err)
		}
		t.Fatal(err)
	}
	defer m.Close()
	for i, tc := range []struct {
		rule ConnectPolicyRuleBPF
		want []byte
	}{
		{connectBPFRuleFor(PolicyAllow, OpConnect, asymmetricIPv4, [16]byte{}, 443), ruleFixtureIPv4()},
		{connectBPFRuleFor(PolicyDeny, OpConnect, 0, ip6Bytes("2001:db8::1"), 22), ruleFixtureIPv6()},
	} {
		key := uint32(i)
		if err := m.Put(key, &tc.rule); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, connectPolicyRuleSize)
		if err := m.Lookup(key, &got); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, tc.want) {
			t.Errorf("kernel map value %d\n got %x\nwant %x", i, got, tc.want)
		}
		var back ConnectPolicyRuleBPF
		if err := m.Lookup(key, &back); err != nil || back != tc.rule {
			t.Errorf("kernel map value %d decodes to %+v (%v), want %+v", i, back, err, tc.rule)
		}
	}
}

// An IPv6 event built byte by byte decodes to its address, port, result and
// hostname; the tail padding is consumed (a 208-byte record).
func TestConnectEventIPv6Fixture(t *testing.T) {
	raw := make([]byte, connectEventSize)
	binary.NativeEndian.PutUint32(raw[0:], 42)
	copy(raw[24:40], "agent")
	binary.NativeEndian.PutUint32(raw[40:], afInet6)
	binary.NativeEndian.PutUint32(raw[44:], 17)
	binary.NativeEndian.PutUint16(raw[52:], 8443)
	binary.NativeEndian.PutUint32(raw[56:], uint32(0xfffffff3)) // -EACCES
	copy(raw[60:], "v6.test")
	copy(raw[188:204], net.ParseIP("2001:db8::1").To16())

	var ev ConnectEvent
	if err := binary.Read(bytes.NewReader(raw), binary.NativeEndian, &ev); err != nil {
		t.Fatal(err)
	}
	if ev.Family != afInet6 || ev.DestPort != 8443 || ev.Result != -13 || safeString(ev.DestHostname[:]) != "v6.test" || net.IP(ev.DestIP6[:]).String() != "2001:db8::1" {
		t.Fatalf("decoded %+v", ev)
	}

	logPath := filepath.Join(t.TempDir(), "events.log")
	logger, err := NewSharedLogger(logPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logger.Close() })
	l, err := NewConnectLsm("/test", logger)
	if err != nil {
		t.Fatal(err)
	}
	l.handleEvent(raw)
	entry, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`protocol=udp`, `addr="[2001:db8::1]:8443"`, `hostname="v6.test"`, `decision=denied`} {
		if !strings.Contains(string(entry), want) {
			t.Errorf("event log %q lacks %s", entry, want)
		}
	}
	// A record one byte short of the C struct is rejected, not misdecoded.
	l.handleEvent(raw[:connectEventSize-1])
	if after, _ := os.ReadFile(logPath); len(after) != len(entry) {
		t.Errorf("a truncated record was logged: %q", after[len(entry):])
	}
}

// A socket_create record (#188) built byte by byte: sock_type (offset 54)
// carries 0x100 | the socket type, and the log names a net.socket decision,
// not a destination.
func TestConnectEventSocketCreateFixture(t *testing.T) {
	raw := make([]byte, connectEventSize)
	binary.NativeEndian.PutUint32(raw[0:], 7)
	copy(raw[24:40], "scapy")
	binary.NativeEndian.PutUint32(raw[40:], 17) // AF_PACKET
	binary.NativeEndian.PutUint32(raw[44:], 0x0300)
	binary.NativeEndian.PutUint16(raw[54:], 0x100|3)            // SOCK_RAW
	binary.NativeEndian.PutUint32(raw[56:], uint32(0xffffffff)) // -EPERM

	logPath := filepath.Join(t.TempDir(), "events.log")
	logger, err := NewSharedLogger(logPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logger.Close() })
	l, err := NewConnectLsm("/test", logger)
	if err != nil {
		t.Fatal(err)
	}
	l.handleEvent(raw)
	entry, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`event=net.socket`, `exe="scapy"`, `family=packet`, `type=raw`, `protocol=768`, `decision=denied`} {
		if !strings.Contains(string(entry), want) {
			t.Errorf("event log %q lacks %s", entry, want)
		}
	}
	if strings.Contains(string(entry), "net.send") {
		t.Errorf("a socket_create record was logged as a send: %q", entry)
	}
}
