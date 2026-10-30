package lsm

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
)

// Connect policy rule structure - must match BPF code
type ConnectPolicyRule struct {
	Action      int32     // 0 = deny, 1 = allow
	Operation   int32     // Always OP_CONNECT (4) for this program
	DestIP      uint32    // Canonical IPv4 value a<<24|b<<16|c<<8|d (0 = any IP)
	DestIP6     [16]byte  // IPv6 address, network byte order (all zero = not an IPv6 rule)
	DestPort    uint16    // Host-order destination port (0 = any port)
	Hostname    [128]byte // Hostname pattern (empty for IP-only rules)
	HostnameLen int32     // Length of hostname for efficient matching
	IsWildcard  int32     // 1 if hostname starts with *.
}

// String returns a human-readable representation of a ConnectPolicyRule
func (rule *ConnectPolicyRule) String() string {
	var parts []string

	// Action
	action := "deny"
	if rule.Action == 1 {
		action = "allow"
	}
	parts = append(parts, fmt.Sprintf("action=%s", action))

	// Operation (should always be OP_CONNECT for this rule type)
	parts = append(parts, fmt.Sprintf("operation=%d", rule.Operation))

	// Destination IP
	if ip := ConnectRuleAddr(rule.DestIP, rule.DestIP6); ip == "" {
		parts = append(parts, "dest_ip=any")
	} else {
		parts = append(parts, fmt.Sprintf("dest_ip=%s", ip))
	}

	// Destination Port
	if rule.DestPort == 0 {
		parts = append(parts, "dest_port=any")
	} else {
		parts = append(parts, fmt.Sprintf("dest_port=%d", rule.DestPort))
	}

	// Hostname
	if rule.HostnameLen > 0 && rule.Hostname[0] != '*' {
		hostname := string(bytes.TrimRight(rule.Hostname[:rule.HostnameLen], "\x00"))
		if rule.IsWildcard == 1 {
			parts = append(parts, fmt.Sprintf("hostname=%s (wildcard)", hostname))
		} else {
			parts = append(parts, fmt.Sprintf("hostname=%s", hostname))
		}
	} else {
		if rule.IsWildcard == 1 {
			// shouldn't happen but for debugging
			parts = append(parts, "hostname=any (wildcard)")
		} else {
			parts = append(parts, "hostname=any")
		}
	}

	return fmt.Sprintf("ConnectPolicyRule{%s}", strings.Join(parts, ", "))
}

// Address families of the connect ABI (linux/socket.h).
const (
	afInet  = 2
	afInet6 = 10
)

// ConnectPolicyRuleBPF is the value of the connect_policy_rules map; it
// matches struct connect_policy_rule in lsm_connect.bpf.c byte for byte
// (36 bytes, every padding byte explicit).
//
// Family selects the address match: 0 matches every destination (IPv4 and
// IPv6), AF_INET compares DestIP, AF_INET6 compares DestIP6. The kernel
// classifies an IPv4-mapped IPv6 destination (::ffff:a.b.c.d) as AF_INET, so
// IPv4 rules govern it. Hostnames never reach the kernel: hostname rules are
// resolved to address rules at load time.
type ConnectPolicyRuleBPF struct {
	Action    uint32   // offset 0: 0 = deny, 1 = allow
	Operation uint32   // offset 4: always OpConnect
	Family    uint32   // offset 8: 0 = any address, AF_INET, AF_INET6
	DestIP    uint32   // offset 12: canonical IPv4 value (Family == AF_INET)
	DestIP6   [16]byte // offset 16: IPv6 address, network byte order (Family == AF_INET6)
	DestPort  uint16   // offset 32: host-order destination port (0 = any port)
	_         [2]byte  // offset 34: explicit padding
}

// ConnectEvent is a connect_events ring-buffer record; it matches struct
// connect_event in lsm_connect.bpf.c byte for byte (208 bytes, every padding
// byte explicit, so binary.Read decodes it field by field).
type ConnectEvent struct {
	PID          uint32    // offset 0
	TGID         uint32    // offset 4
	Timestamp    uint64    // offset 8
	CgroupID     uint64    // offset 16
	Comm         [16]byte  // offset 24
	Family       uint32    // offset 40: AF_INET (including IPv4-mapped IPv6) or AF_INET6
	Protocol     uint32    // offset 44: IPPROTO_TCP, IPPROTO_UDP
	DestIP       uint32    // offset 48: canonical IPv4 value a<<24|b<<16|c<<8|d (AF_INET)
	DestPort     uint16    // offset 52: host-order destination port
	SockType     uint16    // offset 54: 0 for connect/sendmsg; lsm_socket_create: 0x100 | socket type
	Result       int32     // offset 56: 0 = allowed, -EACCES = denied
	DestHostname [128]byte // offset 60: resolved hostname if available
	DestIP6      [16]byte  // offset 188: IPv6 address, network byte order (AF_INET6)
	_            [4]byte   // offset 204: explicit tail padding (8-byte alignment)
}

// connectBPFRuleFor converts one address-or-any connect rule to its map
// value.
func connectBPFRuleFor(action, operation int32, v4 uint32, v6 [16]byte, port uint16) ConnectPolicyRuleBPF {
	r := ConnectPolicyRuleBPF{Action: uint32(action), Operation: uint32(operation), DestPort: port}
	switch {
	case v6 != [16]byte{}:
		r.Family, r.DestIP6 = afInet6, v6
	case v4 != 0:
		r.Family, r.DestIP = afInet, v4
	}
	return r
}

const (
	MaxConnectPolicyRules = 256
	// Note: OpConnect is defined in common.go
)

// lookupConnectHost resolves a hostname rule's A and AAAA records; tests
// substitute a fixed resolver.
var lookupConnectHost = net.LookupIP

type ConnectLsmLoader func() (*ebpf.CollectionSpec, error)

type ConnectLsm struct {
	cgroupPath string
	logger     *SharedLogger

	policyRules         []ConnectPolicyRuleBPF
	numPolicyRules      int
	defaultPolicyResult bool       // Default policy result: false=deny, true=allow
	logMutex            sync.Mutex // Protect concurrent writes to stdout and log file

	// unaddressedAllowed is lsm_socket_create's verdict for packet, raw IP,
	// XDP and SCTP sockets (#188); see unaddressedSocketsAllowed.
	unaddressedAllowed bool
	// proxyRestricted is set by the manager when the policy restricts
	// traffic the L7 proxy enforces (an MCP forbid). A packet socket
	// bypasses the proxy too, so it keeps unaddressed sockets denied.
	proxyRestricted bool

	// DNS cache for hostname resolution
	dnsCache    map[uint32]string // IP -> hostname mapping
	dnsCacheMux sync.RWMutex

	// BPF program state
	ebpfCollection *ebpf.Collection
}

func NewConnectLsm(cgroupPath string, logger *SharedLogger) (*ConnectLsm, error) {
	if cgroupPath == "" {
		return nil, fmt.Errorf("cgroup path is required")
	}

	l := &ConnectLsm{
		cgroupPath: cgroupPath,
		logger:     logger,

		dnsCache:            make(map[uint32]string),
		defaultPolicyResult: false, // Default to deny (false)
	}

	// Note: Policy loading is now done separately via LoadPolicies()
	return l, nil
}

// Interface methods for LSMModule

func (l *ConnectLsm) getCgroupPath() string {
	return l.cgroupPath
}

func (l *ConnectLsm) setEbpfCollection(coll *ebpf.Collection) {
	l.ebpfCollection = coll
}

// LoadPolicies loads connect policy rules into the LSM
func (l *ConnectLsm) LoadPolicies(policies []ConnectPolicyRule, defaultOverride *bool) error {
	// Convert hostname-based rules to IP-based rules so kernel enforces IP+port only
	var expanded []ConnectPolicyRuleBPF
	var skippedWildcard, failedResolves int

	// Reset DNS cache before repopulating
	l.dnsCacheMux.Lock()
	l.dnsCache = make(map[uint32]string)
	l.dnsCacheMux.Unlock()

	allowAny := false
	explicitDefault := defaultOverride != nil
	if explicitDefault {
		l.defaultPolicyResult = *defaultOverride
	} else {
		l.defaultPolicyResult = false
	}
	for _, rule := range policies {
		// If rule already has an IP (IPv4 or IPv6), keep as-is
		if rule.DestIP != 0 || rule.DestIP6 != ([16]byte{}) {
			expanded = append(expanded, connectBPFRuleFor(rule.Action, rule.Operation, rule.DestIP, rule.DestIP6, rule.DestPort))
			continue
		}

		// Hostname-based rule
		if rule.HostnameLen == 0 {
			// No IP and no hostname means "any" (IPv4 and IPv6); keep as-is
			expanded = append(expanded, connectBPFRuleFor(rule.Action, rule.Operation, 0, [16]byte{}, rule.DestPort))
			continue
		}

		// Skip wildcards in kernel; enforce via userspace proxy
		if rule.IsWildcard == 1 {
			skippedWildcard++
			continue
		}

		hostname := string(bytes.TrimRight(rule.Hostname[:], "\x00"))
		// Special case: "*" means allow any destination via default allow policy
		if hostname == "*" && rule.Action == PolicyAllow {
			if !explicitDefault {
				allowAny = true
			}
			continue
		}
		// forbid Host::"*" is the explicit default deny (applyConnectDefaults
		// sets the override), not a rule to resolve.
		if isConnectDefault(rule.DestIP, rule.DestPort, rule.Hostname[:], rule.HostnameLen) {
			continue
		}
		ips, err := lookupHostIPs(hostname)
		if err != nil {
			failedResolves++
			continue
		}

		// Create an address rule for each resolved A and AAAA record, so a
		// hostname rule covers the name over IPv4 and IPv6 alike.
		for _, ip := range ips {
			if ipNum, ok := canonicalIPv4(ip); ok {
				expanded = append(expanded, connectBPFRuleFor(rule.Action, rule.Operation, ipNum, [16]byte{}, rule.DestPort))

				// Populate DNS cache for logging/BPF map
				l.dnsCacheMux.Lock()
				l.dnsCache[ipNum] = hostname
				l.dnsCacheMux.Unlock()
				continue
			}
			ip16 := ip.To16()
			if ip16 == nil || ip16.IsUnspecified() {
				continue
			}
			var v6 [16]byte
			copy(v6[:], ip16)
			expanded = append(expanded, connectBPFRuleFor(rule.Action, rule.Operation, 0, v6, rule.DestPort))
		}
	}

	l.policyRules = expanded
	l.numPolicyRules = len(expanded)

	// The BPF scan takes the first match: every deny goes first so a matching
	// forbid always wins (#135), then by port and IP for a stable order.
	sortConnectBPFRulesByPrecedence(l.policyRules)

	if !explicitDefault {
		// Check if root path "/" is allowed to set default policy result
		l.checkRootConnectPolicy()

		// If we saw "allow net.send *", set default allow in the kernel
		if allowAny {
			l.defaultPolicyResult = true
		}
	}

	l.unaddressedAllowed = unaddressedSocketsAllowed(policies, l.defaultPolicyResult, l.proxyRestricted)

	fmt.Printf("Loaded %d connect IP rules (skipped %d wildcard, %d unresolved)\n", l.numPolicyRules, skippedWildcard, failedResolves)
	if explicitDefault {
		if l.defaultPolicyResult {
			fmt.Printf("Default connect policy result: ALLOW (configured override)\n")
		} else {
			fmt.Printf("Default connect policy result: DENY (configured override)\n")
		}
	} else {
		if l.defaultPolicyResult {
			fmt.Printf("Default connect policy result: ALLOW (wildcard '*' is allowed)\n")
		} else {
			fmt.Printf("Default connect policy result: DENY (no wildcard rule found)\n")
		}
	}

	if l.unaddressedAllowed {
		fmt.Printf("Packet/raw/SCTP sockets: ALLOWED (the policy restricts no destination)\n")
	} else {
		fmt.Printf("Packet/raw/SCTP sockets: DENIED (the policy restricts egress; no address rule can govern them)\n")
	}

	// If eBPF collection is already loaded, update the BPF maps
	if l.ebpfCollection != nil {
		if err := l.loadPolicyIntoBPF(l.ebpfCollection); err != nil {
			return fmt.Errorf("failed to update BPF maps: %w", err)
		}

		// Also update the DNS cache in BPF
		if err := l.updateDNSCacheInBPF(l.ebpfCollection); err != nil {
			fmt.Printf("Warning: failed to update DNS cache in BPF: %v\n", err)
		}

		fmt.Printf("Updated BPF maps with new connect policies\n")
	}

	return nil
}

// unaddressedSocketsAllowed decides whether the workload may create the
// sockets whose traffic no address hook sees (#188): AF_PACKET and AF_XDP
// sockets, SOCK_RAW on AF_INET/AF_INET6, and SCTP. A packet or IP_HDRINCL
// raw socket bound with bind() sends with send() and no address; SCTP adds
// peers through sctp_connectx(), the sendmsg SCTP_DSTADDRV4/V6 list and the
// peer's own address list, none of which pass socket_connect. No connect rule
// can name such traffic, so these sockets are allowed only when the policy
// restricts nothing they could bypass: the connect default is allow, there is
// no deny connect rule of any kind (address, port, hostname or wildcard),
// and the proxy enforces no forbid (proxyRestricted). Every other policy
// denies them: under a default-deny policy (the usual case) and under a
// default-allow policy with a forbid alike, since a raw socket could reach
// the forbidden host.
func unaddressedSocketsAllowed(rules []ConnectPolicyRule, defaultAllow, proxyRestricted bool) bool {
	if !defaultAllow || proxyRestricted {
		return false
	}
	for _, r := range rules {
		if r.Action != PolicyAllow {
			return false
		}
	}
	return true
}

// checkRootConnectPolicy checks if there's a wildcard rule that allows all connections
func (l *ConnectLsm) checkRootConnectPolicy() {
	// Default is false (deny)
	l.defaultPolicyResult = false

	// For connect policies, we consider a rule that allows all IPs/hostnames as permissive
	for _, rule := range l.policyRules {
		if rule.Action == PolicyAllow && rule.Family == 0 {
			l.defaultPolicyResult = true
			break
		}
	}
}

func (l *ConnectLsm) LoadAndAttach(loader func() (*ebpf.CollectionSpec, error)) error {
	config := BPFConfig{
		ProgramNames:      []string{"lsm_connect", "lsm_sendmsg", "lsm_socket_create"},
		EventMapName:      "connect_events",
		AuditLogger:       l.logger,
		AllowedCgroupsMap: "connect_allowed_cgroups",
		TargetCgroupMap:   "connect_target_cgroup",
		StartMessage:      "Successfully started monitoring network connections and sendmsg operations",
		ShutdownMessage:   "Shutting down connect LSM tracker",
	}

	// Custom setup for DNS cache
	customSetup := func(coll *ebpf.Collection) error {
		// Load DNS cache into BPF maps
		if err := l.updateDNSCacheInBPF(coll); err != nil {
			fmt.Printf("Warning: failed to load DNS cache into BPF: %v\n", err)
		}
		return nil
	}

	return LoadAndAttachBPFWithSetup(l, loader, config, customSetup)
}

// connectMapPutter is the one map operation loadPolicyIntoBPF needs; an
// *ebpf.Map satisfies it, and tests substitute an in-memory model.
type connectMapPutter interface {
	Put(key, value interface{}) error
}

func (l *ConnectLsm) loadPolicyIntoBPF(coll *ebpf.Collection) error {
	return l.writePolicyMaps(func(name string) connectMapPutter {
		if m := coll.Maps[name]; m != nil {
			return m
		}
		return nil
	})
}

// writePolicyMaps pushes the current policy into the connect maps. The rule
// count is ALWAYS written — including zero — so a reload that drops to no
// connect rules (or whose hostnames all fail to resolve) retires the
// previously loaded kernel rules instead of leaving them live (#118 review).
// Rules are written before the count so a growing set never exposes
// unwritten slots; entries beyond the count are ignored by the program.
func (l *ConnectLsm) writePolicyMaps(lookup func(string) connectMapPutter) error {
	get := func(name string) (connectMapPutter, error) {
		m := lookup(name)
		if m == nil {
			return nil, fmt.Errorf("BPF map %s not found", name)
		}
		return m, nil
	}

	key := uint32(0)
	defaultResult := uint32(0) // Default to deny
	if l.defaultPolicyResult {
		defaultResult = uint32(1) // Allow
	}
	defMap, err := get("connect_default_policy")
	if err != nil {
		return err
	}
	if err := defMap.Put(&key, &defaultResult); err != nil {
		return fmt.Errorf("failed to update connect_default_policy map: %w", err)
	}

	unaddressed := uint32(0)
	if l.unaddressedAllowed {
		unaddressed = 1
	}
	unaddrMap, err := get("connect_unaddressed_policy")
	if err != nil {
		return err
	}
	if err := unaddrMap.Put(&key, &unaddressed); err != nil {
		return fmt.Errorf("failed to update connect_unaddressed_policy map: %w", err)
	}

	numMap, err := get("connect_num_rules")
	if err != nil {
		return err
	}

	if l.numPolicyRules > 0 {
		rulesMap, err := get("connect_policy_rules")
		if err != nil {
			return err
		}
		fmt.Printf("Loading %d connect policy rules into BPF maps...\n", l.numPolicyRules)
		for i := 0; i < l.numPolicyRules; i++ {
			if err := rulesMap.Put(uint32(i), &l.policyRules[i]); err != nil {
				return fmt.Errorf("failed to update connect_policy_rules map for rule %d: %w", i, err)
			}
		}
	} else {
		fmt.Printf("No connect policy rules to load, using default policy result: %v\n", l.defaultPolicyResult)
	}

	numRules := int32(l.numPolicyRules)
	if err := numMap.Put(&key, &numRules); err != nil {
		return fmt.Errorf("failed to update connect_num_rules map: %w", err)
	}
	return nil
}

// validateConnectEvent checks if the event data is properly formed
func validateConnectEvent(event *ConnectEvent) bool {
	return validateEventArrays(event.Comm[:], event.DestHostname[:])
}

func (l *ConnectLsm) handleEvent(data []byte) {
	if len(data) < int(unsafe.Sizeof(ConnectEvent{})) {
		fmt.Fprintf(os.Stderr, "Error: received incomplete connect event\n")
		return
	}

	// Ring-buffer records are in the kernel's (host) byte order.
	var event ConnectEvent
	reader := bytes.NewReader(data)
	if err := binary.Read(reader, binary.NativeEndian, &event); err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to parse connect event: %v\n", err)
		return
	}

	// Validate event data to prevent corruption
	if !validateConnectEvent(&event) {
		fmt.Fprintf(os.Stderr, "Error: received corrupted connect event data\n")
		return
	}

	// Extract strings from byte arrays with safe conversion
	comm := safeString(event.Comm[:])
	hostname := safeString(event.DestHostname[:])

	// Additional validation
	if len(comm) == 0 {
		fmt.Fprintf(os.Stderr, "Error: received connect event with empty comm\n")
		return
	}

	if event.SockType != 0 {
		l.logSocketCreate(&event, comm)
		return
	}

	destIP := canonicalIPv4String(event.DestIP)
	if event.Family == afInet6 {
		destIP = net.IP(event.DestIP6[:]).String()
	}
	destPort := event.DestPort

	// Use current time for ISO 8601 format (BPF timestamp is kernel boot time, not Unix time)
	timestamp := time.Now().Format(time.RFC3339)

	// Format result string
	resultStr := "allowed"
	if event.Result != 0 {
		resultStr = "denied"
	}

	// Determine protocol string
	protocolStr := "unknown"
	switch event.Protocol {
	case 6: // IPPROTO_TCP
		protocolStr = "tcp"
	case 17: // IPPROTO_UDP
		protocolStr = "udp"
	}

	// Create destination string
	destStr := JoinConnectTarget(destIP, destPort)
	if event.Family != afInet && event.Family != afInet6 && event.Family != 0 {
		// A non-IP socket family (packet, vsock, ...) decided by the connect
		// default: there is no address to show.
		destStr = fmt.Sprintf("family=%d", event.Family)
	}

	// Add hostname if available
	hostnameStr := ""
	if len(hostname) > 0 {
		hostnameStr = fmt.Sprintf(" hostname=\"%s\"", hostname)
	}

	// Format in logfmt (key=value pairs)
	logEntry := fmt.Sprintf("time=%s event=net.send pid=%d cgroup=%d exe=\"%s\" protocol=%s addr=\"%s\"%s decision=%s",
		timestamp, event.PID, event.CgroupID, comm, protocolStr, destStr, hostnameStr, resultStr)

	// Protect concurrent writes with mutex
	l.logMutex.Lock()
	defer l.logMutex.Unlock()

	// Write to shared logger if configured
	if l.logger != nil {
		_ = l.logger.Write(logEntry)
	}

	// Unique connect logging removed

	// Update DNS cache if hostname is provided
	if len(hostname) > 0 && event.Family != afInet6 {
		l.dnsCacheMux.Lock()
		l.dnsCache[event.DestIP] = hostname
		l.dnsCacheMux.Unlock()
	}
}

// Socket type names for net.socket events (linux/net.h).
var sockTypeNames = map[uint16]string{1: "stream", 2: "dgram", 3: "raw", 4: "rdm", 5: "seqpacket", 10: "packet"}

// Socket family names for net.socket events (linux/socket.h).
var sockFamilyNames = map[uint32]string{afInet: "inet", afInet6: "inet6", 17: "packet", 44: "xdp"}

// logSocketCreate logs one lsm_socket_create decision (#188): a packet, raw
// IP, XDP or SCTP socket the workload tried to create.
func (l *ConnectLsm) logSocketCreate(event *ConnectEvent, comm string) {
	family := sockFamilyNames[event.Family]
	if family == "" {
		family = fmt.Sprintf("%d", event.Family)
	}
	typ := sockTypeNames[event.SockType&0xff]
	if typ == "" {
		typ = fmt.Sprintf("%d", event.SockType&0xff)
	}
	resultStr := "allowed"
	if event.Result != 0 {
		resultStr = "denied"
	}
	logEntry := fmt.Sprintf("time=%s event=net.socket pid=%d cgroup=%d exe=\"%s\" family=%s type=%s protocol=%d decision=%s",
		time.Now().Format(time.RFC3339), event.PID, event.CgroupID, comm, family, typ, event.Protocol, resultStr)
	l.logMutex.Lock()
	defer l.logMutex.Unlock()
	if l.logger != nil {
		_ = l.logger.Write(logEntry)
	}
}

// UpdateDNSCache allows external components (like DNS monitoring) to update the hostname cache
func (l *ConnectLsm) UpdateDNSCache(ip uint32, hostname string) {
	l.dnsCacheMux.Lock()
	defer l.dnsCacheMux.Unlock()
	l.dnsCache[ip] = hostname
}

// GetDNSCache returns the current DNS cache for integration with BPF maps
func (l *ConnectLsm) GetDNSCache() map[uint32]string {
	l.dnsCacheMux.RLock()
	defer l.dnsCacheMux.RUnlock()

	cache := make(map[uint32]string)
	for ip, hostname := range l.dnsCache {
		cache[ip] = hostname
	}
	return cache
}

// updateDNSCacheInBPF updates the BPF DNS cache map with current hostname mappings
func (l *ConnectLsm) updateDNSCacheInBPF(coll *ebpf.Collection) error {
	dnsMap := coll.Maps["dns_cache"]
	if dnsMap == nil {
		return fmt.Errorf("dns_cache map not found")
	}

	l.dnsCacheMux.RLock()
	defer l.dnsCacheMux.RUnlock()

	// Clear existing cache entries first
	// Note: We could iterate and delete, but for simplicity, we'll just overwrite

	updatedCount := 0
	for ip, hostname := range l.dnsCache {
		var hostnameBytes [128]byte
		copy(hostnameBytes[:], hostname)

		if err := dnsMap.Put(&ip, &hostnameBytes); err != nil {
			fmt.Printf("Warning: failed to update DNS cache for %s (%d): %v\n", hostname, ip, err)
			continue
		}
		updatedCount++
	}

	if updatedCount > 0 {
		fmt.Printf("Updated %d DNS cache entries in BPF map\n", updatedCount)
	}

	return nil
}
