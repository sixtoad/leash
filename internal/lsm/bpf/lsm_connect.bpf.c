// SPDX-License-Identifier: GPL-2.0

// Define basic types first
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed char __s8;
typedef short __s16;
typedef int __s32;
typedef long long __s64;

// Define network types
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __wsum;

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

// Define missing types
typedef int bool;
#define true 1
#define false 0

// BPF map types
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_RINGBUF 27
#define BPF_ANY 0

char LICENSE[] SEC("license") = "GPL";

#define MAX_HOSTNAME_LEN 128
#define MAX_ENTRIES 8192
// BPF verifier-friendly constant bound for policy rules (max 256 with loop-based implementation)
#define MAX_POLICY_RULES 256

// Operation types (must match Go constants)
#define OP_CONNECT 4    // connect

// TCP socket states
#define TCP_ESTABLISHED 1

// Ring-buffer record of one connect/sendmsg decision. Every padding byte is
// an explicit field: Go decodes it with binary.Read, which adds no implicit
// padding (ConnectEvent in net_connect.go).
struct connect_event {
    u32 pid;
    u32 tgid;
    u64 timestamp;
    u64 cgroup_id;
    char comm[16];         // Task command name
    u32 family;            // AF_INET (also IPv4-mapped IPv6), AF_INET6, or the socket's family
    u32 protocol;          // IPPROTO_TCP, IPPROTO_UDP
    u32 dest_ip;           // Canonical IPv4 value (a<<24 | b<<16 | c<<8 | d), AF_INET
    u16 dest_port;         // Host-order destination port
    u16 _pad0;             // Explicit padding
    s32 result;            // Result of the connect operation (0 = allowed, -EACCES = denied)
    char dest_hostname[MAX_HOSTNAME_LEN]; // Resolved hostname if available
    u32 dest_ip6[4];       // IPv6 address, network byte order, AF_INET6
    u32 _pad1;             // Explicit tail padding (8-byte struct alignment)
};

// Policy rule structure for BPF map (ConnectPolicyRuleBPF in Go). family
// selects the address match: 0 = any destination (IPv4 and IPv6), AF_INET
// compares dest_ip, AF_INET6 compares dest_ip6. Hostname rules are resolved
// to address rules in userspace; the kernel never matches names.
struct connect_policy_rule {
    u32 action;            // 0 = deny, 1 = allow
    u32 operation;         // Always OP_CONNECT for this program
    u32 family;            // 0 = any address, AF_INET, AF_INET6
    u32 dest_ip;           // Canonical IPv4 value (family == AF_INET)
    u32 dest_ip6[4];       // IPv6 address, network byte order (family == AF_INET6)
    u16 dest_port;         // Host-order destination port (0 = any port)
    u16 _pad0;             // Explicit padding
};

// A destination classified for policy: an IPv4-mapped IPv6 address
// (::ffff:a.b.c.d) is AF_INET, so IPv4 rules govern it.
struct connect_dest {
    u32 family;            // AF_INET or AF_INET6
    u32 ip;                // Canonical IPv4 value (AF_INET)
    u32 ip6[4];            // IPv6 address, network byte order (AF_INET6)
    u16 port;              // Host-order port
};

// UAPI struct sockaddr_in6 up to sin6_addr (SIN6_LEN_RFC2133 = 24 bytes, the
// minimum length the IPv6 protocols accept). Declared here, not in
// vmlinux.h, so it is a plain fixed layout without CO-RE relocations.
struct leash_sockaddr_in6 {
    u16 sin6_family;
    u16 sin6_port;         // Network byte order
    u32 sin6_flowinfo;
    u32 sin6_addr[4];      // Network byte order
};

// Guard the Go/BPF ABI used by policy maps and ring-buffer events.
_Static_assert(__builtin_offsetof(struct connect_event, dest_ip) == 48, "connect_event.dest_ip ABI drift");
_Static_assert(__builtin_offsetof(struct connect_event, dest_port) == 52, "connect_event.dest_port ABI drift");
_Static_assert(__builtin_offsetof(struct connect_event, result) == 56, "connect_event.result ABI drift");
_Static_assert(__builtin_offsetof(struct connect_event, dest_hostname) == 60, "connect_event.dest_hostname ABI drift");
_Static_assert(__builtin_offsetof(struct connect_event, dest_ip6) == 188, "connect_event.dest_ip6 ABI drift");
_Static_assert(sizeof(struct connect_event) == 208, "connect_event size ABI drift");
_Static_assert(__builtin_offsetof(struct connect_policy_rule, family) == 8, "connect_policy_rule.family ABI drift");
_Static_assert(__builtin_offsetof(struct connect_policy_rule, dest_ip) == 12, "connect_policy_rule.dest_ip ABI drift");
_Static_assert(__builtin_offsetof(struct connect_policy_rule, dest_ip6) == 16, "connect_policy_rule.dest_ip6 ABI drift");
_Static_assert(__builtin_offsetof(struct connect_policy_rule, dest_port) == 32, "connect_policy_rule.dest_port ABI drift");
_Static_assert(sizeof(struct connect_policy_rule) == 36, "connect_policy_rule size ABI drift");
_Static_assert(sizeof(struct leash_sockaddr_in6) == 24, "sockaddr_in6 prefix layout");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} connect_events SEC(".maps");

// Map to store the target cgroup ID for filtering (root of subtree to monitor)
// [0] = box cgroup id (0 = monitoring off), [1] = box depth from the cgroup root.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, u32);
    __type(value, u64);
} connect_target_cgroup SEC(".maps");

// Map to store multiple cgroup IDs to monitor (for descendants)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, u8);
} connect_allowed_cgroups SEC(".maps");

// Map to store policy rules (indexed by rule number, supports up to 256 rules)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_POLICY_RULES);
    __type(key, u32);
    __type(value, struct connect_policy_rule);
} connect_policy_rules SEC(".maps");

// Map to store the number of policy rules
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, s32);
} connect_num_rules SEC(".maps");

// Map to store default policy result (0 = deny, 1 = allow)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} connect_default_policy SEC(".maps");

// DNS hostname cache: IP -> hostname mapping
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u32);   // IPv4 address
    __type(value, char[MAX_HOSTNAME_LEN]); // Hostname
} dns_cache SEC(".maps");

// Helper to check if current cgroup should be monitored
static __always_inline bool is_connect_target_cgroup(void)
{
    u64 current_cgroup_id = bpf_get_current_cgroup_id();
    
    // Check if monitoring is enabled
    u32 key = 0;
    u64 *target_ptr = bpf_map_lookup_elem(&connect_target_cgroup, &key);
    if (!target_ptr || *target_ptr == 0) {
        return false;
    }
    
    // Check if current cgroup is in the allowed set
    u8 *allowed = bpf_map_lookup_elem(&connect_allowed_cgroups, &current_cgroup_id);
    if (allowed != NULL) {
        return true;
    }

    // Hierarchy check: cover sub-cgroups created after the attach-time snapshot
    // (see lsm_open.bpf.c). [1] = box depth; ancestor at that depth == box id
    // ([0]) iff current is under the box.
    u32 level_key = 1;
    u64 *box_level = bpf_map_lookup_elem(&connect_target_cgroup, &level_key);
    if (box_level && bpf_get_current_ancestor_cgroup_id((int)*box_level) == *target_ptr) {
        return true;
    }

    return false;
}

// Helper function for simple string prefix matching (BPF verifier friendly)
static __always_inline bool hostname_starts_with(const char *hostname, const char *prefix, u32 prefix_len)
{
    if (prefix_len == 0) return true;
    
    #pragma clang loop unroll(disable)
    for (u32 i = 0; i < MAX_HOSTNAME_LEN && i < prefix_len; i++) {
        if (hostname[i] != prefix[i]) {
            return false;
        }
        if (hostname[i] == '\0') {
            // hostname is shorter than prefix
            return false;
        }
    }
    return true;
}

// Helper function for wildcard hostname matching (*.example.com)
static __always_inline bool hostname_matches_wildcard(const char *hostname, const char *pattern, u32 pattern_len)
{
    if (pattern_len < 3) return false; // At least "*.x"
    if (pattern[0] != '*' || pattern[1] != '.') return false;
    
    // Extract the suffix (remove "*.")
    const char *suffix = pattern + 2;
    u32 suffix_len = pattern_len - 2;
    
    // Find the hostname length
    u32 hostname_len = 0;
    #pragma clang loop unroll(disable)
    for (u32 i = 0; i < MAX_HOSTNAME_LEN; i++) {
        if (hostname[i] == '\0') {
            hostname_len = i;
            break;
        }
    }
    
    if (hostname_len < suffix_len) return false;
    
    // Check if hostname ends with the suffix
    u32 start_pos = hostname_len - suffix_len;
    #pragma clang loop unroll(disable)
    for (u32 i = 0; i < suffix_len && i < MAX_HOSTNAME_LEN; i++) {
        if (hostname[start_pos + i] != suffix[i]) {
            return false;
        }
    }
    
    // Ensure there's a subdomain (hostname is longer than suffix or has a dot before suffix)
    if (hostname_len == suffix_len) {
        return false; // Exact match, not a subdomain
    }
    if (start_pos > 0 && hostname[start_pos - 1] != '.') {
        return false; // Not a proper subdomain boundary
    }
    
    return true;
}

static __always_inline int connect_default_verdict(void)
{
    u32 key = 0;
    u32 *default_ptr = bpf_map_lookup_elem(&connect_default_policy, &key);
    return default_ptr ? *default_ptr : 0; // Default to deny
}

// Check connect policy for a classified destination (hostnames are resolved
// to address rules in userspace).
static __always_inline int check_connect_policy(const struct connect_dest *d)
{
    u32 key = 0;
    s32 *num_rules_ptr = bpf_map_lookup_elem(&connect_num_rules, &key);
    if (!num_rules_ptr) {
        return 0; // Default to deny if no rules loaded
    }

    s32 num_rules = *num_rules_ptr;
    if (num_rules <= 0) {
        return connect_default_verdict();
    }

    // Check each policy rule (rules are sorted by specificity in userspace)
    #pragma clang loop unroll(disable)
    for (u32 i = 0; i < MAX_POLICY_RULES; i++) {
        if (i >= (u32)num_rules) break;
        u32 rule_key = i;
        struct connect_policy_rule *rule = bpf_map_lookup_elem(&connect_policy_rules, &rule_key);
        if (!rule) continue;

        // Address match (family 0 = any destination, IPv4 or IPv6)
        if (rule->family != 0) {
            if (rule->family != d->family) {
                continue;
            }
            if (d->family == AF_INET) {
                if (rule->dest_ip != d->ip) {
                    continue;
                }
            } else if (rule->dest_ip6[0] != d->ip6[0] || rule->dest_ip6[1] != d->ip6[1] ||
                       rule->dest_ip6[2] != d->ip6[2] || rule->dest_ip6[3] != d->ip6[3]) {
                continue;
            }
        }

        // Check port match (0 means any port)
        if (rule->dest_port != 0 && rule->dest_port != d->port) {
            continue;
        }

        // Rule matches
        return rule->action;
    }

    // No matching rule found, use default policy
    return connect_default_verdict();
}

// Outcome of classifying a connect/sendmsg address.
#define DEST_ALLOW   0  // not network egress (AF_UNIX, AF_NETLINK, connect(AF_UNSPEC))
#define DEST_ADDR    1  // an IPv4/IPv6 destination: check the rules
#define DEST_DEFAULT 2  // another family: no rule can name it, the default verdict applies
#define DEST_DENY    3  // the address could not be read: fail closed

// Read an AF_INET or AF_INET6 sockaddr (a KERNEL pointer: the LSM hooks run
// after the address was copied in) into d.
static __always_inline int read_inet_dest(const void *addr, u16 family, struct connect_dest *d)
{
    if (family == AF_INET) {
        struct sockaddr_in a4 = {};
        if (bpf_probe_read_kernel(&a4, sizeof(a4), addr) != 0) {
            return DEST_DENY;
        }
        // sockaddr_in stores both fields in network byte order. Convert once
        // at ingress so policy maps, DNS keys, and events all use canonical
        // values.
        d->family = AF_INET;
        d->ip = bpf_ntohl(a4.sin_addr.s_addr);
        d->port = bpf_ntohs(a4.sin_port);
        return DEST_ADDR;
    }
    struct leash_sockaddr_in6 a6 = {};
    if (bpf_probe_read_kernel(&a6, sizeof(a6), addr) != 0) {
        return DEST_DENY;
    }
    d->port = bpf_ntohs(a6.sin6_port);
    if (a6.sin6_addr[0] == 0 && a6.sin6_addr[1] == 0 && a6.sin6_addr[2] == bpf_htonl(0x0000ffff)) {
        // IPv4-mapped (::ffff:a.b.c.d) on a dual-stack socket: the packet is
        // IPv4, so the IPv4 rules decide.
        d->family = AF_INET;
        d->ip = bpf_ntohl(a6.sin6_addr[3]);
        return DEST_ADDR;
    }
    d->family = AF_INET6;
    d->ip6[0] = a6.sin6_addr[0];
    d->ip6[1] = a6.sin6_addr[1];
    d->ip6[2] = a6.sin6_addr[2];
    d->ip6[3] = a6.sin6_addr[3];
    return DEST_ADDR;
}

// Classify the destination of connect(2) (is_send = 0) or of a sendmsg with
// an explicit address (is_send = 1). The socket's family decides first,
// because protocols do not all check the address family: packet sockets
// ignore it, IPv4 UDP/raw sendmsg treat AF_UNSPEC as AF_INET, and IPv6 raw
// sendmsg treats AF_UNSPEC as AF_INET6.
static __always_inline int classify_dest(struct socket *sock, const void *addr, int is_send, struct connect_dest *d, u16 *family_out)
{
    u16 family = 0;
    if (bpf_probe_read_kernel(&family, sizeof(family), addr) != 0) {
        return DEST_DENY;
    }
    u16 sk_family = BPF_CORE_READ(sock, sk, __sk_common.skc_family);
    *family_out = sk_family;
    if (sk_family != AF_INET && sk_family != AF_INET6) {
        if (sk_family == AF_UNIX || sk_family == AF_NETLINK) {
            return DEST_ALLOW; // local IPC, not network egress
        }
        return DEST_DEFAULT; // AF_PACKET, AF_VSOCK, ...: no rule names them
    }
    if (family == AF_UNSPEC) {
        if (!is_send) {
            return DEST_ALLOW; // connect(AF_UNSPEC) dissolves the association
        }
        family = sk_family;
    }
    if (family != AF_INET && family != AF_INET6) {
        return DEST_DEFAULT; // rejected by the protocol; never allow by omission
    }
    *family_out = family;
    return read_inet_dest(addr, family, d);
}

// Helper function to process network events and apply policy (shared between hooks)
static __always_inline int process_network_event(struct socket *sock, const struct connect_dest *d, u16 family, int kind)
{
    struct connect_event *event;
    int policy_result = 0;
    char hostname[MAX_HOSTNAME_LEN] = {0};

    if (kind == DEST_ADDR) {
        // Try to lookup hostname from DNS cache (IPv4 keys only)
        if (d->family == AF_INET) {
            u32 ip_key = d->ip;
            char *cached_hostname = bpf_map_lookup_elem(&dns_cache, &ip_key);
            if (cached_hostname) {
                // Copy cached hostname
                #pragma clang loop unroll(disable)
                for (int i = 0; i < MAX_HOSTNAME_LEN - 1; i++) {
                    hostname[i] = cached_hostname[i];
                    if (cached_hostname[i] == '\0') break;
                }
                hostname[MAX_HOSTNAME_LEN - 1] = '\0';
            }
        }
        // Check policy for this destination (hostname ignored for enforcement)
        policy_result = check_connect_policy(d);
    } else {
        policy_result = connect_default_verdict();
    }

    // Reserve ringbuf space for event logging
    event = bpf_ringbuf_reserve(&connect_events, sizeof(*event), 0);
    if (!event) {
        // Still need to enforce policy even if we can't log
        return policy_result ? 0 : -13; // -EACCES = 13
    }

    // Ring buffer memory is not zeroed: clear padding and the unused
    // hostname tail so no stale bytes reach userspace.
    __builtin_memset(event, 0, sizeof(*event));

    // Get process information
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid >> 32;
    event->tgid = pid_tgid & 0xFFFFFFFF;
    event->timestamp = bpf_ktime_get_ns();
    event->cgroup_id = bpf_get_current_cgroup_id();

    // Get process command name
    bpf_get_current_comm(event->comm, sizeof(event->comm));

    // Set network details
    event->family = kind == DEST_ADDR ? d->family : family;
    event->protocol = BPF_CORE_READ(sock, sk, sk_protocol);
    event->dest_ip = d->ip;
    event->dest_ip6[0] = d->ip6[0];
    event->dest_ip6[1] = d->ip6[1];
    event->dest_ip6[2] = d->ip6[2];
    event->dest_ip6[3] = d->ip6[3];
    event->dest_port = d->port;

    // Copy hostname if available
    #pragma clang loop unroll(disable)
    for (int i = 0; i < MAX_HOSTNAME_LEN; i++) {
        event->dest_hostname[i] = hostname[i];
        if (hostname[i] == '\0') break;
    }

    // Set result based on policy
    event->result = policy_result ? 0 : -13; // 0 = allowed, -EACCES = denied

    bpf_ringbuf_submit(event, 0);

    // Return policy decision: 0 = allow, negative = deny
    return policy_result ? 0 : -13; // -EACCES = 13
}

// Decide one destination address (shared by both hooks).
static __always_inline int decide_destination(struct socket *sock, const void *addr, int is_send)
{
    struct connect_dest d = {};
    u16 family = 0;
    int kind = classify_dest(sock, addr, is_send, &d, &family);
    if (kind == DEST_ALLOW) {
        return 0;
    }
    if (kind == DEST_DENY) {
        return -13; // -EACCES: an unreadable address is never allowed
    }
    return process_network_event(sock, &d, family, kind);
}

SEC("lsm/socket_connect")
int BPF_PROG(lsm_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
    // Check if we should monitor this cgroup
    if (!is_connect_target_cgroup()) {
        return 0;
    }

    // security_socket_connect() runs after move_addr_to_kernel(), so address
    // is a KERNEL pointer: a user read fails.
    return decide_destination(sock, address, 0);
}

SEC("lsm/socket_sendmsg")
int BPF_PROG(lsm_sendmsg, struct socket *sock, void *msg, int size)
{
    // Check if we should monitor this cgroup
    if (!is_connect_target_cgroup()) {
        return 0;
    }

    // Handle both connectionless sockets (UDP, raw) and any sends with explicit
    // destinations (including TCP Fast Open's sendto(MSG_FASTOPEN)).
    void *msg_name = NULL;

    // Read msg_name (the first field of struct msghdr)
    if (bpf_probe_read_kernel(&msg_name, sizeof(msg_name), msg) != 0) {
        return -13; // -EACCES: fail closed
    }

    // No destination address: send()/write() on a connected socket. Its peer
    // was checked by lsm_connect when connect(2) set it, so allow here.
    if (!msg_name) {
        return 0;
    }

    // msg_name is the kernel copy of the address (not a user pointer)
    return decide_destination(sock, msg_name, 1);
}
