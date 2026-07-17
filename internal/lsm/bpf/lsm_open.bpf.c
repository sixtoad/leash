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

// Define missing types
typedef int bool;
#define true 1
#define false 0

// BPF map types
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_RINGBUF 27
#define BPF_MAP_TYPE_PERCPU_ARRAY 6
#define BPF_ANY 0

char LICENSE[] SEC("license") = "GPL";

#define MAX_PATH_LEN 256
#define MAX_ENTRIES 8192
// BPF verifier-friendly constant bound for policy rules (max 256 with loop-based implementation)
#define MAX_POLICY_RULES 256

// Operation types (must match Go constants)
#define OP_OPEN 0    // open (any mode)
#define OP_OPEN_RO 1 // open:ro (read-only)
#define OP_OPEN_RW 2 // open:rw (any write mode)

struct open_event {
    u32 pid;
    u32 tgid;
    u64 timestamp;
    u64 cgroup_id;
    char comm[16];  // Task command name
    char path[MAX_PATH_LEN];
    u32 operation;  // OP_OPEN, OP_OPEN_RO, OP_OPEN_RW
    s32 result;     // Result of the open operation (0 = allowed, -EACCES = denied)
};

// Policy rule structure for BPF map
struct policy_rule {
    u32 action;      // 0 = deny, 1 = allow
    u32 operation;   // 0 = open, 1 = open:ro, 2 = open:rw
    u32 path_len;
    char path[MAX_PATH_LEN];
    u32 is_directory; // 1 if path ends with /
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Box cgroup descriptor: [0] = box cgroup id (0 = monitoring off), [1] = box
// depth from the cgroup root (for the hierarchy check in is_target_cgroup).
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, u32);
    __type(value, u64);
} target_cgroup SEC(".maps");

// Map to store multiple cgroup IDs to monitor (for descendants)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, u8);
} allowed_cgroups SEC(".maps");

// Map to store policy rules (indexed by rule number, supports up to 256 rules)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_POLICY_RULES);
    __type(key, u32);
    __type(value, struct policy_rule);
} policy_rules SEC(".maps");

// Map to store the number of policy rules
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} num_rules SEC(".maps");

// Map to store the default policy result (0 = deny, 1 = allow)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} default_policy SEC(".maps");

// Helper to check if we're in a target cgroup or descendant
static __always_inline bool is_target_cgroup()
{
    u32 key = 0;
    u64 *target_cgroup_id = bpf_map_lookup_elem(&target_cgroup, &key);
    if (!target_cgroup_id || *target_cgroup_id == 0) {
        // No target cgroup set, don't monitor anything
        return false;
    }

    // Get the current cgroup ID
    u64 current_cgroup_id = bpf_get_current_cgroup_id();

    // Check if this cgroup ID is in our allowed list
    // The userspace program populates this with all descendant cgroup IDs
    u8 *allowed = bpf_map_lookup_elem(&allowed_cgroups, &current_cgroup_id);
    if (allowed && *allowed == 1) {
        return true;
    }

    // Also enforce on cgroups created AFTER the attach-time snapshot: match by
    // hierarchy so a nested/delegated sub-cgroup of the box can't escape. [1] is
    // the box's depth from the cgroup root; the current task's ancestor at that
    // depth equals the box id ([0]) iff the task is under the box. (When [0] is
    // the legacy enable value 1 it can't equal a real cgroup id, so this no-ops
    // and the snapshot above still applies.)
    u32 level_key = 1;
    u64 *box_level = bpf_map_lookup_elem(&target_cgroup, &level_key);
    if (box_level && bpf_get_current_ancestor_cgroup_id((int)*box_level) == *target_cgroup_id) {
        return true;
    }

    return false;
}

// Bounded loop string comparison with disabled unrolling for BPF verifier
static __always_inline int simple_string_starts_with(const char *s, const char *p, __u32 max_len)
{
    if (max_len > 64) max_len = 64;

    #pragma clang loop unroll(disable)
    for (int i = 0; i < 64; i++) {
        if (i >= max_len) break;          // dominates the byte loads
        if (s[i] != p[i]) return 0;
    }
    return 1;
}

// Check if path is a Linux namespace FD from nsfs
static __always_inline bool is_nsfs_path(const char *path)
{
    // nsfs paths have the pattern: namespace_type:[inode_number]
    // Examples: mnt:[4026537166], net:[4026532621], ipc:[4026537168]

    // Check for common namespace types followed by :[ pattern
    const char *nsfs_prefixes[] = {
        "mnt:[", "net:[", "ipc:[", "pid:[",
        "uts:[", "user:[", "cgroup:[", "time:["
    };

    // Check each prefix with a bounded loop for BPF verifier
    #pragma clang loop unroll(disable)
    for (int prefix_idx = 0; prefix_idx < 8; prefix_idx++) {
        const char *prefix;
        int prefix_len;

        // Manually set prefix and length for each case to avoid dynamic array access
        if (prefix_idx == 0) { prefix = "mnt:["; prefix_len = 5; }
        else if (prefix_idx == 1) { prefix = "net:["; prefix_len = 5; }
        else if (prefix_idx == 2) { prefix = "ipc:["; prefix_len = 5; }
        else if (prefix_idx == 3) { prefix = "pid:["; prefix_len = 5; }
        else if (prefix_idx == 4) { prefix = "uts:["; prefix_len = 5; }
        else if (prefix_idx == 5) { prefix = "user:["; prefix_len = 6; }
        else if (prefix_idx == 6) { prefix = "cgroup:["; prefix_len = 8; }
        else if (prefix_idx == 7) { prefix = "time:["; prefix_len = 6; }
        else continue;

        // Check if path starts with this prefix
        bool matches = true;
        #pragma clang loop unroll(disable)
        for (int i = 0; i < 8; i++) {
            if (i >= prefix_len) break;
            if (path[i] != prefix[i]) {
                matches = false;
                break;
            }
        }

        if (matches) {
            // Verify there are digits after the colon-bracket
            int digit_pos = prefix_len;
            bool found_digit = false;
            #pragma clang loop unroll(disable)
            for (int i = 0; i < 16; i++) { // Check up to 16 chars for inode number
                if (digit_pos + i >= MAX_PATH_LEN) break;
                char c = path[digit_pos + i];
                if (c >= '0' && c <= '9') {
                    found_digit = true;
                } else if (c == ']' && found_digit) {
                    return true; // Found valid nsfs pattern
                } else if (c == '\0') {
                    break; // End of string
                } else if (c != '0' && c != '1' && c != '2' && c != '3' && c != '4' &&
                         c != '5' && c != '6' && c != '7' && c != '8' && c != '9') {
                    break; // Invalid character in inode number
                }
            }
        }
    }

    return false;
}

// Helper to determine operation type from file mode
static __always_inline u32 get_file_operation_type(struct file *file)
{
    // Read file mode flags
    fmode_t f_mode = BPF_CORE_READ(file, f_mode);

    // Check if file has write capabilities
    if (f_mode & FMODE_WRITE) {
        return OP_OPEN_RW; // Any write mode counts as rw
    }

    // Check if file has only read capabilities
    if (f_mode & FMODE_READ) {
        return OP_OPEN_RO; // Read-only
    }

    // Default to general open if we can't determine
    return OP_OPEN;
}

// Clean loop-based policy check for up to 256 rules with BPF verifier compatibility
// NOT __always_inline: kept as a real BPF-to-BPF subprogram so its 256-rule scan
// is verified once and CALLED, not duplicated inline into every hook. Inlining it
// into lsm_link (which also reconstructs the path) blew the verifier's 1M budget.
static __noinline int check_path_policy(const char *path, u32 file_op_type)
{
    __u32 key = 0;
    __u32 *nptr = bpf_map_lookup_elem(&num_rules, &key);
    __u32 n = nptr ? *nptr : 0;
    if (n == 0) {
        // No rules defined, use default policy from userspace
        __u32 *default_ptr = bpf_map_lookup_elem(&default_policy, &key);
        return default_ptr ? *default_ptr : 0; // Default to deny if map lookup fails
    }
    if (n > 256) n = 256;

    #pragma clang loop unroll(disable)
    for (__u32 i = 0; i < 256; i++) {
        if (i >= n) break;

        key = i;
        struct policy_rule *rule = bpf_map_lookup_elem(&policy_rules, &key);
        if (!rule) continue;

        __u32 len = rule->path_len;
        if (len == 0 || len > 64) continue;

        // One prefix pass to len-1, then classify the final char (one hot-path pass
        // instead of two). Exact match (path[len-1] == rule[len-1]) covers
        // descendants and file rules; for a directory rule, the directory ITSELF
        // also matches — its runtime path has no trailing slash, so it ends where
        // the rule's '/' is (path[len-1] == '\0'). That dir-itself case is why a
        // forbidden dir's entries could otherwise be enumerated and an allowed dir
        // wasn't listable.
        bool matches = false;
        if (simple_string_starts_with(path, rule->path, len - 1)) {
            if (path[len - 1] == rule->path[len - 1]) {
                matches = true;
            } else if (rule->is_directory && path[len - 1] == '\0') {
                matches = true;
            }
        }
        if (matches) {
            // Check if operation types match
            if (rule->operation == OP_OPEN) {
                // "open" matches any file operation type
                return rule->action;
            } else if (rule->operation == file_op_type) {
                // Exact operation match (open:ro or open:rw)
                return rule->action;
            }
            // Path matches but operation doesn't, continue to next rule
        }
    }

    // No matching rule found, use default policy from userspace
    key = 0;
    __u32 *default_ptr = bpf_map_lookup_elem(&default_policy, &key);
    return default_ptr ? *default_ptr : 0; // Default to deny if map lookup fails
}

SEC("lsm/file_open")
int BPF_PROG(lsm_open, struct file *file)
{
    // Check if we should monitor this cgroup
    if (!is_target_cgroup()) {
        return 0;
    }

    struct open_event *event;
    char path[MAX_PATH_LEN];
    int policy_result = 0;

    // Get file path first - file pointer is already trusted from BPF_PROG macro
    int ret = bpf_d_path(&file->f_path, path, sizeof(path));
    if (ret < 0) {
        // If d_path fails, try to at least get the filename
        struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
        const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);
        bpf_probe_read_kernel_str(path, sizeof(path), name);
    }

    // Skip logging nsfs (namespace filesystem) paths
    if (is_nsfs_path(path)) {
        return 0; // Allow but don't log namespace FDs
    }

    // Determine file operation type from file mode
    u32 file_op_type = get_file_operation_type(file);

    // Check policy for this path and operation type
    policy_result = check_path_policy(path, file_op_type);

    // Reserve ringbuf space
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        // Still need to enforce policy even if we can't log
        return policy_result ? 0 : -13; // -EACCES = 13
    }

    // Get process information
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid >> 32;
    event->tgid = pid_tgid & 0xFFFFFFFF;
    event->timestamp = bpf_ktime_get_ns();
    event->cgroup_id = bpf_get_current_cgroup_id();

    // Get process command name
    bpf_get_current_comm(event->comm, sizeof(event->comm));

    // NOTE: a spoofable comm-name allowlist (apt-get / dpkg* / update*) that
    // force-allowed every file open was removed here (issue #5). comm is the
    // executable's basename and is trivially forged (e.g. cp /bin/sh /tmp/update),
    // which disabled ALL path enforcement. Package tooling that needs relaxed
    // access must be granted by explicit path policy, not by process name.

    // Copy path to event with BPF verifier-friendly bounded loop
    #pragma clang loop unroll(disable)
    for (int i = 0; i < MAX_PATH_LEN; i++) {
        event->path[i] = path[i];
        if (path[i] == '\0') break;
    }

    // Record the resolved operation so userspace can distinguish read vs write opens
    event->operation = file_op_type;

    // Set result based on policy
    event->result = policy_result ? 0 : -13; // 0 = allowed, -EACCES = denied

    bpf_ringbuf_submit(event, 0);

    // Return policy decision: 0 = allow, negative = deny
    return policy_result ? 0 : -13; // -EACCES = 13
}

// --- hard-link guard (audit finding #3) -------------------------------------
// A path-based sandbox is bypassable by hard-linking a forbidden file into an
// allowed dir and reading it via the allowed path (the file-open hook resolves
// the NEW link's path, not the original; symlink resolution doesn't apply to
// hard links). Deny creating a hard link whose SOURCE wouldn't be readable by
// policy — so you can't alias a file you couldn't open directly.
//
// bpf_d_path can't help here: it requires a *trusted* struct path from the hook
// context, and path_link exposes the source only as a bare dentry (old_dentry).
// So reconstruct the source path by walking d_parent to the filesystem root
// (hard links are same-mount, so a single-mount walk yields the absolute path;
// files under a nested mount resolve relative to that inner mount — a known gap).
// Reconstruction bounds. These are tight because lsm_link inlines the 256-rule
// check_path_policy, and the two together must stay under the verifier's 1M-insn
// budget. COMP=40 covers git object filenames (38 hex chars); DEPTH=4 covers
// .git/objects/ab/<hash> when the box/mount root is the workdir (the common
// bind-mount case). Sources exceeding these fail OPEN (link allowed) — a residual
// hard-link-aliasing gap tracked for a tail-call fix that would free the budget.
#define HL_MAX_DEPTH 4
#define HL_MAX_COMP 40
// Only the first HL_MATCH_LEN bytes of the reconstructed path are compared
// (check_path_policy caps rule length at 64); a safe margin over that.
#define HL_MATCH_LEN 72

// CO-RE flavor to reach vfsmount.mnt_root — struct vfsmount isn't fully defined in
// the BTF header. The ___leash suffix makes libbpf relocate this against the
// kernel's real struct vfsmount at load time.
struct vfsmount___leash {
    struct dentry *mnt_root;
} __attribute__((preserve_access_index));

// Per-CPU scratch for the path buffers: 256-byte buffers on the stack would blow
// the 512-byte BPF stack limit, so they live in a per-CPU map instead (per-CPU
// avoids races between concurrent link() calls on different CPUs).
struct hl_scratch {
    char dest_abs[MAX_PATH_LEN]; // destination dir's absolute path (bpf_d_path)
    char raw[MAX_PATH_LEN];      // source within-mount path, reverse-built
    char path[MAX_PATH_LEN];     // assembled absolute source path
};
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct hl_scratch);
} hl_scratch_map SEC(".maps");

// hl_within_len returns the byte length of `dentry`'s within-mount path (walking
// to mnt_root) WITHOUT building it — cheap, for sizing the shared mount prefix.
// Returns 1 for the mount root itself ("/"), or -1 on overflow.
static __always_inline int hl_within_len(struct dentry *dentry, struct dentry *mnt_root)
{
    int total = 0;
    struct dentry *d = dentry;
    #pragma clang loop unroll(disable)
    for (int i = 0; i < HL_MAX_DEPTH; i++) {
        if (d == mnt_root) {
            break;
        }
        struct dentry *parent = BPF_CORE_READ(d, d_parent);
        if (parent == d) {
            break;
        }
        __u32 len = BPF_CORE_READ(d, d_name.len);
        if (len == 0 || len > HL_MAX_COMP) {
            return -1;
        }
        total += (int)len + 1; // component + leading '/'
        if (total >= MAX_PATH_LEN) {
            return -1;
        }
        d = parent;
    }
    if (total == 0) {
        total = 1; // "/" — dentry is the mount root
    }
    return total;
}

// hl_build_within reverse-fills buf with `dentry`'s path RELATIVE TO its mount
// (walking d_parent up to mnt_root), returning the start offset (path occupies
// [start, MAX_PATH_LEN)), or -1 on overflow. One probe per component keeps it in
// the verifier's budget. Stopping at mnt_root (not the filesystem root) is what
// makes bind mounts work: a bind mount shares the source dentry tree, so d_parent
// would otherwise walk past the mount into the source filesystem.
static __always_inline int hl_build_within(struct dentry *dentry, struct dentry *mnt_root, char *buf)
{
    int off = MAX_PATH_LEN; // exclusive write cursor, moves down
    struct dentry *d = dentry;

    #pragma clang loop unroll(disable)
    for (int i = 0; i < HL_MAX_DEPTH; i++) {
        if (d == mnt_root) {
            break;
        }
        struct dentry *parent = BPF_CORE_READ(d, d_parent);
        if (parent == d) {
            break; // filesystem root (safety net)
        }
        __u32 len = BPF_CORE_READ(d, d_name.len);
        const char *name = (const char *)BPF_CORE_READ(d, d_name.name);
        if (len == 0 || len > HL_MAX_COMP) {
            return -1;
        }
        if (off - (int)len - 1 < 1) {
            return -1;
        }
        char comp[HL_MAX_COMP];
        bpf_probe_read_kernel(comp, len, name);
        #pragma clang loop unroll(disable)
        for (int j = 0; j < HL_MAX_COMP; j++) {
            if ((__u32)j >= len) {
                break;
            }
            int dst = (off - (int)len + j) & (MAX_PATH_LEN - 1);
            buf[dst] = comp[j];
        }
        off -= (int)len;
        off -= 1;
        buf[off & (MAX_PATH_LEN - 1)] = '/';
        d = parent;
    }

    if (off >= MAX_PATH_LEN) {
        off = MAX_PATH_LEN - 1; // dentry was the mount root -> "/"
        buf[off & (MAX_PATH_LEN - 1)] = '/';
    }
    return off;
}

SEC("lsm/path_link")
int BPF_PROG(lsm_link, struct dentry *old_dentry, const struct path *new_dir, struct dentry *new_dentry)
{
    if (!is_target_cgroup()) {
        return 0;
    }

    u32 zero = 0;
    struct hl_scratch *s = bpf_map_lookup_elem(&hl_scratch_map, &zero);
    if (!s) {
        return 0;
    }

    // Hard links are same-mount, so source and destination share this mount root.
    struct vfsmount___leash *vm = (void *)BPF_CORE_READ(new_dir, mnt);
    struct dentry *mnt_root = BPF_CORE_READ(vm, mnt_root);

    // Destination dir's TRUE absolute path. new_dir is a trusted struct path, so
    // bpf_d_path is allowed and crosses mount boundaries — giving us the mount's
    // absolute prefix, which the source (same mount) shares. bpf_d_path returns the
    // length INCLUDING the trailing NUL, so subtract 1.
    long dret = bpf_d_path((struct path *)new_dir, s->dest_abs, sizeof(s->dest_abs));
    if (dret < 1) {
        return 0; // unresolved -> fail open (file-open hook still guards the read)
    }
    int dest_abs_len = (int)dret - 1;
    if (dest_abs_len < 0 || dest_abs_len >= MAX_PATH_LEN) {
        return 0;
    }

    // Destination dir's within-mount path LENGTH (no byte-building needed), to
    // learn how much of dest_abs is the shared mount prefix. When the dir IS the
    // mount root its within-path is "/", which maps onto the mount point itself
    // (nothing to strip).
    int dest_within_len = hl_within_len(BPF_CORE_READ(new_dir, dentry), mnt_root);
    if (dest_within_len < 0) {
        return 0;
    }
    int strip = (dest_within_len <= 1) ? 0 : dest_within_len;
    int prefix_len = dest_abs_len - strip;
    if (prefix_len < 0 || prefix_len >= MAX_PATH_LEN) {
        return 0;
    }

    // Source's within-mount path (a file, so always "/..." with len > 1).
    __builtin_memset(s->raw, 0, sizeof(s->raw));
    int sstart = hl_build_within(old_dentry, mnt_root, s->raw);
    if (sstart < 0 || sstart >= MAX_PATH_LEN) {
        return 0;
    }
    int slen = MAX_PATH_LEN - sstart; // source within-mount length

    // Assemble in ONE pass: path = dest_abs[0:prefix_len] + raw[sstart:]. Only the
    // first HL_MATCH_LEN bytes are ever compared (check_path_policy caps rule
    // length at 64), so stop there — building the full 256 is wasted verifier
    // work, and any rule that matches a longer path matches within its prefix.
    __builtin_memset(s->path, 0, sizeof(s->path));
    #pragma clang loop unroll(disable)
    for (int i = 0; i < HL_MATCH_LEN; i++) {
        if (i >= prefix_len + slen) {
            break;
        }
        char c;
        if (i < prefix_len) {
            c = s->dest_abs[i & (MAX_PATH_LEN - 1)];
        } else {
            int si = (sstart + (i - prefix_len)) & (MAX_PATH_LEN - 1);
            c = s->raw[si];
        }
        s->path[i & (MAX_PATH_LEN - 1)] = c;
    }

    // Deny the link if reading the source by its real path would be denied.
    if (check_path_policy(s->path, OP_OPEN) != 1) {
        return -1; // -EPERM: refuse to hard-link a file the box can't read
    }
    return 0;
}
