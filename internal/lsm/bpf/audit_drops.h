// SPDX-License-Identifier: GPL-2.0
//
// Audit-loss accounting shared by every leash LSM object (issue #241).
//
// Every LSM program decides first and records second: the decision never
// depends on the audit record. When bpf_ringbuf_reserve fails (the ring is
// full because userspace has not drained it yet) the record cannot be written.
// Before #241 that loss was silent. Each failed reservation now increments a
// per-CPU counter slot, which userspace sums and reports as an audit.dropped
// record, so an incomplete audit trail is always visible.
//
// audit_config[0] bit 0 (AUDIT_CONFIG_LOSSLESS) is the opt-in "lossless audit"
// posture: an operation whose record cannot be written is denied instead of
// decided without a record. Userspace sets it before the programs attach.
//
// Include after vmlinux.h and bpf_helpers.h; the including object defines u32
// and u64.
#ifndef LEASH_AUDIT_DROPS_H
#define LEASH_AUDIT_DROPS_H

#ifndef BPF_MAP_TYPE_PERCPU_ARRAY
#define BPF_MAP_TYPE_PERCPU_ARRAY 6
#endif
#ifndef BPF_MAP_TYPE_ARRAY
#define BPF_MAP_TYPE_ARRAY 2
#endif

// Default size of each object's event ring buffer. Userspace may resize it
// before load (LEASH_AUDIT_RINGBUF_KB); it must stay a power-of-two multiple
// of the page size.
#define AUDIT_RINGBUF_DEFAULT_BYTES (1024 * 1024)

// Counter slots. The slot meaning is per object; internal/lsm/audit_drops.go
// names them. Keep in step.
#define AUDIT_DROP_SLOTS 4

#define AUDIT_CONFIG_LOSSLESS 1

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, AUDIT_DROP_SLOTS);
    __type(key, u32);
    __type(value, u64);
} audit_drops SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} audit_config SEC(".maps");

// Count one record that could not be reserved in slot. Returns nonzero when
// the lossless posture is on, i.e. the caller must deny the operation.
static __always_inline int audit_record_dropped(u32 slot)
{
    u64 *count = bpf_map_lookup_elem(&audit_drops, &slot);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }
    u32 zero = 0;
    u32 *config = bpf_map_lookup_elem(&audit_config, &zero);
    return config && (*config & AUDIT_CONFIG_LOSSLESS);
}

#endif // LEASH_AUDIT_DROPS_H
