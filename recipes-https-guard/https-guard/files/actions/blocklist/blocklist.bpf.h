#ifndef HTTPS_GUARD_BLOCKLIST_BPF_H
#define HTTPS_GUARD_BLOCKLIST_BPF_H

#define HTTPS_GUARD_BLOCKLIST_MAP_NAME "src_blocklist"
#define HTTPS_GUARD_BLOCKLIST_MAX_ENTRIES 1024

#ifndef __cplusplus

#include <bpf/bpf_helpers.h>

/* src_ip_v4 (network byte order) -> absolute expiry in nanoseconds
 * (bpf_ktime_get_ns() clock). */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, HTTPS_GUARD_BLOCKLIST_MAX_ENTRIES);
    __type(key, __u32);
    __type(value, __u64);
} src_blocklist SEC(".maps");

/* Returns XDP_DROP if the source IP is currently blocklisted; XDP_PASS
 * otherwise. Performs opportunistic expiry pruning of stale entries. */
static __always_inline int blocklist_check(__u32 src_ip_v4)
{
    __u64 now = bpf_ktime_get_ns();
    __u64* expiry = bpf_map_lookup_elem(&src_blocklist, &src_ip_v4);
    if (!expiry) {
        return XDP_PASS;
    }

    if (now >= *expiry) {
        bpf_map_delete_elem(&src_blocklist, &src_ip_v4);
        return XDP_PASS;
    }

    return XDP_DROP;
}

#endif // __cplusplus

#endif /* HTTPS_GUARD_BLOCKLIST_BPF_H */