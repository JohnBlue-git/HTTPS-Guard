#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#include "../include/https_guard/events.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

static __always_inline void fill_common_event_fields(struct hg_event* evt)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    evt->pid = (__u32)pid_tgid;
    evt->tgid = (__u32)(pid_tgid >> 32);
    evt->timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&evt->process, sizeof(evt->process));
}

static __always_inline int deny_if_legacy_tls(struct xdp_md* ctx, void* data, void* data_end,
                                              struct tcphdr* tcp, __u32 src_ip, __u32 dst_ip)
{
    __u8* p = (__u8*)(tcp + 1);
    if ((void*)(p + 6) > data_end) {
        return XDP_PASS;
    }

    __u8 tls_record_type = p[0];
    __u16 tls_version = ((__u16)p[1] << 8) | p[2];
    __u8 handshake_type = p[5];

    if (tls_record_type != 0x16 || handshake_type != 0x01) {
        return XDP_PASS;
    }

    if (tls_version == 0x0301 || tls_version == 0x0302) {
        struct hg_event* evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
        if (evt) {
            __builtin_memset(evt, 0, sizeof(*evt));
            fill_common_event_fields(evt);
            evt->event_type = HG_EVENT_TLS_VERSION_VIOLATION;
            evt->severity = HG_SEV_CRITICAL;
            evt->src_ip_v4 = src_ip;
            evt->dst_ip_v4 = dst_ip;
            evt->src_port = bpf_ntohs(tcp->source);
            evt->dst_port = bpf_ntohs(tcp->dest);
            evt->tls_version = tls_version;
            evt->tls_record_type = tls_record_type;
            bpf_ringbuf_submit(evt, 0);
        }
        return XDP_DROP;
    }

    struct hg_event* evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (evt) {
        __builtin_memset(evt, 0, sizeof(*evt));
        fill_common_event_fields(evt);
        evt->event_type = HG_EVENT_TLS_HANDSHAKE_METADATA;
        evt->severity = HG_SEV_INFO;
        evt->src_ip_v4 = src_ip;
        evt->dst_ip_v4 = dst_ip;
        evt->src_port = bpf_ntohs(tcp->source);
        evt->dst_port = bpf_ntohs(tcp->dest);
        evt->tls_version = tls_version;
        evt->tls_record_type = tls_record_type;
        bpf_ringbuf_submit(evt, 0);
    }

    return XDP_PASS;
}

SEC("xdp")
int https_guard_xdp(struct xdp_md* ctx)
{
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;

    struct ethhdr* eth = data;
    if ((void*)(eth + 1) > data_end) {
        return XDP_PASS;
    }
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
        return XDP_PASS;
    }

    struct iphdr* ip = (void*)(eth + 1);
    if ((void*)(ip + 1) > data_end) {
        return XDP_PASS;
    }
    if (ip->protocol != IPPROTO_TCP) {
        return XDP_PASS;
    }

    struct tcphdr* tcp = (void*)ip + ip->ihl * 4;
    if ((void*)(tcp + 1) > data_end) {
        return XDP_PASS;
    }

    __u16 dport = bpf_ntohs(tcp->dest);
    __u16 sport = bpf_ntohs(tcp->source);
    if (dport != 443 && sport != 443) {
        return XDP_PASS;
    }

    return deny_if_legacy_tls(ctx, data, data_end, tcp, ip->saddr, ip->daddr);
}

static __always_inline int has_payload_signature(const char* buf, int len)
{
    if (len < 8) {
        return 0;
    }

    #pragma unroll
    for (int i = 0; i < 200; i++) {
        if (i + 9 >= len) {
            break;
        }
        if (buf[i] == '.' && buf[i + 1] == '.' && buf[i + 2] == '/' &&
            buf[i + 3] == '.' && buf[i + 4] == '.' && buf[i + 5] == '/') {
            return 1;
        }
        if (buf[i] == 'U' && buf[i + 1] == 'N' && buf[i + 2] == 'I' &&
            buf[i + 3] == 'O' && buf[i + 4] == 'N') {
            return 1;
        }
    }

    return 0;
}

SEC("uprobe/SSL_write")
int BPF_KPROBE(https_guard_ssl_write, void* ssl, const char* buf, int num)
{
    if (!buf || num <= 0) {
        return 0;
    }

    struct hg_event* evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) {
        return 0;
    }

    __builtin_memset(evt, 0, sizeof(*evt));
    fill_common_event_fields(evt);
    evt->event_type = HG_EVENT_HTTP_PAYLOAD_OBSERVED;
    evt->severity = HG_SEV_INFO;

    int copy_len = num;
    if (copy_len > HG_PAYLOAD_SNIPPET_LEN - 1) {
        copy_len = HG_PAYLOAD_SNIPPET_LEN - 1;
    }

    long copied = bpf_probe_read_user_str(evt->payload_snippet, copy_len, buf);
    if (copied <= 0) {
        bpf_ringbuf_discard(evt, 0);
        return 0;
    }

    if (has_payload_signature(evt->payload_snippet, copy_len)) {
        evt->event_type = HG_EVENT_HTTP_ANOMALY_DETECTED;
        evt->severity = HG_SEV_WARNING;
    }

    bpf_ringbuf_submit(evt, 0);
    return 0;
}
