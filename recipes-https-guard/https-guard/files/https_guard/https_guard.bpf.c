/* SPDX-License-Identifier: GPL-2.0 */
/* HTTPS-Guard eBPF programs
 *
 * XDP program:  Inspects TLS handshake packets on the wire.
 *               Detects TLS version violations and basic HTTP anomalies.
 * Uprobe:       Hooks OpenSSL SSL_write() to inspect plaintext payloads.
 */

/* Tell bpf_tracing.h which architecture we are targeting. */
#if !defined(__TARGET_ARCH_x86) && !defined(__TARGET_ARCH_arm) && \
    !defined(__TARGET_ARCH_arm64) && !defined(__TARGET_ARCH_powerpc) && \
    !defined(__TARGET_ARCH_riscv)
#define __TARGET_ARCH_x86
#endif

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

/* BPF C is C99 without a standard library; provide bool ourselves. */
#ifndef bool
typedef _Bool bool;
#define true  1
#define false 0
#endif

#define HG_COMM_LEN            16
#define HG_IP_STR_LEN          32
#define HG_SNI_LEN             64
#define HG_URI_LEN             128
#define HG_PAYLOAD_SNIPPET_LEN 128

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

enum hg_event_type {
    HG_EVENT_TLS_VERSION_VIOLATION  = 1,
    HG_EVENT_TLS_HANDSHAKE_METADATA = 2,
    HG_EVENT_HTTP_PAYLOAD_OBSERVED  = 3,
    HG_EVENT_HTTP_ANOMALY_DETECTED  = 4
};

enum hg_severity {
    HG_SEV_INFO     = 0,
    HG_SEV_WARNING  = 1,
    HG_SEV_CRITICAL = 2
};

struct hg_event {
    __u64 timestamp_ns;
    __u32 event_type;
    __u32 severity;

    __u32 pid;
    __u32 tgid;

    __u32 src_ip_v4;
    __u32 dst_ip_v4;
    __u16 src_port;
    __u16 dst_port;

    __u16 tls_version;
    __u16 tls_record_type;

    char process[HG_COMM_LEN];
    char source_ip[HG_IP_STR_LEN];
    char sni[HG_SNI_LEN];
    char uri[HG_URI_LEN];
    char payload_snippet[HG_PAYLOAD_SNIPPET_LEN];
};

char LICENSE[] SEC("license") = "GPL";

/* =========================================================================
 * Ring buffer for sending events from BPF to userspace
 * ========================================================================= */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);  /* 16 MiB */
} events SEC(".maps");

/* =========================================================================
 * Helpers
 * ========================================================================= */

static __always_inline int
fill_common_fields(struct hg_event *evt, void *data_end)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    evt->pid = (__u32)pid_tgid;
    evt->tgid = (__u32)(pid_tgid >> 32);
    evt->timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&evt->process, sizeof(evt->process));
    evt->severity = 0;
    return 0;
}

/* Copy at most 'dst_sz - 1' bytes from 'src', ensuring the result is
 * null-terminated.  Returns the number of bytes written (excluding the
 * null terminator).
 */
static __always_inline int
safe_strlcpy(char *dst, const void *src, int dst_sz, void *data_end)
{
    int i;
    const char *s = (const char *)src;

#pragma unroll
    for (i = 0; i < dst_sz - 1; i++) {
        if (&s[i] >= (const char *)data_end)
            break;
        dst[i] = s[i];
        if (s[i] == '\0')
            break;
    }
    dst[i] = '\0';
    return i;
}

/* =========================================================================
 * XDP program – inline TLS and HTTP inspection on the network interface
 * ========================================================================= */

/*
 * Minimal HTTP plaintext detection helper (XDP layer).
 * Returns true if the payload snippet looks like HTTP (starts with
 * "GET ", "POST ", "PUT " etc.).
 */
static __always_inline bool
looks_like_http(const char *payload, int len)
{
    if (len < 4)
        return false;

    if (payload[0] == 'G' && payload[1] == 'E' &&
        payload[2] == 'T' && payload[3] == ' ')
        return true;

    if (payload[0] == 'P' && payload[1] == 'O' &&
        payload[2] == 'S' && payload[3] == 'T')
        return true;

    if (payload[0] == 'P' && payload[1] == 'U' &&
        payload[2] == 'T' && payload[3] == ' ')
        return true;

    if (payload[0] == 'D' && payload[1] == 'E' &&
        payload[2] == 'L' && payload[3] == 'E')
        return true;

    return payload[0] == 'H' && payload[1] == 'T' &&
           payload[2] == 'T' && payload[3] == 'P';
}

/*
 * Parse a TLS ClientHello and extract:
 *   - tls_version  (the version the client announces)
 *   - sni           (the Server Name Indication, if present)
 *   - event_type    set to HG_EVENT_TLS_VERSION_VIOLATION if version < 1.2
 *
 * The caller is responsible for bounds-checking before calling this
 * helper.  We assume the TCP payload starts at 'tcp_payload' and has
 * 'payload_len' bytes.
 */
static __always_inline void
parse_tls_clienthello(struct hg_event *evt,
                      const unsigned char *tcp_payload,
                      const unsigned char *payload_end)
{
    const unsigned char *cursor = tcp_payload + 5;
    const unsigned char *ext_end;
    int i;

    /* --- Handshake protocol --- */
    if (cursor + 4 > payload_end)
        return;
    /* HandshakeType = tcp_payload[offset];  0x01 = ClientHello */
    /* Handshake length (3 bytes, big-endian) */
    __u32 hs_len = ((__u32)cursor[1] << 16) |
                   ((__u32)cursor[2] << 8)  |
                   ((__u32)cursor[3]);
    (void)hs_len; /* length check not critical for our fields */
    cursor += 4;

    /* --- ClientHello fixed fields --- */
    if (cursor + 2 > payload_end)
        return;
    evt->tls_version = ((__u16)cursor[0] << 8) |
                        (__u16)cursor[1];
    if (evt->tls_version < 0x0303) {
        evt->event_type = HG_EVENT_TLS_VERSION_VIOLATION;
        evt->severity = HG_SEV_CRITICAL;
    } else {
        evt->event_type = HG_EVENT_TLS_HANDSHAKE_METADATA;
    }
    cursor += 2;     /* skip version */

    if (cursor + 32 > payload_end)
        return;
    cursor += 32;    /* random (32 bytes) */

    /* --- Session ID --- */
    if (cursor + 1 > payload_end)
        return;
    int sid_len = cursor[0];
    cursor += 1;
    if (cursor + sid_len > payload_end)
        return;
    cursor += sid_len;

    /* --- Cipher Suites --- */
    if (cursor + 2 > payload_end)
        return;
    int cs_len = ((int)cursor[0] << 8) | cursor[1];
    cursor += 2;
    if (cursor + cs_len > payload_end)
        return;
    cursor += cs_len;

    /* --- Compression Methods --- */
    if (cursor + 1 > payload_end)
        return;
    int cm_len = cursor[0];
    cursor += 1;
    if (cursor + cm_len > payload_end)
        return;
    cursor += cm_len;

    /* --- Extensions --- */
    if (cursor + 2 > payload_end)
        return;
    int ext_total_len = ((int)cursor[0] << 8) | cursor[1];
    cursor += 2;
    if (cursor + ext_total_len > payload_end)
        return;

    /*
     * Walk extensions.  We are interested in:
     *   0x0000  –  Server Name Indication (SNI)
     */
    ext_end = cursor + ext_total_len;
    int sni_len = 0;

    while (cursor + 4 <= ext_end) {
        __u16 ext_type = ((__u16)cursor[0] << 8) |
                          (__u16)cursor[1];
        __u16 ext_len  = ((__u16)cursor[2] << 8) |
                          (__u16)cursor[3];
        cursor += 4;

        if (cursor + ext_len > ext_end)
            return;

        if (ext_type == 0x0000 && ext_len > 0) {
            /* SNI list entry: ServerNameList length (2 bytes) */
            if (cursor + 2 > ext_end)
                return;
            int sni_list_len = ((int)cursor[0] << 8) |
                                cursor[1];
            if (sni_list_len < 3 || sni_list_len > ext_len)
                return;
            cursor += 2;

            /* First (and usually only) entry:
             *   - NameType (1 byte, 0 = host_name)
             *   - NameLength (2 bytes)
             *   - Name (variable) */
            if (cursor + 3 > ext_end)
                return;
            __u8 name_type = cursor[0];
            int name_len = ((int)cursor[1] << 8) |
                            cursor[2];
            cursor += 3;

            if (name_type == 0 && name_len > 0) {
                if (cursor + name_len > ext_end)
                    return;
                int copy_sz = name_len < (int)sizeof(evt->sni) - 1
                                  ? name_len
                                  : (int)sizeof(evt->sni) - 1;
                for (i = 0; i < (int)sizeof(evt->sni) - 1; i++) {
                    if (i >= copy_sz)
                        break;
                    evt->sni[i] = cursor[i];
                }
                evt->sni[copy_sz] = '\0';
                sni_len = copy_sz;
            }
            break;
        }
        cursor += ext_len;
    }
    (void)sni_len;
}

SEC("xdp")
int https_guard_xdp(struct xdp_md *ctx)
{
    /* Packet headers are parsed from packet bytes, not kernel structs, so
     * direct accesses remain correct here even in a CO-RE-enabled build. */
    void *data_end = (void *)(unsigned long)ctx->data_end;
    void *data     = (void *)(unsigned long)ctx->data;
    struct ethhdr *eth = (struct ethhdr *)data;

    /* Must have at least an Ethernet header */
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Only IPv4 for now */
    if (eth->h_proto != __bpf_constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u16 tot_len = bpf_ntohs(ip->tot_len);
    if (tot_len < sizeof(*ip))
        return XDP_PASS;

    __u32 ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(*ip))
        return XDP_PASS;

    /* Only TCP */
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (struct tcphdr *)((char *)ip + ip_hdr_len);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    __u32 tcp_hdr_len = tcp->doff * 4;
    if (tcp_hdr_len < sizeof(*tcp))
        return XDP_PASS;

    /* Only care about port 443 (HTTPS) */
    if (bpf_ntohs(tcp->dest) != 443 && bpf_ntohs(tcp->source) != 443)
        return XDP_PASS;

    /* Only inspect the first packet of a connection (SYN flag set) to
     * catch the TLS ClientHello.  We still look at non-SYN packets for
     * HTTP anomaly detection. */
    if ((void *)tcp + tcp_hdr_len > data_end)
        return XDP_PASS;

    int payload_offset = ip_hdr_len + tcp_hdr_len;

    if (payload_offset > tot_len)
        return XDP_PASS;

    const unsigned char *tcp_payload = (const unsigned char *)tcp + tcp_hdr_len;
    const unsigned char *payload_end = (const unsigned char *)data_end;

    if (tcp_payload + 5 > payload_end)
        return XDP_PASS;

    int payload_len = tot_len - payload_offset;

    if (payload_len < 5)
        return XDP_PASS;

    /* Check for TLS ClientHello: ContentType = 0x16 */
    if (tcp_payload[0] == 0x16) {
        struct hg_event *evt;

        evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
        if (!evt)
            return XDP_PASS;

        __builtin_memset(evt, 0, sizeof(*evt));
        fill_common_fields(evt, data_end);
        evt->src_ip_v4 = ip->saddr;
        evt->dst_ip_v4 = ip->daddr;
        evt->src_port  = bpf_ntohs(tcp->source);
        evt->dst_port  = bpf_ntohs(tcp->dest);

        /*
         * Write printable source-IP string directly into evt->source_ip.
         * Suppress leading zeros for each octet.  evt->source_ip is up to
         * 32 bytes; at most "255.255.255.255" == 15 chars.
         */
        {
            const __u8 *b = (const __u8 *)&ip->saddr;
            int p = 0;
            __u8 oct;
            int i;
            for (i = 0; i < 4; i++) {
                oct = b[i];
                if (oct >= 100) {
                    evt->source_ip[p++] = '0' + oct / 100;
                }
                if (oct >= 10) {
                    evt->source_ip[p++] = '0' + (oct / 10) % 10;
                }
                evt->source_ip[p++] = '0' + oct % 10;
                if (i < 3) {
                    evt->source_ip[p++] = '.';
                }
            }
            evt->source_ip[p] = '\0';
        }

        parse_tls_clienthello(evt, tcp_payload, payload_end);

        bpf_ringbuf_submit(evt, 0);
        return XDP_PASS;  /* Do not drop – only observe & report. */
    }

    /* Plaintext HTTP detection on port 443 is unusual after TLS handshake
     * (should be encrypted).  If we see HTTP verbs on 443, flag as anomaly. */
    if ((tcp_payload[0] == 'G' || tcp_payload[0] == 'P') &&
        looks_like_http(tcp_payload, payload_len)) {
        struct hg_event *evt;

        evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
        if (!evt)
            return XDP_PASS;

        __builtin_memset(evt, 0, sizeof(*evt));
        fill_common_fields(evt, data_end);
        evt->event_type   = HG_EVENT_HTTP_ANOMALY_DETECTED;
        evt->severity     = HG_SEV_WARNING;
        evt->src_ip_v4    = ip->saddr;
        evt->dst_ip_v4    = ip->daddr;
        evt->src_port     = bpf_ntohs(tcp->source);
        evt->dst_port     = bpf_ntohs(tcp->dest);

        safe_strlcpy(evt->payload_snippet, tcp_payload,
                     sizeof(evt->payload_snippet), data_end);

        bpf_ringbuf_submit(evt, 0);
    }

    return XDP_PASS;
}

/* =========================================================================
 * Uprobe program – captures plaintext from OpenSSL SSL_write()
 * ========================================================================= */

/*
 * SSL_write(SSL *ssl, const void *buf, int num)
 *   - arg1: ssl  (unused here)
 *   - arg2: buf  (pointer to plaintext)
 *   - arg3: num  (length in bytes)
 */
SEC("uprobe/ssl_write")
int https_guard_ssl_write(struct pt_regs *ctx)
{
    const void *buf = (const void *)PT_REGS_PARM2(ctx);
    int num = (int)PT_REGS_PARM3(ctx);

    if (num <= 0 || !buf)
        return 0;

    struct hg_event *evt;

    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    __builtin_memset(evt, 0, sizeof(*evt));
    fill_common_fields(evt, (void *)(unsigned long)(num));

    evt->event_type = HG_EVENT_HTTP_PAYLOAD_OBSERVED;
    evt->severity   = HG_SEV_INFO;

    /* Capture a snippet of the plaintext payload. */
    int copy_sz = num < (int)sizeof(evt->payload_snippet) - 1
                      ? num
                      : (int)sizeof(evt->payload_snippet) - 1;

    /* Read from userspace memory using bpf_probe_read_user(). */
    bpf_probe_read_user(evt->payload_snippet, copy_sz, buf);
    evt->payload_snippet[copy_sz] = '\0';

    bpf_ringbuf_submit(evt, 0);
    return 0;
}
