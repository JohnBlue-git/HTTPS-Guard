/* SPDX-License-Identifier: GPL-2.0 */
/* HTTPS-Guard eBPF programs
 *
 * XDP program:  Inspects TLS handshake packets on the wire.
 *               Detects TLS version violations and basic HTTP anomalies.
 * Uprobe:       Hooks OpenSSL SSL_write() to inspect plaintext payloads.
 */

/* Tell bpf_tracing.h which architecture we are targeting. */
#define __TARGET_ARCH_x86

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <asm/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

/* BPF C is C99 without a standard library; provide bool ourselves. */
#ifndef bool
typedef _Bool bool;
#define true  1
#define false 0
#endif

#include "../include/https_guard/events.h"

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
looks_like_http(const char *payload, int len, void *data_end)
{
    const char *prefixes[] = { "GET ", "POST ", "PUT ", "DELE", "PATC",
                               "HEAD", "HTTP", "OPTIO", "CONNE", "TRACE" };
    int i;

    if (len < 4)
        return false;

    for (i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++) {
        bool match = true;
        int j;

        for (j = 0; j < 4; j++) {
            const char *p = &prefixes[i][j];
            if (p >= (const char *)data_end) {
                match = false;
                break;
            }
        }
        if (!match)
            continue;

        /* Use a volatile trick to avoid unrolled-loop verifier limit. */
        switch (i) {
        case 0:  /* "GET " */
            if (payload[0] == 'G' && payload[1] == 'E' &&
                payload[2] == 'T'  && payload[3] == ' ')  return true;
            break;
        case 1:  /* "POST " */
            if (payload[0] == 'P' && payload[1] == 'O' &&
                payload[2] == 'S' && payload[3] == 'T')  return true;
            break;
        case 2:  /* "PUT "  */
            if (payload[0] == 'P' && payload[1] == 'U' &&
                payload[2] == 'T' && payload[3] == ' ')  return true;
            break;
        case 3:  /* "DELE" (DELETE) */
            if (payload[0] == 'D' && payload[1] == 'E' &&
                payload[2] == 'L' && payload[3] == 'E')  return true;
            break;
        default:
            break;
        }
    }
    return false;
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
                      const char *tcp_payload, int payload_len,
                      void *data_end)
{
    int offset = 0;
    int i;

    /* --- TLS Record header (5 bytes) --- */
    /* ContentType = tcp_payload[0]; we already checked it is 0x16 */
    /* ProtocolVersion = tcp_payload[1] << 8 | tcp_payload[2]; (not the
     * negotiated version – we use ClientHello.version later) */
    /* Length = (tcp_payload[3] << 8) | tcp_payload[4]; */
    offset = 5;

    /* --- Handshake protocol --- */
    if (offset + 4 > payload_len)
        return;
    /* HandshakeType = tcp_payload[offset];  0x01 = ClientHello */
    /* Handshake length (3 bytes, big-endian) */
    __u32 hs_len = ((__u32)tcp_payload[offset + 1] << 16) |
                   ((__u32)tcp_payload[offset + 2] << 8)  |
                   ((__u32)tcp_payload[offset + 3]);
    (void)hs_len; /* length check not critical for our fields */
    offset += 4;

    /* --- ClientHello fixed fields --- */
    if (offset + 2 > payload_len)
        return;
    evt->tls_version = ((__u16)tcp_payload[offset] << 8) |
                        (__u16)tcp_payload[offset + 1];
    if (evt->tls_version < 0x0303) {
        evt->event_type = HG_EVENT_TLS_VERSION_VIOLATION;
        evt->severity = HG_SEV_CRITICAL;
    } else {
        evt->event_type = HG_EVENT_TLS_HANDSHAKE_METADATA;
    }
    offset += 2;     /* skip version */

    offset += 32;    /* random (32 bytes) */

    /* --- Session ID --- */
    if (offset + 1 > payload_len)
        return;
    int sid_len = tcp_payload[offset];
    offset += 1 + sid_len;
    if (offset > payload_len)
        return;

    /* --- Cipher Suites --- */
    if (offset + 2 > payload_len)
        return;
    int cs_len = ((int)tcp_payload[offset] << 8) | tcp_payload[offset + 1];
    offset += 2 + cs_len;
    if (offset > payload_len)
        return;

    /* --- Compression Methods --- */
    if (offset + 1 > payload_len)
        return;
    int cm_len = tcp_payload[offset];
    offset += 1 + cm_len;
    if (offset > payload_len)
        return;

    /* --- Extensions --- */
    if (offset + 2 > payload_len)
        return;
    int ext_total_len = ((int)tcp_payload[offset] << 8) | tcp_payload[offset + 1];
    offset += 2;
    if (offset + ext_total_len > payload_len)
        return;

    /*
     * Walk extensions.  We are interested in:
     *   0x0000  –  Server Name Indication (SNI)
     */
    int ext_end = offset + ext_total_len;
    int sni_len = 0;

    while (offset + 4 <= ext_end) {
        __u16 ext_type = ((__u16)tcp_payload[offset] << 8) |
                          (__u16)tcp_payload[offset + 1];
        __u16 ext_len  = ((__u16)tcp_payload[offset + 2] << 8) |
                          (__u16)tcp_payload[offset + 3];
        offset += 4;

        if (ext_type == 0x0000 && ext_len > 0) {
            /* SNI list entry: ServerNameList length (2 bytes) */
            if (offset + 2 > ext_end)
                return;
            int sni_list_len = ((int)tcp_payload[offset] << 8) |
                                tcp_payload[offset + 1];
            if (sni_list_len < 3 || sni_list_len > ext_len)
                return;
            offset += 2;

            /* First (and usually only) entry:
             *   - NameType (1 byte, 0 = host_name)
             *   - NameLength (2 bytes)
             *   - Name (variable) */
            if (offset + 3 > ext_end)
                return;
            __u8 name_type = tcp_payload[offset];
            int name_len = ((int)tcp_payload[offset + 1] << 8) |
                            tcp_payload[offset + 2];
            offset += 3;

            if (name_type == 0 && name_len > 0) {
                if (offset + name_len > ext_end)
                    return;
                int copy_sz = name_len < (int)sizeof(evt->sni) - 1
                                  ? name_len
                                  : (int)sizeof(evt->sni) - 1;
                for (i = 0; i < (int)sizeof(evt->sni) - 1; i++) {
                    if (i >= copy_sz)
                        break;
                    evt->sni[i] = tcp_payload[offset + i];
                }
                evt->sni[copy_sz] = '\0';
                sni_len = copy_sz;
            }
            break;
        }
        offset += ext_len;
    }
    (void)sni_len;
}

SEC("xdp")
int https_guard_xdp(struct xdp_md *ctx)
{
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
    int payload_offset = ip_hdr_len + tcp_hdr_len;
    int payload_len    = tot_len - payload_offset;

    if (payload_len < 5)
        return XDP_PASS;

    const char *tcp_payload = (const char *)ip + payload_offset;
    if ((const void *)(tcp_payload + payload_len) > data_end)
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

        parse_tls_clienthello(evt, tcp_payload, payload_len, data_end);

        bpf_ringbuf_submit(evt, 0);
        return XDP_PASS;  /* Do not drop – only observe & report. */
    }

    /* Plaintext HTTP detection on port 443 is unusual after TLS handshake
     * (should be encrypted).  If we see HTTP verbs on 443, flag as anomaly. */
    if ((tcp_payload[0] == 'G' || tcp_payload[0] == 'P') &&
        looks_like_http(tcp_payload, payload_len, data_end)) {
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