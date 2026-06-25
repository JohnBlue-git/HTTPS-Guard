/* SPDX-License-Identifier: GPL-2.0 */
/* HTTPS-Guard eBPF programs
 *
 * Uprobe programs (primary detection mechanism):
 *   - SSL_write(SSL *ssl, const void *buf, int num):
 *       Reads the negotiated TLS version from ssl->version.
 *       Detects TLS version violations (< 1.2) and captures
 *       plaintext HTTP payloads for anomaly detection.
 *
 * XDP program (auxiliary, only works on platforms with NIC support):
 *   - Inspects TLS ClientHello packets on the wire for TLS version
 *     violations.  Disabled by default because most BMC platforms
 *     (ASpeed AST2600, ftgmac100) do not support XDP in QEMU or
 *     real hardware.  See PACKAGECONFIG build-time switch.
 *
 * Both programs share the same ring-buffer event format and blocklist
 * map, so the userspace daemon processes them identically.
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

/* Shared event types and structs (used by both BPF and userspace) */
#include "events.h"

/* Build-time generated header with the offset of ssl_st.version.
 * Produced by scripts/gen_ssl_offset.c, which uses hardcoded
 * architecture-specific offsets (OpenSSL 3.x made ssl_st opaque).
 * This is the clean way to access ssl->version without CO-RE —
 * see the NOTE below for details. */
#include "ssl_version_offset.h"

/* NOTE on OpenSSL ssl_st struct access:
 *
 * We do NOT use CO-RE (bpf_core_read) for userspace structs because
 * CO-RE relocations require the target type to exist in the kernel's
 * BTF — but ssl_st is a userspace struct from libssl.so, not a kernel
 * struct.  The kernel BTF has no type ID for it, so any CO-RE
 * relocation for ssl_st fields will fail at program load time with
 * "invalid CO-RE relocation" / "failed to resolve CO-RE relocation".
 *
 * Instead we read ssl->version directly from userspace memory using
 * bpf_probe_read_user() (see https_guard_ssl_write below for the
 * exact offset, which was empirically determined). */

/* Hybrid enforcement: see actions/blocklist.bpf.h. The early-return XDP_DROP
 * check lives entirely in this header so the .bpf.c detection logic
 * stays uncluttered. */
#include "../actions/blocklist/blocklist.bpf.h"

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
fill_uprobe_event_fields(struct uprobe_event *evt, void *data_end)
{
    evt->event_source = HG_SOURCE_UPROBE;
    evt->reserved = 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    evt->pid = (__u32)pid_tgid;
    evt->tgid = (__u32)(pid_tgid >> 32);
    evt->timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&evt->process, sizeof(evt->process));
    evt->padding = 0;
    return 0;
}

static __always_inline int
fill_xdp_event_fields(struct xdp_event *evt, void *data_end)
{
    evt->event_source = HG_SOURCE_XDP;
    evt->is_violation = 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    evt->pid = (__u32)pid_tgid;
    evt->tgid = (__u32)(pid_tgid >> 32);
    evt->timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&evt->process, sizeof(evt->process));
    evt->padding = 0;
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
 * Uprobe program – primary detection mechanism for BMC platforms
 *
 * Hooks OpenSSL SSL_write(SSL *ssl, const void *buf, int num) to:
 *   1. Read the negotiated TLS version from the SSL struct (ssl->version)
 *      and detect violations (version < TLS 1.2 = 0x0303).
 *   2. Capture plaintext HTTP payloads for anomaly detection.
 *
 * This is the PRIMARY enforcement path for BMCs because XDP is not
 * available on ASpeed AST2600 ftgmac100 NICs (the typical BMC
 * network controller).  The uprobe works on all platforms since it
 * only requires userspace uprobe support (CONFIG_UPROBES).
 * ========================================================================= */

/*
 * SSL_write(SSL *ssl, const void *buf, int num)
 *   - arg1: ssl  (pointer to SSL object – read version from here)
 *   - arg2: buf  (pointer to plaintext)
 *   - arg3: num  (length in bytes)
 *
 * DESIGN PRINCIPLE: BPF is PURELY OBSERVATIONAL.
 * -------------------------------------------------
 * This uprobe does NOT classify events or make security decisions.
 * It only reads raw data from the process and forwards it to the
 * ring buffer.  All classification (TLS version violation vs normal
 * traffic, anomaly detection) happens in userspace
 * (https_guard_program.cpp), where we have access to the full C++
 * standard library and OpenSSL headers.
 *
 * This separation keeps the BPF program minimal, verifier-friendly,
 * and free from policy decisions that belong in userspace.
 *
 * DATA READ FROM THE PROCESS:
 *   - ssl->version:  The negotiated TLS version code, read from
 *     the OpenSSL ssl_st struct at the build-time determined offset
 *     (SSL_VERSION_OFFSET, generated by scripts/gen_ssl_offset.c
 *     using offsetof(struct ssl_st, version) from the actual headers).
 *   - buf[0..num]:   A snippet of the plaintext payload being written.
 *   - pid/tgid:      Process identification for socket correlation.
 *
 * MEMORY ACCESS:
 *   All data pointers (ssl, buf) are userspace virtual addresses in
 *   the probed process.  We use bpf_probe_read_user() which safely
 *   handles page faults — if a pointer is invalid, it returns -EFAULT
 *   and the output buffer remains zeroed.
 *
 * CO-RE NOTE:
 *   We do NOT use bpf_core_read() for ssl_st because CO-RE relocations
 *   require the target type to exist in the kernel's BTF.  ssl_st is a
 *   userspace struct — no kernel BTF type ID exists.  Using
 *   bpf_core_read() would fail at program load time with "invalid
 *   CO-RE relocation".  Instead we use bpf_probe_read_user() with the
 *   build-time offset from gen_ssl_offset.c.
 */
SEC("uprobe/ssl_write")
int https_guard_ssl_write(struct pt_regs *ctx)
{
    const void *ssl = (const void *)PT_REGS_PARM1(ctx);
    const void *buf = (const void *)PT_REGS_PARM2(ctx);
    int num = (int)PT_REGS_PARM3(ctx);

    if (num <= 0 || !buf || !ssl)
        return 0;

    // Would output to /sys/kernel/debug/tracing/trace_pipe
    bpf_printk("https_guard: uprobe hit pid=%d num=%d\n",
               bpf_get_current_pid_tgid() >> 32, num);

    struct uprobe_event *evt;

    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    __builtin_memset(evt, 0, sizeof(*evt));
    fill_uprobe_event_fields(evt, NULL);

    /* ---------------------------------------------------------------
     * Read ssl->version from userspace memory.
     *
     * The offset of the `version` field within struct ssl_st is
     * determined at build time by scripts/gen_ssl_offset.c, which
     * compiles a small C program that includes <openssl/ssl.h> and
     * prints offsetof(struct ssl_st, version).  The result is stored
     * in ssl_version_offset.h as the SSL_VERSION_OFFSET macro.
     *
     * This approach is architecture-independent: on ARM 32-bit the
     * offset is 36 (two 4-byte pointers before version), on x86_64
     * it would be 20 (two 8-byte pointers before version), and on
     * any future OpenSSL version it adapts automatically.
     *
     * The negotiated TLS version (e.g. TLS 1.2 = 0x0303, TLS 1.3 =
     * 0x0304) is stored in the lower 16 bits of this 4-byte int.
     * --------------------------------------------------------------- */
    __u32 version_raw = 0;
    __u16 tls_version = 0;

    if (bpf_probe_read_user(&version_raw, sizeof(version_raw),
                            (const void *)((uintptr_t)ssl + SSL_VERSION_OFFSET)) == 0) {
        tls_version = (__u16)(version_raw & 0xFFFF);
    }

    /* PURELY OBSERVATIONAL - no classification, no event_type, no severity.
     * Just capture raw data and let userspace decide what it means.
     * Userspace will check tls_version and classify accordingly. */
    evt->tls_version = tls_version;

    /* Capture a snippet of the plaintext payload for anomaly detection */
    int copy_sz = num < (int)sizeof(evt->payload_snippet) - 1
                      ? num
                      : (int)sizeof(evt->payload_snippet) - 1;

    bpf_probe_read_user(evt->payload_snippet, copy_sz, buf);
    evt->payload_snippet[copy_sz] = '\0';

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

/* =========================================================================
 * XDP program – auxiliary, only for platforms with NIC-level XDP support
 *
 * Inspects TLS ClientHello packets on the wire.  Disabled by default
 * on BMC builds; only compiled when PACKAGECONFIG includes "xdp".
 *
 * See the "xdp" PACKAGECONFIG flag in the bitbake recipe for details.
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

    /* Hybrid enforcement: if the source IP is in the blocklist, drop the
     * packet synchronously. */
    if (blocklist_check(ip->saddr) == XDP_DROP)
        return XDP_DROP;

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
        struct xdp_event *evt;

        evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
        if (!evt)
            return XDP_PASS;

        __builtin_memset(evt, 0, sizeof(*evt));
        fill_xdp_event_fields(evt, data_end);
        evt->src_ip_v4 = ip->saddr;
        evt->dst_ip_v4 = ip->daddr;
        evt->src_port  = bpf_ntohs(tcp->source);
        evt->dst_port  = bpf_ntohs(tcp->dest);

        /*
         * Write printable source-IP string directly into evt->source_ip.
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

        /* Parse TLS ClientHello - extract version and check for violation */
        const unsigned char *cursor = tcp_payload + 5;
        __u32 is_violation = 0;
        if (cursor + 2 <= payload_end) {
            evt->tls_version = ((__u16)cursor[0] << 8) | (__u16)cursor[1];
            /* Minimal classification for XDP line-rate decision */
            is_violation = (evt->tls_version < 0x0303) ? 1 : 0;
            evt->is_violation = is_violation;
        }

        bpf_ringbuf_submit(evt, 0);

        /* Direct enforcement: drop TLS version violations at XDP level.
         * This MUST stay in BPF - XDP cannot wait for userspace.
         *
         * IMPORTANT: We use the local 'is_violation' variable, NOT evt->is_violation,
         * because bpf_ringbuf_submit() invalidates the evt pointer. */
        if (is_violation)
            return XDP_DROP;

        return XDP_PASS;
    }

    /* Plaintext HTTP detection on port 443 */
    if ((tcp_payload[0] == 'G' || tcp_payload[0] == 'P') &&
        looks_like_http((const char *)tcp_payload, payload_len)) {
        struct xdp_event *evt;

        evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
        if (!evt)
            return XDP_PASS;

        __builtin_memset(evt, 0, sizeof(*evt));
        fill_xdp_event_fields(evt, data_end);
        evt->src_ip_v4    = ip->saddr;
        evt->dst_ip_v4    = ip->daddr;
        evt->src_port     = bpf_ntohs(tcp->source);
        evt->dst_port     = bpf_ntohs(tcp->dest);
        evt->is_violation = 0;  /* Not a TLS version violation, just HTTP on port 443 */

        safe_strlcpy(evt->payload_snippet, tcp_payload,
                     sizeof(evt->payload_snippet), data_end);

        bpf_ringbuf_submit(evt, 0);
    }

    return XDP_PASS;
}