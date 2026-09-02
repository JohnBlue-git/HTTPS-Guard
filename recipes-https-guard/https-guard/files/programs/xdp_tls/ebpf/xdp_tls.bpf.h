/* SPDX-License-Identifier: GPL-2.0 */
/* HTTPS-Guard eBPF program – XDP TLS inspection (AUXILIARY detection)
 *
 * Inspects TLS ClientHello packets on the wire on platforms with NIC-level
 * XDP support.  Only compiled/attached where the driver (or generic SKB
 * mode) supports it; see HttpGuardProgram's attach fallback.
 *
 * Hook: network driver RX path (or generic SKB mode).
 *   1. Ethernet + IP + TCP headers - filters to IPv4/TCP on port 443.
 *   2. TLS ClientHello - identifies ContentType 0x16 (Handshake).
 *   3. TLS version - extracted from the ClientHello fixed portion.
 *   4. Plaintext HTTP - detects HTTP methods (GET, POST, PUT, DELETE, HEAD)
 *      on port 443.
 *
 * Minimal classification: sets is_violation (1 if TLS < 1.2, 0 otherwise).
 * This is the ONLY classification in BPF - all other decisions happen in
 * userspace.
 *
 * Enforcement:
 *   - Synchronous: blocklist_check(ip->saddr) -> XDP_DROP for active
 *     blocklist entries.
 *   - Synchronous: is_violation == 1 -> XDP_DROP for TLS version violations.
 *   - Asynchronous: all other events -> XDP_PASS + ring buffer submission.
 */
#pragma once

#include "xdp_tls_event.h"

/* ClientHello cipher-suite/SNI parse. Kept in its own dependency-free
 * header so the same code that runs here can be unit-tested host-side —
 * see parse_client_hello.h's own header comment. */
#include "parse_client_hello.h"
#include "conn_rate.bpf.h"

/* Hybrid enforcement: see actions/blocklist/blocklist.bpf.h.  The
 * early-return XDP_DROP check lives entirely in this header so the
 * detection logic below stays uncluttered. */
#include "../../../actions/blocklist/blocklist.bpf.h"

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

static __always_inline int
fill_xdp_event_fields(struct xdp_event *evt, void *data_end)
{
    evt->hdr.event_source = HG_SOURCE_XDP;
    evt->tls.is_violation = 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    evt->hdr.pid = (__u32)pid_tgid;
    evt->hdr.tgid = (__u32)(pid_tgid >> 32);
    evt->hdr.timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&evt->hdr.comm, sizeof(evt->hdr.comm));
    evt->hdr.reserved = 0;
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
    for (i = 0; i < dst_sz - 1; i++)
    {
        if (&s[i] >= (const char *)data_end)
        {
            break;
        }
        dst[i] = s[i];
        if (s[i] == '\0')
        {
            break;
        }
    }
    dst[i] = '\0';
    return i;
}


/*
 * Minimal HTTP plaintext detection helper (XDP layer).
 * Returns true if the payload snippet looks like HTTP (starts with
 * "GET ", "POST ", "PUT " etc.).
 */
static __always_inline bool
looks_like_http(const char *payload, int len)
{
    if (len < 4)
    {
        return false;
    }

    if (payload[0] == 'G' && payload[1] == 'E' && payload[2] == 'T' && payload[3] == ' ')
    {
        return true;
    }

    if (payload[0] == 'P' && payload[1] == 'O' && payload[2] == 'S' && payload[3] == 'T')
    {
        return true;
    }

    if (payload[0] == 'P' && payload[1] == 'U' && payload[2] == 'T' && payload[3] == ' ')
    {
        return true;
    }

    if (payload[0] == 'D' && payload[1] == 'E' && payload[2] == 'L' && payload[3] == 'E')
    {
        return true;
    }

    return payload[0] == 'H' && payload[1] == 'T' &&
           payload[2] == 'T' && payload[3] == 'P';
}

SEC("xdp")
int https_guard_xdp(struct xdp_md *ctx)
{
    void *data_end = (void *)(unsigned long)ctx->data_end;
    void *data     = (void *)(unsigned long)ctx->data;
    struct ethhdr *eth = (struct ethhdr *)data;

    bpf_printk("xdp: packet received\n");

    /* Must have at least an Ethernet header */
    if ((void *)(eth + 1) > data_end)
    {
        bpf_printk("xdp: fail - not enough data for ethernet header\n");
        return XDP_PASS;
    }

    /* Only IPv4 for now */
    if (eth->h_proto != __bpf_constant_htons(ETH_P_IP))
    {
        bpf_printk("xdp: skip - not IPv4 (proto=0x%x)\n", bpf_ntohs(eth->h_proto));
        return XDP_PASS;
    }

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
    {
        return XDP_PASS;
    }

    /* Hybrid enforcement: if the source IP is in the blocklist, drop the
     * packet synchronously. */
    if (blocklist_check(ip->saddr) == XDP_DROP)
    {
        bpf_printk("xdp: DROP - blocklist hit for %pI4\n", &ip->saddr);
        return XDP_DROP;
    }

    __u16 tot_len = bpf_ntohs(ip->tot_len);
    if (tot_len < sizeof(*ip))
    {
        return XDP_PASS;
    }

    __u32 ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(*ip))
    {
        return XDP_PASS;
    }

    /* Only TCP */
    if (ip->protocol != IPPROTO_TCP)
    {
        bpf_printk("xdp: skip - not TCP (protocol=%d)\n", ip->protocol);
        return XDP_PASS;
    }

    struct tcphdr *tcp = (struct tcphdr *)((char *)ip + ip_hdr_len);
    if ((void *)(tcp + 1) > data_end)
    {
        return XDP_PASS;
    }

    __u32 tcp_hdr_len = tcp->doff * 4;
    if (tcp_hdr_len < sizeof(*tcp))
    {
        return XDP_PASS;
    }

    /* Record connection attempts before the port filter below. A port scan
     * targets ports other than 443 by definition, so counting after that
     * filter would make the thing we want to detect invisible.
     *
     * SYN without ACK is the connection-attempt signal: it counts each new
     * attempt once, rather than every packet of an established session, so a
     * single busy download cannot look like a flood. */
    if (tcp->syn && !tcp->ack)
    {
        conn_rate_record(ip->saddr, HG_CONN_ATTEMPT);
    }
    else if (tcp->fin || tcp->rst)
    {
        /* Pairs with the SYN above to maintain the held-open level that
         * Slowloris detection reads. */
        conn_rate_record(ip->saddr, HG_CONN_CLOSED);
    }

    /* Only care about port 443 (HTTPS) */
    if (bpf_ntohs(tcp->dest) != 443 && bpf_ntohs(tcp->source) != 443)
    {
        bpf_printk("xdp: skip - not port 443 (src=%d dst=%d)\n",
                   bpf_ntohs(tcp->source), bpf_ntohs(tcp->dest));
        return XDP_PASS;
    }

    if ((void *)tcp + tcp_hdr_len > data_end)
    {
        return XDP_PASS;
    }

    int payload_offset = ip_hdr_len + tcp_hdr_len;

    if (payload_offset > tot_len)
    {
        return XDP_PASS;
    }

    const unsigned char *tcp_payload = (const unsigned char *)tcp + tcp_hdr_len;
    const unsigned char *payload_end = (const unsigned char *)data_end;

    if (tcp_payload + 5 > payload_end)
    {
        return XDP_PASS;
    }

    int payload_len = tot_len - payload_offset;

    if (payload_len < 5)
    {
        return XDP_PASS;
    }

    /* Check for TLS ClientHello: ContentType = 0x16 */
    if (tcp_payload[0] == 0x16)
    {
        /* Counted per source per window, for renegotiation-storm detection.
         * Recorded for any handshake record, not only a ClientHello: a
         * renegotiation storm is characterised by repeated handshakes, and
         * distinguishing message types here would cost a parse before the
         * bounds checks below have been made. */
        conn_rate_record(ip->saddr, HG_CONN_HELLO);
        struct xdp_event *evt;

        evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
        if (!evt)
        {
            return XDP_PASS;
        }

        __builtin_memset(evt, 0, sizeof(*evt));
        fill_xdp_event_fields(evt, data_end);
        evt->conn.src_ip_v4 = ip->saddr;
        evt->conn.dst_ip_v4 = ip->daddr;
        evt->conn.src_port  = bpf_ntohs(tcp->source);
        evt->conn.dst_port  = bpf_ntohs(tcp->dest);

        /*
         * Write printable source-IP string directly into evt->conn.src_ip_str.
         */
        {
            const __u8 *b = (const __u8 *)&ip->saddr;
            int p = 0;
            __u8 oct;
            int i;
            for (i = 0; i < 4; i++)
            {
                oct = b[i];
                if (oct >= 100)
                {
                    evt->conn.src_ip_str[p++] = '0' + oct / 100;
                }
                if (oct >= 10)
                {
                    evt->conn.src_ip_str[p++] = '0' + (oct / 10) % 10;
                }
                evt->conn.src_ip_str[p++] = '0' + oct % 10;
                if (i < 3)
                {
                    evt->conn.src_ip_str[p++] = '.';
                }
            }
            evt->conn.src_ip_str[p] = '\0';
        }

        /* Parse TLS ClientHello - extract version and check for violation.
         * Record header (5 bytes: ContentType + Version + Length) is
         * followed by the Handshake header (4 bytes: HandshakeType +
         * 3-byte Length) before the legacy_version field we want. */
        const unsigned char *cursor = tcp_payload + 5 + 4;
        __u32 is_violation = 0;
        __u16 tls_ver = 0;
        if (cursor + 2 <= payload_end)
        {
            tls_ver = ((__u16)cursor[0] << 8) | (__u16)cursor[1];
            evt->tls.version = tls_ver;
            /* Minimal classification for XDP line-rate decision */
            is_violation = (tls_ver < 0x0303) ? 1 : 0;
            evt->tls.is_violation = is_violation;

            /* Cipher suites + SNI, from the same ClientHello body `cursor`
             * already points at. Only for an actual ClientHello — every
             * other handshake message (ServerHello, Certificate, ...) has
             * a completely different body layout, and walking one as if it
             * were a ClientHello would produce garbage rather than nothing.
             * Deliberately does not touch tls_version/is_violation above. */
            if (tcp_payload + 6 <= payload_end && tcp_payload[5] == 0x01)
            {
                parse_client_hello_detail(&evt->client_hello, cursor, payload_end);
            }
        }

        bpf_ringbuf_submit(evt, 0);

        /* Direct enforcement: drop TLS version violations at XDP level.
         * This MUST stay in BPF - XDP cannot wait for userspace.
         *
         * IMPORTANT: We use the local 'is_violation' variable, NOT evt->tls.is_violation,
         * because bpf_ringbuf_submit() invalidates the evt pointer. */
        if (is_violation)
        {
            bpf_printk("xdp: DROP - TLS version violation (0x%04x < 0x0303)\n",
                       tls_ver);
            return XDP_DROP;
        }

        bpf_printk("xdp: PASS - TLS version OK (0x%04x)\n", tls_ver);
        return XDP_PASS;
    }

    /* Plaintext HTTP detection on port 443 */
    if ((tcp_payload[0] == 'G' || tcp_payload[0] == 'P') &&
        looks_like_http((const char *)tcp_payload, payload_len))
    {
        bpf_printk("xdp: HTTP detected on port 443\n");
        struct xdp_event *evt;

        evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
        if (!evt)
        {
            return XDP_PASS;
        }

        __builtin_memset(evt, 0, sizeof(*evt));
        fill_xdp_event_fields(evt, data_end);
        evt->conn.src_ip_v4    = ip->saddr;
        evt->conn.dst_ip_v4    = ip->daddr;
        evt->conn.src_port     = bpf_ntohs(tcp->source);
        evt->conn.dst_port     = bpf_ntohs(tcp->dest);
        evt->tls.is_violation = 0;  /* Not a TLS version violation, just HTTP on port 443 */

        safe_strlcpy(evt->tls.payload_snippet, tcp_payload,
                     sizeof(evt->tls.payload_snippet), data_end);

        bpf_ringbuf_submit(evt, 0);
    }

    return XDP_PASS;
}
