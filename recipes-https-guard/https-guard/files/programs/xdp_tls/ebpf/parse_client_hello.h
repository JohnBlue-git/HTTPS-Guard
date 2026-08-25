/* SPDX-License-Identifier: GPL-2.0 */
/* ClientHello deep parse: cipher suite list + SNI host_name.
 *
 * Deliberately dependency-free: plain pointer arithmetic and `uint*_t`
 * only, no BPF helpers, no libbpf, no libc. That's what lets the *actual
 * shipped parser* be unit-tested host-side against hand-built ClientHello
 * byte sequences (see tests/test_client_hello_parsing.cpp) instead of a
 * test-only reimplementation that could drift from what really runs.
 * `hg_event_source.h` supplies the `uint*_t` types in both worlds (its own
 * typedefs under `__BPF__`, `<stdint.h>` otherwise).
 *
 * Everything here is PURELY OBSERVATIONAL — it extracts raw bytes into the
 * event and never classifies. Weak-cipher and unexpected-SNI decisions are
 * made in userspace (detections/cipher_suite/, detections/sni/), not here.
 * The one exception on this hook remains `is_violation` for the TLS
 * version, which predates this and must stay in BPF because XDP_DROP has
 * to happen at line rate.
 *
 * ClientHello layout being walked (all lengths big-endian on the wire):
 *
 *   ┌─ TLS record header ─────────────────────────────────────────┐
 *   │ [0]    ContentType = 0x16 (Handshake)                        │
 *   │ [1..2] record version      [3..4] record length              │
 *   ├─ Handshake header ──────────────────────────────────────────┤
 *   │ [5]    HandshakeType = 0x01 (ClientHello)                    │
 *   │ [6..8] handshake length (3 bytes)                            │
 *   ├─ ClientHello body ── `ch` below points HERE ────────────────┤
 *   │ +0..1   legacy_version   ◄── already parsed by the caller     │
 *   │ +2..33  random (32 bytes)                                    │
 *   │ +34     session_id_len (1)  then session_id (variable)       │
 *   │ ...     cipher_suites_len (2) then cipher_suites (variable)  │
 *   │ ...     compression_len (1)   then compression (variable)    │
 *   │ ...     extensions_len (2)    then extensions:               │
 *   │           ext_type(2) ext_len(2) ext_data(ext_len) ...       │
 *   │           where ext_type 0x0000 = server_name (SNI):         │
 *   │             list_len(2) name_type(1)=0 name_len(2) name(..)  │
 *   └──────────────────────────────────────────────────────────────┘
 *
 * BPF verifier notes: every read is bounds-checked against `end` (the real
 * packet end) immediately before it, and `off` is re-bounded against
 * HG_CH_MAX_SCAN on each variable-length advance so it stays a tracked,
 * bounded scalar rather than becoming unbounded. The loops have
 * compile-time trip counts and are unrolled (BPF only) for the same reason.
 */
#pragma once

#include "xdp_tls_event.h"

/* clang accepts `#pragma unroll`; host compilers warn about it under
 * -Wall. The unrolling only matters for the BPF verifier anyway. */
#ifdef __BPF__
#define HG_UNROLL _Pragma("unroll")
#else
#define HG_UNROLL
#endif

/* Hard cap on how deep into the ClientHello we're willing to walk. Also
 * what keeps the running offset a provably bounded scalar. */
#define HG_CH_MAX_SCAN 1024
/* How many extensions to walk before giving up looking for SNI. */
#define HG_CH_MAX_EXTS 16

#ifdef __BPF__
#define HG_CH_INLINE static __always_inline
#else
#define HG_CH_INLINE static inline
#endif

/* --- Bounds-checked single-byte reads -------------------------------------
 *
 * Every read below goes through these, one byte at a time, each recomputing
 * its own pointer from `base` and validating exactly that byte against
 * `end` immediately before dereferencing.
 *
 * This is more verbose than checking a whole field's width once and then
 * indexing into it, and it is that way on purpose. The straightforward
 * version — `if (base + off + 5 > end) return; ... base[off+4] ...` — was
 * rejected by the BPF verifier on the real target:
 *
 *   parse_client_hello.h:154: r0 = *(u8 *)(r5 +6)
 *   invalid access to packet, off=31 size=1, R5(id=49,off=31,r=29)
 *   R5 offset is outside of the packet
 *
 * clang had CSE'd the pointer arithmetic across the bounds check, so the
 * read ended up on a register whose *validated* range (r=29) was shorter
 * than the offset being read (31) — the check and the read had drifted onto
 * different pointers. Pairing each check with its own read, on a pointer
 * computed right there, is what keeps them from being separated.
 * ------------------------------------------------------------------------- */

HG_CH_INLINE int
hg_ch_u8(const unsigned char *base, uint32_t off, const unsigned char *end, uint32_t *out)
{
    if (off >= HG_CH_MAX_SCAN)
        return 0;
    if (base + off + 1 > end)
        return 0;
    *out = (uint32_t)*(base + off);
    return 1;
}

HG_CH_INLINE int
hg_ch_u16(const unsigned char *base, uint32_t off, const unsigned char *end, uint32_t *out)
{
    uint32_t hi = 0;
    uint32_t lo = 0;

    if (!hg_ch_u8(base, off, end, &hi))
        return 0;
    if (!hg_ch_u8(base, off + 1, end, &lo))
        return 0;

    *out = (hi << 8) | lo;
    return 1;
}

/* Takes the ClientHello sub-struct rather than the whole xdp_event, so it
 * is structurally incapable of touching the header, the connection tuple or
 * the TLS fields the caller already filled in. That used to rest on
 * reviewer discipline; now it rests on the type. */
HG_CH_INLINE void
parse_client_hello_detail(struct hg_client_hello *out,
                          const unsigned char *ch,
                          const unsigned char *end)
{
    uint32_t off;
    uint32_t sid_len = 0;
    uint32_t cs_len = 0;
    uint32_t comp_len = 0;
    uint32_t captured = 0;

    /* legacy_version (2) + random (32) — the caller already read the
     * version; this parse deliberately does not touch it again. */
    off = 2 + 32;

    /* --- session_id (skipped; length only) --- */
    if (!hg_ch_u8(ch, off, end, &sid_len))
        return;
    if (sid_len > 32) {          /* RFC 8446: max 32 */
        out->sni_malformed = 1;
        return;
    }
    off += 1 + sid_len;

    /* --- cipher_suites --- */
    if (!hg_ch_u16(ch, off, end, &cs_len))
        return;
    off += 2;

    if (cs_len == 0 || (cs_len & 1)) {  /* must be a non-zero multiple of 2 */
        out->sni_malformed = 1;
        return;
    }

    out->cipher_suites_offered = (uint16_t)(cs_len / 2);

    HG_UNROLL
    for (int i = 0; i < HG_MAX_CIPHER_SUITES; i++) {
        uint32_t suite = 0;
        if ((uint32_t)(i * 2) >= cs_len)
            break;
        if (!hg_ch_u16(ch, off + (uint32_t)(i * 2), end, &suite))
            break;
        out->cipher_suites[i] = (uint16_t)suite;
        captured++;
    }
    out->cipher_suite_count = (uint16_t)captured;

    /* Bound before advancing past the full list — a client offering more
     * than 256 suites (512 bytes) is well past anything legitimate, and
     * this is also what keeps the offset bounded below. */
    if (cs_len > 512)
        return;
    off += cs_len;

    /* --- compression_methods (skipped; length only) --- */
    if (!hg_ch_u8(ch, off, end, &comp_len))
        return;
    if (comp_len > 16) {
        out->sni_malformed = 1;
        return;
    }
    off += 1 + comp_len;

    /* --- extensions --- */
    {
        uint32_t ext_total = 0;
        if (!hg_ch_u16(ch, off, end, &ext_total))
            return;  /* no extensions at all: legal, and means no SNI */
        off += 2;    /* the declared total isn't needed; `end` bounds us */
    }

    HG_UNROLL
    for (int e = 0; e < HG_CH_MAX_EXTS; e++) {
        uint32_t etype = 0;
        uint32_t elen = 0;
        uint32_t list_len = 0;
        uint32_t ntype = 0;
        uint32_t nlen = 0;
        uint32_t n = 0;

        if (!hg_ch_u16(ch, off, end, &etype))
            return;
        if (!hg_ch_u16(ch, off + 2, end, &elen))
            return;
        off += 4;

        if (elen > 512)
            return;  /* implausible single extension; stop rather than guess */

        if (etype != 0) {        /* not server_name — skip its body */
            off += elen;
            continue;
        }

        /* --- server_name (SNI) extension --- */
        if (!hg_ch_u16(ch, off, end, &list_len) ||
            !hg_ch_u8(ch, off + 2, end, &ntype) ||
            !hg_ch_u16(ch, off + 3, end, &nlen)) {
            out->sni_malformed = 1;
            return;
        }

        /* name_type 0 == host_name is the only type ever defined */
        if (ntype != 0 || nlen == 0 || list_len < nlen + 3) {
            out->sni_malformed = 1;
            return;
        }

        off += 5;

        HG_UNROLL
        for (int k = 0; k < HG_SNI_LEN - 1; k++) {
            uint32_t c = 0;
            if ((uint32_t)k >= nlen)
                break;
            if (!hg_ch_u8(ch, off + (uint32_t)k, end, &c))
                break;
            out->sni_hostname[k] = (char)c;
            n++;
        }

        if (n > HG_SNI_LEN - 1)
            n = HG_SNI_LEN - 1;
        out->sni_hostname[n] = '\0';
        out->sni_present = (n > 0) ? 1 : 0;

        /* Fewer bytes captured than the name declared — either it exceeded
         * HG_SNI_LEN, or the packet ended mid-name. Either way the captured
         * string is a PREFIX, and a detector must not compare a prefix as
         * if it were the whole hostname: a truncated "bmc.evil.com" would
         * otherwise read as "bmc" and could match an expected hostname it
         * has nothing to do with. Flagging it malformed is what stops that
         * from becoming a mismatch-check bypass. */
        if (n < nlen)
            out->sni_malformed = 1;

        return;
    }
}
