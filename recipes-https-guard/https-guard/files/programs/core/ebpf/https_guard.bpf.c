/* SPDX-License-Identifier: GPL-2.0 */
/* HTTPS-Guard eBPF programs — aggregator
 *
 * This translation unit is the only thing clang actually compiles for the
 * BPF target.  It owns everything shared across hooks (arch macro, common
 * includes, the LICENSE symbol, the ring buffer map, the BPF C99 `bool`
 * shim) and then pulls in each hook's own program body as a header:
 *
 *   - ssl_uprobe.bpf.h     — uprobe on OpenSSL SSL_write() (primary detection)
 *   - xdp_tls.bpf.h         — XDP TLS ClientHello inspection (auxiliary)
 *   - lsm_cert_guard.bpf.h — BPF-LSM guard on the HTTPS cert/key file (shadow mode)
 *
 * Both hooks share this same ring buffer and the blocklist map (adopted
 * separately by the blocklist.bpf.h header xdp_tls.bpf.h pulls in), so the
 * userspace daemon processes their events identically regardless of which
 * hook produced them.  See programs/<hook>/ebpf/<hook>.bpf.h for each hook's own
 * design rationale.
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

/* Shared event-source discriminator (used by both hooks' event structs) */
#include "hg_event_source.h"

/* BPF C is C99 without a standard library; provide bool ourselves. */
#ifndef bool
typedef _Bool bool;
#define true  1
#define false 0
#endif

char LICENSE[] SEC("license") = "GPL";

/* =========================================================================
 * Ring buffer for sending events from BPF to userspace.  Shared by every
 * hook below.
 * ========================================================================= */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);  /* 16 MiB */
} events SEC(".maps");

#include "../../ssl_uprobe/ebpf/ssl_uprobe.bpf.h"
#include "../../xdp_tls/ebpf/xdp_tls.bpf.h"
#include "../../lsm_cert_guard/ebpf/lsm_cert_guard.bpf.h"
