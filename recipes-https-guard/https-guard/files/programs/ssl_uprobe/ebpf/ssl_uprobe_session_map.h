/* SPDX-License-Identifier: GPL-2.0 */
/* Wire layout for ssl_uprobe's kernel-side session-binding maps -- shared
 * between the BPF program (ssl_uprobe.bpf.h) and userspace
 * (SessionTupleSweeper), the same way conn_rate.bpf.h shares hg_conn_rate's
 * layout with ConnRateSweeper. Plain C, no libbpf: safe for the host C++
 * compiler as well as clang's BPF target, which is why this uses uint*_t
 * rather than the __u8/__u16/__u64 kernel typedefs the rest of
 * ssl_uprobe.bpf.h uses -- those aren't visible outside a kernel/BPF build.
 *
 * uint*_t comes from hg_event_source.h rather than <stdint.h> directly: the
 * BPF target has no usable libc header here, so that header hand-declares
 * these typedefs under __BPF__ and only falls back to <stdint.h> otherwise
 * -- see its own comment. conn_rate.bpf.h relies on the same include for the
 * same reason.
 */
#pragma once

#include "hg_event_source.h"

#define HTTPS_GUARD_THREAD_TUPLE_MAP_NAME  "https_guard_thread_tuple_map"
#define HTTPS_GUARD_SESSION_TUPLE_MAP_NAME "https_guard_session_tuple_map"

/* {pid_tgid -> the port-443 socket this thread most recently touched} and
 * {SSL* (as an integer) -> its bound tuple} both use this as their value
 * type -- see ssl_uprobe.bpf.h for how each map is populated and consumed. */
struct hg_bound_tuple {
    uint8_t  is_ipv6;
    uint8_t  padding[7];
    uint8_t  local_addr[16];
    uint8_t  remote_addr[16];
    uint16_t local_port;   /* host byte order */
    uint16_t remote_port;  /* host byte order */
    uint64_t timestamp_ns; /* bpf_ktime_get_ns() -- CLOCK_MONOTONIC-equivalent */
};
