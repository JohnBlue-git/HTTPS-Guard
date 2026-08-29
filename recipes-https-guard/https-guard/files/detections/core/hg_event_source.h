#pragma once

/*
 * Use BPF-native integer types when compiled for the BPF target
 * (clang -target bpf), and standard <stdint.h> types otherwise.
 */
#ifdef __BPF__
typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned int       uint32_t;
typedef unsigned long long uint64_t;
#else
#include <stdint.h>
#endif // __BPF__

#define HG_COMM_LEN            16
#define HG_IP_STR_LEN          32
#define HG_PAYLOAD_SNIPPET_LEN 128
#define HG_PATH_LEN            64

/* Upper bound on a single raw ring-buffer record, used by DetectLoop to size
 * its preallocated queue slots. Every hook's event struct must fit; each
 * hook's .cpp static_asserts this so a struct that outgrows it fails to
 * compile rather than being silently dropped at runtime. */
#define HG_MAX_RAW_EVENT_SIZE  1024

/* ClientHello parsing limits (xdp_tls only). Both are capture caps, not
 * protocol limits: a client may legitimately offer more cipher suites or
 * a longer SNI than these, in which case the excess is not captured (the
 * raw counts are still reported so userspace can tell truncation apart
 * from a genuinely short list). Kept small deliberately — every byte
 * here is in the per-event ring-buffer record, and BPF's verifier cost
 * scales with the unrolled parse loops these sizes drive. */
#define HG_MAX_CIPHER_SUITES   32
#define HG_SNI_LEN             64

/* Event source discriminator - first field in all event structs.  Shared
 * by every hook's raw event struct (see e.g. programs/ssl_uprobe/ssl_uprobe_event.h) so the
 * userspace ring-buffer callback can tell them apart. */
enum hg_event_source {
    HG_SOURCE_UPROBE         = 1,
    HG_SOURCE_XDP             = 2,
    HG_SOURCE_LSM_CERT_GUARD  = 3
};
