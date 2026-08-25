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
    HG_SOURCE_LSM_CERT_GUARD  = 3,
    /* Synthesised in userspace by ConnRateSweeper from the BPF counter map,
     * not parsed from a ring-buffer record -- no hook module claims it. */
    HG_SOURCE_CONN_RATE       = 4
};

/* =========================================================================
 * The envelope every hook's raw record starts with.
 *
 * Factored out because all three hooks were carrying identical copies of
 * these five fields, and a shared struct is the difference between "they
 * happen to match" and "they cannot drift". Each hook's event struct then
 * nests this plus its own detail sub-structs, so a reader can see at a
 * glance which fields are universal and which belong to one hook -- see
 * programs/<hook>/ebpf/<hook>_event.h.
 *
 * `event_source` MUST remain the first member of this struct, and this
 * struct the first member of every event struct: DetectLoop::process()
 * reads a uint32 at offset 0 of the raw record to decide which hook owns
 * it, before it knows the type. A static_assert in each hook's .cpp pins
 * that offset.
 * ========================================================================= */
struct hg_event_hdr {
    uint32_t event_source;   /* enum hg_event_source -- keep first */
    uint32_t reserved;       /* explicit, so the 8-byte align below is not silent padding */
    uint64_t timestamp_ns;   /* bpf_ktime_get_ns() when the hook fired */
    uint32_t pid;
    uint32_t tgid;
    char     comm[HG_COMM_LEN];  /* self-reported -- a hint, never an identity */
};
