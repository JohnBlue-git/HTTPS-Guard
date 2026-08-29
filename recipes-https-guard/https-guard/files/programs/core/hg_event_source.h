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

/* Event source discriminator - first field in all event structs.  Shared
 * by every hook's raw event struct (see e.g. programs/ssl_uprobe/ssl_uprobe_event.h) so the
 * userspace ring-buffer callback can tell them apart. */
enum hg_event_source {
    HG_SOURCE_UPROBE         = 1,
    HG_SOURCE_XDP             = 2,
    HG_SOURCE_LSM_CERT_GUARD  = 3
};
