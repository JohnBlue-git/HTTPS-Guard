#pragma once

#include <cstdint>
#include <cstdio>

#include "ssl_uprobe_event.h"

namespace https_guard::test_support {

// Builds a raw uprobe_event as programs/ssl_uprobe would emit it, for
// detection tests that need a real wire record rather than a constructed
// event struct. Shared across the detection test files that exercise the
// uprobe path (tls_version, payload_anomaly, traffic_observed).
inline uprobe_event makeUprobeEvent(hg_uprobe_direction direction, uint16_t tls_version,
                                     const char* process, const char* payload)
{
    uprobe_event raw{};
    raw.hdr.event_source = HG_SOURCE_UPROBE;
    raw.hdr.timestamp_ns = 1700000000000000000ULL;
    raw.hdr.pid  = 4242;
    raw.hdr.tgid = 4242;
    std::snprintf(raw.hdr.comm, sizeof(raw.hdr.comm), "%s", process);

    raw.direction   = direction;
    raw.tls.version = tls_version;
    std::snprintf(raw.tls.payload_snippet, sizeof(raw.tls.payload_snippet), "%s", payload);
    return raw;
}

}  // namespace https_guard::test_support
