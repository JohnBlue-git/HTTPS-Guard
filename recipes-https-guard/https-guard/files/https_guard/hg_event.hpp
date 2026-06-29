#pragma once

#include <string>

#include "events.h"

namespace https_guard {

class hg_event {
public:
    // --- Raw BPF event data ---
    uint64_t timestamp_ns    = 0;
    uint32_t event_type      = 0;

    uint32_t pid             = 0;
    uint32_t tgid            = 0;

    uint32_t src_ip_v4       = 0;
    uint32_t dst_ip_v4       = 0;
    uint16_t src_port        = 0;
    uint16_t dst_port        = 0;

    uint16_t tls_version     = 0;
    uint16_t tls_record_type = 0;

    std::string process;
    std::string source_ip;
    std::string payload_snippet;

    // --- Userspace classification ---
    std::string severity;
    std::string message_id;
    std::string message;
    bool        actionable   = false;
};

}  // namespace https_guard
