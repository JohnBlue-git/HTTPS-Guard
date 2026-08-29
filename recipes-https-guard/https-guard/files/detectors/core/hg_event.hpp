#pragma once

#include <cstdint>
#include <string>

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

    // Some hooks classify their own line-rate verdict directly in BPF
    // (see xdp_tls.bpf.h's `is_violation` — DESIGN.md documents this as
    // the one intentional exception to "BPF is purely observational").
    // When a hook has already made that determination, it sets this hint
    // so detectors don't have to (and can't incorrectly) re-derive it
    // from tls_version alone — tls_version == 0 means "not observed" for
    // hooks that never classify (e.g. the uprobe), but can be a genuinely
    // parsed, violating wire value for hooks that do.
    bool tls_violation_hint  = false;

    // Only meaningful for uprobe events: true if this is what the process
    // received (SSL_read — the request side, where attacker-controlled
    // input actually lives), false if it's what the process sent
    // (SSL_write — the response side) or not applicable (XDP events).
    bool is_inbound          = false;

    // Only meaningful for HG_SOURCE_LSM_CERT_GUARD events: true if the
    // accessing process's real executable (resolved in-kernel from
    // task->mm->exe_file, not the self-reported comm) did not match the
    // expected bmcweb binary. cert_shadow_mode records whether the BPF
    // hook was only observing (never denies) when this event was
    // produced — see detectors/cert_access/CertAccessDetector.hpp.
    bool cert_identity_mismatch = false;
    bool cert_shadow_mode       = true;
    uint64_t cgroup_id          = 0;
    std::string real_exe_path;

    std::string process;
    std::string source_ip;
    std::string payload_snippet;
};

}  // namespace https_guard
