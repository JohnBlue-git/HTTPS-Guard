#pragma once

#include <chrono>
#include <string>

#include "bpf_program.hpp"
#include "events.h"
#include "tls_version.hpp"
#include "pattern_detector.hpp"
#include "redfish_event_message.hpp"
#include "core/ActionLoop.hpp"

namespace https_guard {

class HttpGuardProgram final : public BpfProgram {
public:
    HttpGuardProgram(std::string object_path,
                     ActionLoop& action_loop,
                     std::string openssl_lib_path,
                     unsigned int ifindex,
                     std::chrono::seconds blocklist_ttl,
                     std::string output_path) noexcept;

protected:
    bool attachProgram() noexcept override;
    ring_buffer_sample_fn getRingBufferHandler() noexcept override;

private:
    int ringBufferHandler(void* data, size_t size) noexcept;
    static int ringBufferCallback(void* ctx, void* data, size_t size) noexcept;

    ActionLoop& action_loop_;
    std::string openssl_lib_path_;
    unsigned int ifindex_;
    PatternDetector detector_;
    std::chrono::seconds blocklist_ttl_;
    std::string output_path_;
};

}  // namespace https_guard
