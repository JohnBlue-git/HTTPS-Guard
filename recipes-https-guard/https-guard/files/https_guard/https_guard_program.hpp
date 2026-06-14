#pragma once

#include <string>

#include "ActionLoop.hpp"
#include "bpf_program.hpp"
#include "pattern_detector.hpp"

namespace https_guard {

class HttpGuardProgram final : public BpfProgram {
public:
    HttpGuardProgram(std::string object_path,
                     ActionLoop& action_loop,
                     std::string openssl_lib_path,
                     unsigned int ifindex) noexcept;

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
};

}  // namespace https_guard
