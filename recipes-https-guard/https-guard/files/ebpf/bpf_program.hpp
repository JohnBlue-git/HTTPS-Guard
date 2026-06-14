#pragma once

#include <bpf/libbpf.h>
#include <optional>
#include <string>
#include <vector>

#include "ActionLoop.hpp"
#include "events.h"
#include "pattern_detector.hpp"
#include "string_utils.hpp"

namespace https_guard {

class BpfProgram {
public:
    explicit BpfProgram(std::string object_path) noexcept;
    BpfProgram(const BpfProgram&) = delete;
    BpfProgram& operator=(const BpfProgram&) = delete;
    BpfProgram(BpfProgram&& other) noexcept;
    BpfProgram& operator=(BpfProgram&& other) noexcept;
    virtual ~BpfProgram() noexcept;

    bool loadFilter() noexcept;
    void detachFilter() noexcept;
    bool isLoaded() const noexcept;

    bool openObject() noexcept;
    void closeObject() noexcept;
    int pollEvents(int timeout_ms) noexcept;
    int getProgramFd(const std::string& prog_name) const noexcept;
    int getMapFd(const std::string& map_name) const noexcept;

protected:
    virtual bool attachProgram() noexcept = 0;
    virtual ring_buffer_sample_fn getRingBufferHandler() noexcept = 0;

    bool registerEventHandler() noexcept;
    void releaseRingBuffer() noexcept;
    void detachProgram() noexcept;

    std::string object_path_;
    bpf_object* object_ = nullptr;
    bool loaded_ = false;
    ring_buffer* ring_buffer_ = nullptr;
    std::vector<bpf_link*> links_;
};

}  // namespace https_guard
