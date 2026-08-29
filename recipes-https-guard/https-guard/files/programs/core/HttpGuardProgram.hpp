#pragma once

#include <chrono>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "BpfProgram.hpp"
#include "DetectLoop.hpp"
#include "IDetector.hpp"
#include "IHookModule.hpp"
#include "hg_event_source.h"
#include "core/ActionLoop.hpp"

namespace https_guard {

class HttpGuardProgram final : public BpfProgram {
public:
    // Keyed by hg_event_source (HG_SOURCE_UPROBE / HG_SOURCE_XDP). Each
    // event source's detectors run in order; the first one that matches
    // wins. Built by the composition root (main.cpp) and injected here —
    // this class never constructs a concrete detector itself.
    // Owned by DetectLoop now; aliased here so the composition root's
    // vocabulary doesn't change.
    using DetectorRegistry = DetectLoop::DetectorRegistry;

    // hooks: one entry per BPF hook family (uprobe, XDP, ...), also built
    // and injected by main.cpp. This class knows nothing about SSL_write,
    // ifindex, or any other hook-specific detail — only the IHookModule
    // interface — so a new hook never requires a change here.
    HttpGuardProgram(std::string object_path,
                     ActionLoop& action_loop,
                     std::vector<std::unique_ptr<IHookModule>> hooks,
                     std::chrono::seconds blocklist_ttl,
                     std::string output_path,
                     DetectorRegistry detectors) noexcept;

protected:
    bool attachProgram() noexcept override;
    ring_buffer_sample_fn getRingBufferHandler() noexcept override;

private:
    /**
     * Copies the record and hands it to detect_loop_ -- nothing more. All
     * parsing, /proc access, classification and action construction happen
     * on the DetectLoop worker, because libbpf needs this callback back
     * promptly: a slow callback lets the ring buffer fill, and a full ring
     * buffer drops events silently.
     */
    int ringBufferHandler(void* data, size_t size) noexcept;
    static int ringBufferCallback(void* ctx, void* data, size_t size) noexcept;

    // Declaration order matters: detect_loop_ holds a reference to hooks_,
    // so hooks_ must outlive it. Members are destroyed in reverse order, so
    // detect_loop_ (declared last) is torn down first.
    ActionLoop& action_loop_;
    std::vector<std::unique_ptr<IHookModule>> hooks_;
    DetectLoop detect_loop_;
};

}  // namespace https_guard
