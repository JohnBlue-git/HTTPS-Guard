#pragma once

#include <bpf/libbpf.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "BpfProgram.hpp"
#include "ConnRateSweeper.hpp"
#include "IPeerResolver.hpp"

namespace https_guard {

/**
 * Owns the one BPF object, the one ring buffer and the poll loop, and manages
 * the hooks attached into them.
 *
 * WHY IT DOES NOT INHERIT BpfProgram
 * ----------------------------------
 * It used to, which meant the orchestrator inherited a BPF lifecycle it was
 * only half using and supplied the ring-buffer callback for records produced
 * by *hooks* -- the one thing it is not. The relationship is composition:
 * a hook IS a `BpfProgram`; this class HAS several.
 *
 * ONE OBJECT, ONE RING BUFFER, ONE BLOCKLIST MAP
 * ----------------------------------------------
 * All three are singular on purpose and that must not be quietly changed:
 * `BlocklistAddAction` writes the blocklist map that the XDP program reads, so
 * splitting the object per hook would give each its own map and enforcement
 * would stop working while still looking healthy. Hooks therefore attach *into*
 * an object this class opens and loads.
 */
class HttpGuardProgram {
public:
    explicit HttpGuardProgram(std::string object_path,
                              std::vector<std::unique_ptr<BpfProgram>> hooks) noexcept;
    ~HttpGuardProgram() noexcept;

    HttpGuardProgram(const HttpGuardProgram&) = delete;
    HttpGuardProgram& operator=(const HttpGuardProgram&) = delete;

    /** Open, load, attach every hook, and create the shared ring buffer. */
    bool loadFilter() noexcept;
    void detachFilter() noexcept;
    bool isLoaded() const noexcept { return loaded_; }

    int pollEvents(int timeout_ms) noexcept;

    int getProgramFd(const std::string& prog_name) const noexcept;
    int getMapFd(const std::string& map_name) const noexcept;

    /**
     * The one hook that can also resolve a connection tuple from /proc, or
     * nullptr if none can.
     *
     * Found by asking each hook rather than by remembering an index, so
     * reordering the hook list cannot silently hand the wrong object to the
     * uprobe handler. This is the one place a `dynamic_cast` remains, and it is
     * a lifetime question about hooks rather than a classification decision --
     * it runs once, at startup, not per event.
     */
    const IPeerResolver* peerResolver() const noexcept;

    /**
     * Starts connection-rate sweeping. Must be called after loadFilter(),
     * since the counter map only exists once the object is loaded. A zero
     * threshold leaves it disabled.
     */
    void enableRateSweeps(ConnRateSweeper::Thresholds thresholds) noexcept;

private:
    bool openObject() noexcept;
    void closeObject() noexcept;
    bool attachHooks() noexcept;
    bool registerEventHandler() noexcept;
    void releaseRingBuffer() noexcept;
    void destroyLinks() noexcept;

    /**
     * The libbpf-facing trampoline. It lives here rather than on `BpfProgram`
     * because `ring_buffer__new()` takes one callback and one context for the
     * whole buffer, and there is one shared buffer -- so a per-hook static
     * could never be the thing libbpf calls. It reads the event source at
     * offset 0 and dispatches to the owning hook's `ringBufferHandler()`,
     * whose default simply submits.
     */
    static int ringBufferCallback(void* ctx, void* data, std::size_t size) noexcept;
    int dispatchRecord(const void* data, std::size_t size) noexcept;

    /** The hook whose eventSource() matches, or nullptr. */
    BpfProgram* hookFor(std::uint32_t event_source) const noexcept;

    std::string                                   object_path_;
    std::vector<std::unique_ptr<BpfProgram>>      hooks_;
    bpf_object*                                   object_ = nullptr;
    ring_buffer*                                  ring_buffer_ = nullptr;
    std::vector<bpf_link*>                        links_;
    bool                                          loaded_ = false;
    std::uint64_t                                 unknown_source_count_ = 0;
};

}  // namespace https_guard
