#pragma once

#include <cstddef>
#include <memory>
#include <string>
#include <vector>

#include "hg_event_source.h"

/* Forward-declared rather than including <bpf/libbpf.h>: this header only ever
 * names these as pointers, and keeping it libbpf-free means a hook's own header
 * stays light and the classification tree can be built without a kernel. The
 * hooks include libbpf in their own translation units, where it belongs. */
struct bpf_object;
struct bpf_link;

namespace https_guard {

/**
 * One BPF hook family: the uprobe on OpenSSL, the XDP TLS inspector, the LSM
 * certificate guard. A hook attaches its own programs into an already-loaded
 * BPF object, says which raw event source it produces, parses its own records,
 * and hands them to the detection pipeline.
 *
 * WHAT A HOOK DOES *NOT* OWN
 * --------------------------
 * The BPF object, the ring buffer and the poll loop. Those belong to
 * `HttpGuardProgram`, and that is not an accident of history: there is exactly
 * **one** BPF object, **one** ring buffer and **one** blocklist map for the
 * whole daemon. `BlocklistAddAction` writes the map that the XDP program reads,
 * so three hooks each owning an object would mean three blocklist maps and
 * enforcement that silently stopped working.
 *
 * This class used to be that owner, with `HttpGuardProgram` inheriting it --
 * which put the ring-buffer callback for records produced by *hooks* on the one
 * class that is not a hook. Now the inheritance runs the other way: hooks are
 * `BpfProgram`s, and `HttpGuardProgram` holds them.
 *
 * THE RING-BUFFER HANDLER, AND WHY EVERY HOOK OVERRIDES IT
 * -------------------------------------------------------
 * `ringBufferHandler()` submits a record together with **the detections to try
 * against it**, and only the hook knows what those are -- it is the thing that
 * knows what its records can say. So every hook overrides this, and the
 * override is one line:
 *
 *     DetectLoop::getInstance().submit(data, size, detections_);
 *
 * The base implementation exists so a hook under development, or one that only
 * ever wants the traffic-observed report, still works: it submits with an empty
 * list, which `DetectLoop` counts and reports rather than silently dropping.
 *
 * Whatever an override does, it must return promptly.
 *
 * The libbpf-facing trampoline is *not* here, deliberately. `ring_buffer__new()`
 * takes one callback and one context for the whole buffer, so a per-hook static
 * could never be the thing libbpf calls -- there is one shared buffer. The
 * trampoline therefore lives with the buffer's owner, which reads the event
 * source at offset 0 and calls the owning hook's handler. See
 * `HttpGuardProgram::ringBufferCallback()`.
 *
 */
class BpfProgram {
public:
    explicit BpfProgram(std::string name) noexcept;
    virtual ~BpfProgram() = default;

    BpfProgram(const BpfProgram&) = delete;
    BpfProgram& operator=(const BpfProgram&) = delete;

    /** For diagnostics only — never used to decide anything. */
    const std::string& name() const noexcept { return name_; }

    /**
     * Attaches this hook's program(s) to the already-loaded object. Any
     * resulting `bpf_link*` is appended to `links` so the owner can tear
     * everything down uniformly. Returns whether this hook ended up attached;
     * a hook logs its own diagnostics, but whether a failure is fatal overall
     * is the owner's call.
     */
    virtual bool attach(bpf_object* obj, std::vector<bpf_link*>& links) noexcept = 0;

    /**
     * Which raw event source this hook's records carry. The owner uses it to
     * find whose `ringBufferHandler()` to call; `DetectLoop` uses the same word
     * to find the handler that knows how to parse and classify it.
     *
     * A hook does NOT parse its own records. Parsing is part of deciding what
     * an event means, so it lives with the rule that needs it in `detections/` --
     * which also keeps a hook down to the two things only it can do: attach,
     * and hand over bytes.
     */
    virtual hg_event_source eventSource() const noexcept = 0;

    /**
     * What to do with one of this hook's raw records, on the poll thread.
     *
     * Override this to submit the hook's own detection list, in priority order.
     * Keep it to that: a slow callback lets the ring buffer fill, and a full
     * ring buffer drops events with nothing to report it.
     */
    virtual void ringBufferHandler(const void* data, std::size_t size) noexcept;

private:
    std::string name_;
};

}  // namespace https_guard
