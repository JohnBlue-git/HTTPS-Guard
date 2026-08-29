#pragma once

#include <cstddef>
#include <optional>
#include <vector>

#include <bpf/libbpf.h>

#include "hg_event.hpp"
#include "hg_event_source.h"

namespace https_guard {

/**
 * One BPF hook family (e.g. the OpenSSL uprobe, the XDP TLS inspector).
 * Owns attaching its own BPF program(s) to the shared object and parsing
 * its own raw ring-buffer event into the daemon's common event
 * representation. Does NOT classify events (see detectors/) or dispatch
 * enforcement actions (see actions/) — purely attach + parse, matching
 * the same "BPF is observational, userspace decides" split already
 * applied to the kernel side, one layer up.
 */
class IHookModule {
public:
    virtual ~IHookModule() = default;

    /**
     * Attaches this hook's BPF program(s) to the already-loaded object.
     * Any resulting bpf_link* is appended to `links` so the orchestrator
     * can tear it down uniformly later. Returns whether this hook ended
     * up attached; a hook module logs its own diagnostics, but whether
     * a failure here is fatal overall is the orchestrator's call.
     */
    virtual bool attach(bpf_object* obj, std::vector<bpf_link*>& links) noexcept = 0;

    /** Which hg_event_source (see hg_event_source.h) this hook's raw events carry. */
    virtual hg_event_source eventSource() const noexcept = 0;

    /**
     * Parses a raw ring-buffer event produced by this hook into the
     * common event representation. Returns std::nullopt if `size` is too
     * small for this hook's raw struct (a malformed/truncated event).
     */
    virtual std::optional<hg_event> parseEvent(const void* data, size_t size) const noexcept = 0;
};

}  // namespace https_guard
