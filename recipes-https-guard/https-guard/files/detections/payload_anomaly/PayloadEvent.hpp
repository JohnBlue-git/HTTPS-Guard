#pragma once

#include <string>

#include "bounded_string.hpp"
#include "event_meta.hpp"

namespace https_guard {

/**
 * The plaintext prefix the signature rule matches against.
 *
 * Capped by the producing hook at 127 bytes per call — a signature falling
 * entirely past that offset is not seen. Recorded in LIMITATIONS.md rather than
 * papered over.
 */
struct PayloadEvent {
    EventMeta   meta;
    std::string payload_snippet;

    PayloadEvent() = default;

    /** Builds itself from a raw record's `tls.payload_snippet`. */
    template <class RawT>
    PayloadEvent(const EventMeta& meta_in, const RawT& raw)
        : meta(meta_in)
        , payload_snippet(boundedString(raw.tls.payload_snippet))
    {
    }
};

}  // namespace https_guard
