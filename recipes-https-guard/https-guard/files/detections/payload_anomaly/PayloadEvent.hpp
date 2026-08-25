#pragma once

#include <string>

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
};

}  // namespace https_guard
