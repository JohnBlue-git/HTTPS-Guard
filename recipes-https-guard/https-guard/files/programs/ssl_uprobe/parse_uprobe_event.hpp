#pragma once

#include "ssl_uprobe_event.h"
#include "hg_event.hpp"
#include "bounded_string.hpp"

namespace https_guard {

/**
 * The pure part of turning a raw uprobe_event into the common event
 * representation — no /proc lookup, no libbpf dependency, just field
 * mapping. Split out from SslUprobeProgram::parseEvent() specifically so
 * it's testable without a real process to resolve sockets for (see
 * tests/test_uprobe_parsing.cpp).
 */
inline hg_event parseUprobeEventFields(const uprobe_event& raw)
{
    hg_event evt{};
    evt.pid         = raw.pid;
    evt.tls_version = raw.tls_version;
    evt.is_inbound  = (raw.direction == HG_UPROBE_DIR_READ);
    evt.process         = boundedString(raw.process);
    evt.payload_snippet = boundedString(raw.payload_snippet);
    return evt;
}

}  // namespace https_guard
