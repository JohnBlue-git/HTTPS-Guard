#pragma once

#include "ssl_uprobe_event.h"
#include "uprobe_hg_event.hpp"
#include "bounded_string.hpp"

namespace https_guard {

/**
 * The pure part of turning a raw uprobe_event into this hook's event type
 * — no /proc lookup, no libbpf dependency, just field mapping. Split out
 * from SslUprobeProgram::parseEvent() specifically so it's testable without
 * a real process to resolve sockets for (see tests/test_uprobe_parsing.cpp).
 *
 * Fills in place rather than returning by value: UprobeEvent derives from
 * hg_event, which is non-copyable precisely so a polymorphic event can't be
 * sliced.
 */
inline void parseUprobeEventFields(const uprobe_event& raw, UprobeEvent& evt)
{
    evt.pid         = raw.pid;
    evt.tls_version = raw.tls_version;
    evt.is_inbound  = (raw.direction == HG_UPROBE_DIR_READ);
    evt.process         = boundedString(raw.process);
    evt.payload_snippet = boundedString(raw.payload_snippet);
}

}  // namespace https_guard
