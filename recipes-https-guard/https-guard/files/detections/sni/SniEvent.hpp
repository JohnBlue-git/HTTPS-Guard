#pragma once

#include <string>

#include "event_meta.hpp"

namespace https_guard {

/**
 * The SNI extension as parsed from a ClientHello.
 *
 * `sni_malformed` is checked before `sni_hostname` is ever compared: a truncated
 * name must never be compared as though complete, or a clipped capture could
 * produce a false mismatch or — worse — a false match.
 */
struct SniEvent {
    EventMeta   meta;
    bool        sni_present   = false;
    bool        sni_malformed = false;
    std::string sni_hostname;
};

}  // namespace https_guard
