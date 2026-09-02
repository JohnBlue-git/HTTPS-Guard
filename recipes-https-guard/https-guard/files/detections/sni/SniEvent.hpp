#pragma once

#include <string>

#include "bounded_string.hpp"
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

    SniEvent() = default;

    /** Builds itself from a raw record's `client_hello`. */
    template <class RawT>
    SniEvent(const EventMeta& meta_in, const RawT& raw)
        : meta(meta_in)
        , sni_present(raw.client_hello.sni_present != 0)
        , sni_malformed(raw.client_hello.sni_malformed != 0)
        , sni_hostname(boundedString(raw.client_hello.sni_hostname))
    {
    }
};

}  // namespace https_guard
