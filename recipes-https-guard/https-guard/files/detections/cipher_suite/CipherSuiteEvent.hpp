#pragma once

#include <cstdint>
#include <vector>

#include "event_meta.hpp"
#include "hg_event_source.h"

namespace https_guard {

/**
 * The cipher-suite list a ClientHello offered.
 *
 * `cipher_suites_offered` is the count the client actually sent, which can
 * exceed `cipher_suites.size()`: capture is capped, and reporting both is what
 * lets a clipped list be distinguished from a genuinely short one.
 */
struct CipherSuiteEvent {
    EventMeta                  meta;
    std::vector<std::uint16_t> cipher_suites;
    std::uint16_t              cipher_suites_offered = 0;

    CipherSuiteEvent() = default;

    /** Builds itself from a raw record's `client_hello`, clamping the
     * captured suite count to HG_MAX_CIPHER_SUITES the same way the BPF side
     * capped it when writing the array. */
    template <class RawT>
    CipherSuiteEvent(const EventMeta& meta_in, const RawT& raw)
        : meta(meta_in)
        , cipher_suites_offered(raw.client_hello.cipher_suites_offered)
    {
        const auto&          ch = raw.client_hello;
        const std::uint16_t captured =
            ch.cipher_suite_count < HG_MAX_CIPHER_SUITES ? ch.cipher_suite_count
                                                         : HG_MAX_CIPHER_SUITES;
        cipher_suites.assign(ch.cipher_suites, ch.cipher_suites + captured);
    }
};

}  // namespace https_guard
