#pragma once

#include <cstdint>
#include <vector>

#include "event_meta.hpp"

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
};

}  // namespace https_guard
