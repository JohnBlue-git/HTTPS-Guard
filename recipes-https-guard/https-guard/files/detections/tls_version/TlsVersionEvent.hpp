#pragma once

#include <cstdint>

#include "event_meta.hpp"

namespace https_guard {

/**
 * Everything the TLS-version rule reads, and nothing else.
 *
 * `violation_hint` is not redundant with `tls_version`, and that is the reason
 * this struct has two fields rather than one. The two sources can conclude
 * different things from the same number: a genuinely-parsed wire
 * `legacy_version` of `0x0000` **is** a violation, whereas `tls_version == 0`
 * from a uprobe only means "never observed" — the probe may simply not have
 * resolved `ssl->version`. Collapsing those two zeros shipped as a real bug
 * once, caught in review rather than by the implementer.
 */
struct TlsVersionEvent {
    EventMeta     meta;
    std::uint16_t tls_version    = 0;
    bool          violation_hint = false;
};

}  // namespace https_guard
