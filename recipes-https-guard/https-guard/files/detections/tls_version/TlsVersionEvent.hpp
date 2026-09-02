#pragma once

#include <cstdint>

#include "detection_traits.hpp"
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

    TlsVersionEvent() = default;

    /** Builds itself from a raw record. `violation_hint` is left at its
     * default for a source with no line-rate hint (the uprobe). */
    template <class RawT>
    TlsVersionEvent(const EventMeta& meta_in, const RawT& raw)
        : meta(meta_in)
        , tls_version(raw.tls.version)
    {
        if constexpr (HasViolationHint<RawT>)
        {
            violation_hint = (raw.tls.is_violation != 0);
        }
    }
};

}  // namespace https_guard
