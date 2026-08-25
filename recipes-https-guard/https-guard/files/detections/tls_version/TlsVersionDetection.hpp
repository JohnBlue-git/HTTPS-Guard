#pragma once

#include <cstddef>
#include <optional>

#include "IDetection.hpp"
#include "IPeerResolver.hpp"
#include "TlsVersionDetector.hpp"
#include "TlsVersionEvent.hpp"
#include "detection_traits.hpp"
#include "event_meta_from.hpp"

namespace https_guard {

/**
 * TLS-version detection, for any hook whose raw record carries a TLS version.
 *
 * Templated on the raw struct rather than duplicated per hook: both the uprobe
 * and XDP layouts expose `raw.tls.version`, so the parse is one expression, and
 * the two places they genuinely differ — a connection tuple, and a line-rate
 * violation hint — are read only where they exist.
 */
template <class RawT>
    requires HasTlsFields<RawT>
class TlsVersionDetection final : public IDetection {
public:
    std::string_view name() const noexcept override { return "tls_version"; }

    /**
     * `resolver` is for sources that arrive without a connection tuple (the
     * uprobe). Non-owning, and null for sources that do not need it.
     */
    explicit TlsVersionDetection(const IPeerResolver* resolver = nullptr) noexcept
        : resolver_(resolver)
    {
    }

    std::optional<Verdict> inspect(const void* data, std::size_t size,
                                   EventMeta& meta) const override
    {
        if (data == nullptr || size < sizeof(RawT)) {
            return std::nullopt;
        }
        const auto* raw = static_cast<const RawT*>(data);

        fillEnvelope(*raw, meta);
        if constexpr (HasConnectionTuple<RawT>) {
            fillConnection(raw->conn, meta);
        } else {
            meta.peer_resolver = resolver_;
        }

        TlsVersionEvent evt;
        evt.meta        = meta;
        evt.tls_version = raw->tls.version;
        if constexpr (HasViolationHint<RawT>) {
            evt.violation_hint = (raw->tls.is_violation != 0);
        }

        return rule_.evaluate(evt);
    }

private:
    const IPeerResolver* resolver_;
    TlsVersionDetector   rule_;
};

}  // namespace https_guard
