#pragma once

#include <cstddef>
#include <optional>

#include "IDetection.hpp"
#include "IPeerResolver.hpp"
#include "PayloadAnomalyDetector.hpp"
#include "PayloadEvent.hpp"
#include "bounded_string.hpp"
#include "detection_traits.hpp"
#include "event_meta_from.hpp"

namespace https_guard {

/**
 * Attack-signature detection, for any hook that can capture plaintext.
 *
 * Both the uprobe (either side of OpenSSL) and XDP (plaintext HTTP on 443)
 * expose `raw.tls.payload_snippet`, so one template covers both.
 */
template <class RawT>
    requires HasPayloadSnippet<RawT>
class PayloadAnomalyDetection final : public IDetection {
public:
    std::string_view name() const noexcept override { return "payload_anomaly"; }

    explicit PayloadAnomalyDetection(const IPeerResolver* resolver = nullptr) noexcept
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

        PayloadEvent evt;
        evt.meta            = meta;
        evt.payload_snippet = boundedString(raw->tls.payload_snippet);

        return rule_.evaluate(evt);
    }

private:
    const IPeerResolver*   resolver_;
    PayloadAnomalyDetector rule_;
};

}  // namespace https_guard
