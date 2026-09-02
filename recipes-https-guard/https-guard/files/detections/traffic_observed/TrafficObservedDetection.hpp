#pragma once

#include <cstddef>
#include <optional>
#include <string>

#include "IDetection.hpp"
#include "detection_traits.hpp"
#include "event_meta_from.hpp"
#include "tls_version.hpp"

namespace https_guard {

/**
 * The "nothing matched" report, as a detection that always matches.
 *
 * Lives in its own directory rather than in core/ because it *is* a detection:
 * it implements `IDetection`, it appears in every hook's list, and it emits a
 * message ID the README documents alongside the other eight. Keeping it in
 * `core/` made it the one concrete detection hiding among the shared vocabulary.
 *
 * Put **last** in a hook's list and first-match-wins does the rest: no branch in
 * `DetectLoop`, no special case anywhere, and no class that knows both "run the
 * rules" and "what if none fired". It is not a rule — there is nothing to detect
 * in the absence of a detection — which is exactly why expressing it as the
 * terminal element of the list rather than as logic is the honest shape.
 *
 * Reports the TLS version where the source has one, and `n/a` where it does not
 * (a certificate file open has no TLS version, and printing 0 would read like
 * one).
 */
template <class RawT>
class TrafficObservedDetection final : public IDetection {
public:
    std::string_view name() const noexcept override { return "traffic_observed"; }

    explicit TrafficObservedDetection(const IPeerResolver* resolver = nullptr) noexcept
        : resolver_(resolver)
    {
    }

    std::optional<Verdict> inspect(const void* data, std::size_t size,
                                   EventMeta& meta) const override
    {
        if (data == nullptr || size < sizeof(RawT))
        {
            return std::nullopt;
        }
        const auto* raw = static_cast<const RawT*>(data);

        fillEnvelope(*raw, meta);
        if constexpr (HasConnectionTuple<RawT>)
        {
            fillConnection(raw->conn, meta);
        }
        else
        {
            meta.peer_resolver = resolver_;
        }

        std::string tls_desc = "n/a";
        if constexpr (HasTlsFields<RawT>)
        {
            tls_desc = TlsVersion(raw->tls.version).toString();
        }

        Verdict verdict;
        verdict.severity   = "OK";
        verdict.message_id = "OemSecurityEvent.1.0.HttpsTrafficObserved";
        verdict.message    = "HTTPS traffic observed from process '" + meta.process +
                             "' (PID " + std::to_string(meta.pid) +
                             "), TLS version: " + tls_desc;
        return verdict;
    }

private:
    const IPeerResolver* resolver_;
};

}  // namespace https_guard
