#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <utility>

#include "IDetection.hpp"
#include "SniDetector.hpp"
#include "SniEvent.hpp"
#include "detection_traits.hpp"
#include "event_meta_from.hpp"

namespace https_guard {

/**
 * SNI detection. Malformed structure always fires; hostname mismatch only when
 * an expected name is configured, because there is no safe default — a BMC's
 * hostname is a deployment fact, and guessing it would alert on everything or
 * nothing.
 */
template <class RawT>
    requires HasClientHello<RawT> && HasConnectionTuple<RawT>
class SniDetection final : public IDetection {
public:
    std::string_view name() const noexcept override { return "sni"; }

    explicit SniDetection(std::string expected_hostname) noexcept
        : rule_(std::move(expected_hostname))
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
        fillConnection(raw->conn, meta);

        const SniEvent evt(meta, *raw);

        return rule_.evaluate(evt);
    }

private:
    SniDetector rule_;
};

}  // namespace https_guard
