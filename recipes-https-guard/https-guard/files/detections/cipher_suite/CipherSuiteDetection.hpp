#pragma once

#include <cstddef>
#include <optional>

#include "CipherSuiteDetector.hpp"
#include "CipherSuiteEvent.hpp"
#include "IDetection.hpp"
#include "detection_traits.hpp"
#include "event_meta_from.hpp"

namespace https_guard {

/**
 * Weak-cipher-suite detection. Only a hook that parses ClientHellos can feed
 * this — the `requires` clause says so, so registering it against a source that
 * cannot is a build error rather than a rule that never fires.
 */
template <class RawT>
    requires HasClientHello<RawT> && HasConnectionTuple<RawT>
class CipherSuiteDetection final : public IDetection {
public:
    std::string_view name() const noexcept override { return "cipher_suite"; }

    std::optional<Verdict> inspect(const void* data, std::size_t size,
                                   EventMeta& meta) const override
    {
        if (data == nullptr || size < sizeof(RawT)) {
            return std::nullopt;
        }
        const auto* raw = static_cast<const RawT*>(data);

        fillEnvelope(*raw, meta);
        fillConnection(raw->conn, meta);

        const auto& ch = raw->client_hello;
        const std::uint16_t captured =
            ch.cipher_suite_count < HG_MAX_CIPHER_SUITES ? ch.cipher_suite_count
                                                         : HG_MAX_CIPHER_SUITES;

        CipherSuiteEvent evt;
        evt.meta = meta;
        evt.cipher_suites.assign(ch.cipher_suites, ch.cipher_suites + captured);
        evt.cipher_suites_offered = ch.cipher_suites_offered;

        return rule_.evaluate(evt);
    }

private:
    CipherSuiteDetector rule_;
};

}  // namespace https_guard
