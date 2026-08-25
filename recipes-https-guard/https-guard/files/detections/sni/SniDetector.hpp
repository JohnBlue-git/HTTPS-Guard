#pragma once

#include <algorithm>
#include <optional>
#include <string>

#include "SniEvent.hpp"
#include "Verdict.hpp"

namespace https_guard {

/**
 * Flags an anomalous SNI (Server Name Indication) hostname in a ClientHello.
 *
 * **What counts as anomalous here, and why it's deliberately narrow.** A BMC
 * is overwhelmingly reached by IP address, and a client connecting by IP
 * sends *no* SNI at all — so "SNI absent" is the common, healthy case and is
 * never flagged. Nor is every mismatch worth flagging: a BMC legitimately
 * answers to any DNS name that resolves to it, so comparing SNI against the
 * BMC's own hostname would fire on every connection through a CNAME or a
 * site-specific DNS alias. A detector that noisy gets ignored, which is
 * worse than not having it.
 *
 * So only two things are flagged:
 *   1. A malformed ClientHello / SNI structure (`sni_malformed`) — no
 *      legitimate client produces one, and it's a common fingerprint of
 *      scanners and handcrafted probe packets. Always checked.
 *   2. An SNI that doesn't match an explicitly configured expected hostname
 *      — opt-in only, via `HTTPS_GUARD_EXPECTED_SNI`. Left unset (the
 *      default), this detector only does (1).
 *
 * Comparison is case-insensitive, since DNS names are.
 *
 * **Not actionable**, for the same reason as `CipherSuiteDetector` (see its
 * class comment for the incident that established this): the blocklist is
 * enforced in XDP per source IP across every port, so treating an SNI
 * anomaly as actionable would let one odd hostname lock an administrator
 * out of SSH and everything else on the BMC. An unexpected hostname is
 * worth an alert, not a lockout.
 *
 * XDP-only: no other hook sees ClientHello bytes at all.
 */
class SniDetector {
public:
    explicit SniDetector(std::string expected_hostname = {})
        : expected_hostname_(toLower(std::move(expected_hostname)))
    {
    }

    std::optional<Verdict> evaluate(const SniEvent& evt) const
    {
        if (evt.sni_malformed) {
            return makeVerdict(evt.meta,
                "malformed or over-long SNI/ClientHello structure"
                " — no standard client produces this");
        }

        if (!evt.sni_present || expected_hostname_.empty()) {
            return std::nullopt;
        }

        if (toLower(evt.sni_hostname) == expected_hostname_) {
            return std::nullopt;
        }

        return makeVerdict(evt.meta,
            "SNI hostname '" + evt.sni_hostname + "' does not match the expected '" +
            expected_hostname_ + "'");
    }

private:
    std::optional<Verdict> makeVerdict(const EventMeta& meta, const std::string& detail) const
    {
        Verdict verdict;
        verdict.severity   = "Warning";
        verdict.message_id = "OemSecurityEvent.1.0.HttpsSniAnomalyDetected";
        verdict.message    = "SNI anomaly from " +
                             (meta.source_ip.empty() ? std::string("an unidentified peer")
                                                     : meta.source_ip) +
                             ": " + detail + ".";
        verdict.actionable = false;  // see the class comment — blocklisting on this is a DoS risk
        return verdict;
    }

    static std::string toLower(std::string value)
    {
        std::transform(value.begin(), value.end(), value.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return value;
    }

    std::string expected_hostname_;
};

}  // namespace https_guard
