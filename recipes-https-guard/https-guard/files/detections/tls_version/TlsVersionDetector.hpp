#pragma once

#include <optional>
#include <string>

#include "Verdict.hpp"
#include "TlsVersionEvent.hpp"
#include "tls_version.hpp"

namespace https_guard {

/**
 * Flags TLS below 1.2, either because the version says so or because the
 * producing hook already determined it on the wire.
 *
 * Bound to the TlsTrafficEvent *concept*, not to a hook and not to an
 * interface: both the uprobe and the XDP path satisfy it, and neither is named
 * here. An event that cannot describe TLS traffic is now a compile error at the
 * call site rather than a silent runtime decline.
 */
class TlsVersionDetector {
public:
    std::optional<Verdict> evaluate(const TlsVersionEvent& evt) const
    {
        /* violation_hint first, and separately from the numeric test, because
         * the two producers can conclude different things from the same zero --
         * see TlsVersionEvent.hpp. */
        const bool violation = evt.violation_hint ||
                               (evt.tls_version > 0 && evt.tls_version < 0x0303);
        if (!violation)
        {
            return std::nullopt;
        }

        Verdict verdict;
        verdict.severity   = "Critical";
        verdict.message_id = "OemSecurityEvent.1.0.HttpsTlsVersionViolation";
        verdict.message    = "Security violation: Process '" + evt.meta.process +
                             "' (PID " + std::to_string(evt.meta.pid) +
                             ") attempted an HTTPS connection using an insecure TLS version (" +
                             TlsVersion(evt.tls_version).toString() + "). Packet was blocked.";
        verdict.actionable = true;
        return verdict;
    }
};

}  // namespace https_guard
