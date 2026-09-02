#pragma once

#include <optional>
#include <string>

#include "CertAccessEvent.hpp"
#include "Verdict.hpp"

namespace https_guard {

/**
 * Flags an access to the BMC's HTTPS certificate/key file by a process
 * other than bmcweb, based on the in-kernel identity check already
 * performed by the LSM cert-access-guard hook (see
 * programs/lsm_cert_guard/lsm_cert_guard.bpf.h) — this detector only
 * turns that already-made determination into a Verdict, it does not
 * re-derive it.
 *
 * Not actionable: unlike the network-facing detectors, there is no TCP
 * 4-tuple to blocklist for a local file access, and the only real
 * "enforcement" for this event (denying the open) already happened — or
 * didn't, in shadow mode — synchronously in the BPF hook itself, before
 * this detector ever ran.
 */
class CertAccessDetector {
public:
    std::optional<Verdict> evaluate(const CertAccessEvent& evt) const
    {
        if (!evt.identity_mismatch)
        {
            return std::nullopt;
        }

        Verdict verdict;
        verdict.severity   = "Critical";
        verdict.message_id = "OemSecurityEvent.1.0.HttpsCertificateAccessViolation";
        verdict.message    = "Security violation: process '" + evt.meta.process +
                             "' (PID " + std::to_string(evt.meta.pid) +
                             ", real executable '" + evt.real_exe_path +
                             "', cgroup " + std::to_string(evt.cgroup_id) +
                             ") accessed the BMC's HTTPS certificate/key file; expected only bmcweb or "
                             "phosphor-certificate-manager to do so." +
                             (evt.shadow_mode
                                  ? " Shadow mode: access was observed but not blocked."
                                  : " Access was denied.");
        verdict.actionable = false;
        return verdict;
    }
};

}  // namespace https_guard
