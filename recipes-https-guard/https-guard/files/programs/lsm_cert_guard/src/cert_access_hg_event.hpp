#pragma once

#include <cstdint>
#include <string>

#include "hg_event.hpp"
#include "ICertAccessInfo.hpp"

namespace https_guard {

/**
 * What a certificate-access event carries beyond the universal fields.
 *
 * Supplies ICertAccessInfo only. It has no TLS version, no payload and no
 * ClientHello, because a file open has none of those — the previous
 * all-in-one event claimed all three anyway, which is the kind of untruth
 * this split removes.
 */
class CertAccessEvent final : public hg_event, public ICertAccessInfo {
public:
    bool          identity_mismatch = false;
    bool          shadow_mode       = true;
    std::uint64_t cgroup_id         = 0;
    std::string   real_exe_path;

    bool identityMismatch() const noexcept override { return identity_mismatch; }
    bool shadowMode() const noexcept override { return shadow_mode; }
    std::uint64_t cgroupId() const noexcept override { return cgroup_id; }
    const std::string& realExePath() const noexcept override { return real_exe_path; }
};

}  // namespace https_guard
