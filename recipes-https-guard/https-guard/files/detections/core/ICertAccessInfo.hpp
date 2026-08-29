#pragma once

#include <cstdint>
#include <string>

namespace https_guard {

/**
 * An event describing an access to the BMC's HTTPS certificate/key file,
 * with the accessing process's resolved identity.
 *
 * Supplied by `lsm_cert_guard`. Note the identity check behind
 * `identityMismatch()` is performed in userspace from
 * `/proc/<pid>/exe`, not in BPF — see that hook's DESIGN.md for why the
 * in-kernel version is unreachable on this hardware.
 */
class ICertAccessInfo {
public:
    virtual ~ICertAccessInfo() = default;

    /** True when the real executable was not the expected bmcweb binary. */
    virtual bool identityMismatch() const noexcept = 0;

    /** True when the hook only observed, and did not deny, the access. */
    virtual bool shadowMode() const noexcept = 0;

    virtual std::uint64_t cgroupId() const noexcept = 0;

    /** Resolved from /proc/<pid>/exe; empty if the process already exited. */
    virtual const std::string& realExePath() const noexcept = 0;
};

}  // namespace https_guard
