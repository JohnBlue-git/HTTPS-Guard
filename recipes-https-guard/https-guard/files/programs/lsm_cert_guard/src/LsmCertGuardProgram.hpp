#pragma once

#include <array>
#include <string>
#include <utility>
#include <vector>

#include "BpfProgram.hpp"
#include "CertAccessDetection.hpp"
#include "TrafficObservedDetection.hpp"
#include "lsm_cert_guard_event.h"

namespace https_guard {

/**
 * Attaches the BPF-LSM certificate-access guard (see lsm_cert_guard.bpf.h)
 * to the "file_open" LSM hook. Unlike the other hooks, this one needs no
 * runtime configuration (no interface, no library path) — the target
 * file is a compile-time constant inside the BPF program itself, since the
 * path filter has to run there.
 */
class LsmCertGuardProgram final : public BpfProgram {
public:
    /** `allowed_exes` are the executables allowed to open the HTTPS key. */
    explicit LsmCertGuardProgram(std::vector<std::string> allowed_exes) noexcept
        : BpfProgram("lsm_cert_guard")
        , cert_access_(std::move(allowed_exes))
    {
    }

    void ringBufferHandler(const void* data, std::size_t size) noexcept override;

    bool attach(bpf_object* obj, std::vector<bpf_link*>& links) noexcept override;
    hg_event_source eventSource() const noexcept override;
private:
    using Raw = struct lsm_cert_guard_event;

    const CertAccessDetection<Raw>         cert_access_;
    const TrafficObservedDetection<Raw>    traffic_observed_;
    const std::array<const IDetection*, 2> detections_{&cert_access_, &traffic_observed_};
};

}  // namespace https_guard
