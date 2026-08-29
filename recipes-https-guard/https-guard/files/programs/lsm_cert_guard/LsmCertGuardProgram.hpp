#pragma once

#include "IHookModule.hpp"

namespace https_guard {

/**
 * Attaches the BPF-LSM certificate-access guard (see lsm_cert_guard.bpf.h)
 * to the "file_open" LSM hook. Unlike the other hooks, this one needs no
 * runtime configuration (no interface, no library path) — the target
 * file and expected binary are compile-time constants inside the BPF
 * program itself, since the identity check has to run there.
 */
class LsmCertGuardProgram final : public IHookModule {
public:
    bool attach(bpf_object* obj, std::vector<bpf_link*>& links) noexcept override;
    hg_event_source eventSource() const noexcept override;
    std::optional<hg_event> parseEvent(const void* data, size_t size) const noexcept override;
};

}  // namespace https_guard
