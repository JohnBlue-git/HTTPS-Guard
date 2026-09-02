#pragma once

#include <cstdint>
#include <string>
#include <utility>

#include "event_meta.hpp"

namespace https_guard {

/**
 * An open() of the BMC's HTTPS certificate or private key.
 *
 * Satisfies CertAccessEventLike. Two identity signals exist and they are
 * deliberately not merged: `meta.process` is the self-reported comm the BPF
 * side saw, and `identity_mismatch` comes from the accessing process's *real*
 * executable, resolved in userspace via /proc/<pid>/exe. They can disagree, and
 * which one a reader is looking at matters — only the second is worth acting on.
 */
struct CertAccessEvent {
    EventMeta meta;

    /** From /proc/<pid>/exe — the strong check. */
    bool        identity_mismatch = false;
    std::string real_exe_path;

    /** Whether the in-kernel decision was observe-only. */
    bool shadow_mode = false;

    std::uint64_t cgroup_id = 0;

    CertAccessEvent() = default;

    /** Builds itself from a raw record's `cert` fields, plus the two signals
     * that can only be resolved in userspace — the real executable path and
     * whether it matches an allow-list — since neither one is something a
     * raw record can carry. */
    template <class RawT>
    CertAccessEvent(const EventMeta& meta_in, const RawT& raw,
                     std::string real_exe_path_in, bool identity_mismatch_in)
        : meta(meta_in)
        , identity_mismatch(identity_mismatch_in)
        , real_exe_path(std::move(real_exe_path_in))
        , shadow_mode(raw.cert.shadow_mode != 0)
        , cgroup_id(raw.cert.cgroup_id)
    {
    }
};

}  // namespace https_guard
