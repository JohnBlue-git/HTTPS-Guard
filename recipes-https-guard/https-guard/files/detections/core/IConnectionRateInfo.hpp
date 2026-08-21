#pragma once

#include <cstdint>

namespace https_guard {

/**
 * An event reporting how many connection attempts a source made inside the
 * counting window.
 *
 * Unlike the other capabilities, events carrying this one are synthesised in
 * userspace rather than parsed from a ring-buffer record: the BPF side only
 * maintains counters, and the daemon sweeps them on a timer. See
 * `programs/xdp_tls/ebpf/conn_rate.bpf.h` for why the decision deliberately
 * is not made in BPF.
 */
class IConnectionRateInfo {
public:
    virtual ~IConnectionRateInfo() = default;

    /** Connection attempts (inbound SYNs) counted in the current window. */
    virtual std::uint32_t attemptCount() const noexcept = 0;

    /** Length of that window, in seconds. */
    virtual std::uint32_t windowSeconds() const noexcept = 0;

    /** The threshold that was crossed, so a message can state both numbers. */
    virtual std::uint32_t threshold() const noexcept = 0;
};

}  // namespace https_guard
