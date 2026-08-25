#pragma once

#include <string>

#include <array>

#include "BpfProgram.hpp"
#include "PayloadAnomalyDetection.hpp"
#include "TlsVersionDetection.hpp"
#include "TrafficObservedDetection.hpp"
#include "ssl_uprobe_event.h"
#include "IPeerResolver.hpp"

namespace https_guard {

/**
 * Attaches the OpenSSL SSL_write uprobe (the PRIMARY detection mechanism
 * on BMC platforms where XDP may not be available — see ssl_uprobe.bpf.h)
 * plus its SSL_read mirror (request-side data; a non-fatal bonus if it
 * fails to attach), and parses either direction's raw uprobe_event into
 * the common event representation, resolving the PID to a socket 4-tuple
 * via /proc along the way.
 */
class SslUprobeProgram final : public BpfProgram, public IPeerResolver {
public:
    explicit SslUprobeProgram(std::string openssl_lib_path) noexcept;

    /**
     * Submits a record with the detections this hook can feed, in priority
     * order. TLS version first because it is Critical and the more specific
     * claim; the traffic-observed report is last and always matches, so
     * first-match-wins needs no fallback branch anywhere.
     *
     * No ClientHello detections: a uprobe fires after the handshake, so there
     * is nothing left to parse -- and `CipherSuiteDetection`'s `requires`
     * clause means naming it here would not compile.
     */
    void ringBufferHandler(const void* data, std::size_t size) noexcept override;

    bool attach(bpf_object* obj, std::vector<bpf_link*>& links) noexcept override;
    hg_event_source eventSource() const noexcept override;

    /**
     * IPeerResolver: reads /proc to identify the connection this event's
     * process is using. Called on demand via EventMeta::ensurePeerResolved(),
     * not during parseEvent -- see IPeerResolver.hpp for why.
     */
    bool resolvePeer(EventMeta& meta) const noexcept override;

private:
    using Raw = struct uprobe_event;

    /* Owned here, so the pointers submitted with each record stay valid for as
     * long as the loop might inspect it. Stateless and const, so the two
     * DetectLoop threads can run them concurrently. */
    const TlsVersionDetection<Raw>          tls_version_{this};
    const PayloadAnomalyDetection<Raw>      payload_anomaly_{this};
    const TrafficObservedDetection<Raw>     traffic_observed_{this};
    const std::array<const IDetection*, 3>  detections_{
        &tls_version_, &payload_anomaly_, &traffic_observed_};

    std::string openssl_lib_path_;
};

}  // namespace https_guard
