#pragma once

#include <array>
#include <string>

#include "BpfProgram.hpp"
#include "CipherSuiteDetection.hpp"
#include "PayloadAnomalyDetection.hpp"
#include "SniDetection.hpp"
#include "TlsVersionDetection.hpp"
#include "TrafficObservedDetection.hpp"
#include "xdp_tls_event.h"

namespace https_guard {

/**
 * Attaches the XDP TLS inspector (AUXILIARY — see xdp_tls.bpf.h), and
 * non-fatally gives up if XDP isn't available at all. Parses its raw
 * xdp_event into the common event representation; unlike the uprobe,
 * socket info is already available directly from the packet headers.
 *
 * ATTACHMENT LIFETIME
 * -------------------
 * Prefers a **BPF link** (`bpf_program__attach_xdp`), because the kernel
 * then owns the attachment's lifetime: when the link's fd closes — on
 * clean exit, on a crash, even on SIGKILL — the program is detached
 * automatically.
 *
 * That matters because the legacy `bpf_xdp_attach()` path does the
 * opposite: the attachment belongs to the *netdev* and outlives the
 * process entirely. The daemon used to attach that way and never detach,
 * so every restart hit "XDP program already attached" and silently ran
 * without any wire-level detection until the BMC was rebooted — while
 * still reporting itself healthy. Links make that class of leak
 * impossible rather than merely cleaned up.
 *
 * The legacy path is still kept as a fallback for kernels without XDP
 * link support, and in that case this class detaches in its destructor
 * (which covers clean shutdown, though not a crash — an unavoidable
 * limitation of that API, and the reason it isn't the first choice).
 */
class XdpTlsProgram final : public BpfProgram {
public:
    /** `expected_sni` empty disables SNI hostname-mismatch checking. */
    XdpTlsProgram(unsigned int ifindex, std::string expected_sni) noexcept;

    /**
     * Submits a record with the four detections this hook can feed, in priority
     * order: the two enforcing ones first, then the two alert-only ClientHello
     * ones, then the always-matching traffic-observed report.
     *
     * That order matters and is a real decision. A ClientHello can satisfy
     * several of these at once, and only the first verdict is emitted -- so a
     * legacy-TLS ClientHello that also offers RC4 is reported as the TLS
     * violation, which enforces, rather than as the weak suite, which does not.
     */
    void ringBufferHandler(const void* data, std::size_t size) noexcept override;
    ~XdpTlsProgram() noexcept override;

    bool attach(bpf_object* obj, std::vector<bpf_link*>& links) noexcept override;
    hg_event_source eventSource() const noexcept override;

private:
    using Raw = struct xdp_event;

    /* Owned here so the pointers submitted with each record outlive the async
     * hop. Const and stateless, so DetectLoop's two threads can run them
     * concurrently. */
    const TlsVersionDetection<Raw>         tls_version_;
    const PayloadAnomalyDetection<Raw>     payload_anomaly_;
    const CipherSuiteDetection<Raw>        cipher_suite_;
    const SniDetection<Raw>                sni_;
    const TrafficObservedDetection<Raw>    traffic_observed_;
    const std::array<const IDetection*, 5> detections_{
        &tls_version_, &payload_anomaly_, &cipher_suite_, &sni_, &traffic_observed_};

    /**
     * Clears an attachment left behind by a previous instance of *this*
     * daemon, and only that.
     *
     * Identifies the attached program by name before touching it: a
     * leaked `https_guard_xdp` is ours to remove, but anything else
     * belongs to another tool sharing the interface and must be left
     * alone — force-detaching whatever happens to be there would trade
     * our own outage for someone else's.
     */
    void clearStaleAttachment() noexcept;

    unsigned int ifindex_;
    /* Only set when the legacy (non-link) path was used, since that is
     * the only case with an attachment this process must clean up. */
    bool owns_legacy_attachment_ = false;
};

}  // namespace https_guard
