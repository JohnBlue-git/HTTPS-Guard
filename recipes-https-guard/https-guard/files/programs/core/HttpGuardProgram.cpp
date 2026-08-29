#include <iostream>
#include <memory>
#include <optional>
#include <utility>

#include "HttpGuardProgram.hpp"
#include "hg_event.hpp"
#include "Verdict.hpp"
#include "tls_version.hpp"
#include "redfish_event_message.hpp"
#include "log/LogAction.hpp"
#include "blocklist/Blocklist.hpp"
#include "blocklist/BlocklistAction.hpp"
#include "tcp/BlockTcpAction.hpp"

namespace https_guard {

HttpGuardProgram::HttpGuardProgram(std::string object_path,
                                   ActionLoop& action_loop,
                                   std::vector<std::unique_ptr<IHookModule>> hooks,
                                   std::chrono::seconds blocklist_ttl,
                                   std::string output_path,
                                   DetectorRegistry detectors) noexcept
    : BpfProgram(std::move(object_path))
    , action_loop_(action_loop)
    , hooks_(std::move(hooks))
    , detectors_(std::move(detectors))
    , blocklist_ttl_(blocklist_ttl)
    , output_path_(std::move(output_path))
{
}

bool HttpGuardProgram::attachProgram() noexcept
{
    int attached_count = 0;
    for (auto& hook : hooks_) {
        if (hook->attach(object_, links_)) {
            ++attached_count;
        }
    }

    // Require at least one enforcement path. Which hooks are actually
    // required vs. auxiliary is each hook's own attach() diagnostics to
    // log (see SslUprobeProgram/XdpTlsProgram) — this class only needs
    // to know whether *anything* ended up attached.
    if (attached_count == 0) {
        std::cerr << "https_guard: no hook could be attached\n";
        return false;
    }

    std::cout << "https_guard: enforcement active via " << attached_count
              << " of " << hooks_.size() << " hook(s)\n";

    /* Adopt the blocklist map so ringBufferHandler can populate it after
     * classifying an event.  This is the only "countermeasure" touch
     * point in the attach path -- everything else stays observational. */
    if (!Blocklist::instance().adopt(getMapFd(kBlocklistMapName))) {
        std::cerr << "https_guard: failed to adopt blocklist map '"
                  << kBlocklistMapName << "' (countermeasure disabled)\n";
        /* Non-fatal: the daemon still works in pure observational mode. */
    }
    return true;
}

ring_buffer_sample_fn HttpGuardProgram::getRingBufferHandler() noexcept
{
    return &HttpGuardProgram::ringBufferCallback;
}

int HttpGuardProgram::ringBufferHandler(void* data, size_t size) noexcept
{
    if (size < sizeof(uint32_t)) {
        std::cerr << "https_guard: ringbuffer callback: undersized event (" << size << " bytes)\n";
        return 0;
    }

    const auto event_source = static_cast<hg_event_source>(*static_cast<const uint32_t*>(data));

    const IHookModule* owning_hook = nullptr;
    for (const auto& hook : hooks_) {
        if (hook->eventSource() == event_source) {
            owning_hook = hook.get();
            break;
        }
    }

    if (!owning_hook) {
        std::cerr << "https_guard: unknown event_source=" << event_source
                  << ", size=" << size << ", skipping\n";
        return 0;
    }

    std::optional<hg_event> parsed = owning_hook->parseEvent(data, size);
    if (!parsed) {
        return 0;
    }
    const hg_event evt = std::move(*parsed);

    /* Run the detectors registered for this event source, in order,
     * stopping at the first match — same priority as before (TLS version
     * violation checked ahead of payload anomalies). No match means
     * normal traffic. */
    Verdict verdict;
    bool matched = false;
    if (auto it = detectors_.find(event_source); it != detectors_.end()) {
        for (const auto& detector : it->second) {
            if (auto v = detector->evaluate(evt)) {
                verdict = std::move(*v);
                matched = true;
                break;
            }
        }
    }

    if (!matched) {
        verdict.severity   = "OK";
        verdict.message_id = "OemSecurityEvent.1.0.HttpsTrafficObserved";
        verdict.message    = "HTTPS traffic observed from process '" + evt.process +
                             "' (PID " + std::to_string(evt.pid) +
                             "), TLS version: " + TlsVersion(evt.tls_version).toString();
    }

    if (verdict.actionable)
    {
        if (evt.src_ip_v4 != 0)
        {
            // Unified path for both XDP (socket from BPF) and uprobe (socket
            // resolved from /proc).  Kill the connection and blocklist the source.

            // BlockTcpAction
            action_loop_.pushAction(
                std::make_unique<BlockTcpAction>(
                evt.src_ip_v4,
                evt.dst_ip_v4,
                evt.src_port,
                evt.dst_port,
                verdict.message));

            // BlocklistAddAction
            action_loop_.pushAction(
                std::make_unique<BlocklistAddAction>(
                evt.src_ip_v4,
                blocklist_ttl_,
                verdict.message));
        }
        else
        {
            std::cerr << "https_guard: uprobe PID " << evt.pid
                      << " (" << evt.process << "), TLS version: "
                      << TlsVersion(evt.tls_version).toString()
                      << " — no TCP sockets found, cannot SOCK_DESTROY\n";
        }
    }

    // LogAction
    RedfishEventMessage event_msg(
        evt, verdict.message_id, verdict.message, verdict.severity);
    action_loop_.pushAction(
        std::make_unique<LogAction>(event_msg.format(), output_path_));
    std::cerr << "https_guard: pushing LogAction for severity=" << verdict.severity << "\n";
    return 0;
}

int HttpGuardProgram::ringBufferCallback(void* ctx, void* data, size_t size) noexcept
{
    return static_cast<HttpGuardProgram*>(ctx)->ringBufferHandler(data, size);
}

}  // namespace https_guard
