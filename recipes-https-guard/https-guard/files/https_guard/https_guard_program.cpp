#include "https_guard_program.hpp"
#include "LogAction.hpp"

#include <utility>

namespace https_guard {

HttpGuardProgram::HttpGuardProgram(std::string object_path,
                                   ActionLoop& action_loop,
                                   std::string openssl_lib_path,
                                   unsigned int ifindex) noexcept
    : BpfProgram(std::move(object_path))
    , action_loop_(action_loop)
    , openssl_lib_path_(std::move(openssl_lib_path))
    , ifindex_(ifindex)
{
}

bool HttpGuardProgram::attachProgram() noexcept
{
    bpf_program* xdp_prog = bpf_object__find_program_by_name(object_, "https_guard_xdp");
    if (!xdp_prog) {
        return false;
    }

    bpf_link* xdp_link = bpf_program__attach_xdp(xdp_prog, ifindex_);
    if (!xdp_link) {
        return false;
    }
    links_.push_back(xdp_link);

    bpf_program* uprobe_prog = bpf_object__find_program_by_name(object_, "https_guard_ssl_write");
    if (!uprobe_prog) {
        return false;
    }

    bpf_link* uprobe_link = bpf_program__attach_uprobe(uprobe_prog, false, -1, openssl_lib_path_.c_str(), 0);
    if (!uprobe_link) {
        return false;
    }
    links_.push_back(uprobe_link);
    return true;
}

ring_buffer_sample_fn HttpGuardProgram::getRingBufferHandler() noexcept
{
    return &HttpGuardProgram::ringBufferCallback;
}

int HttpGuardProgram::ringBufferHandler(void* data, size_t size) noexcept
{
    if (size < sizeof(hg_event)) {
        return 0;
    }

    const auto* evt = static_cast<const hg_event*>(data);
    std::string severity;
    std::string message_id;
    std::string message;

    if (evt->event_type == HG_EVENT_TLS_VERSION_VIOLATION) {
        severity = "Critical";
        message_id = "OemSecurityEvent.1.0.0.HttpsTlsVersionViolation";
        message = "Security violation: Process '" + std::string(evt->process) + "' (PID " +
                  std::to_string(evt->pid) + ") attempted an HTTPS connection using an insecure TLS version (" +
                  TlsVersion(evt->tls_version).toString() + "). Packet was blocked.";
    } else if (evt->event_type == HG_EVENT_HTTP_ANOMALY_DETECTED ||
               evt->event_type == HG_EVENT_HTTP_PAYLOAD_OBSERVED) {
        std::string matched_rule;
        const bool suspicious = detector_.isSuspicious(evt->payload_snippet, matched_rule) ||
                                evt->event_type == HG_EVENT_HTTP_ANOMALY_DETECTED;

        if (!suspicious) {
            return 0;
        }

        if (matched_rule.empty()) {
            matched_rule = "kernel-signature";
        }

        severity = "Warning";
        message_id = "OemSecurityEvent.1.0.0.HttpsPayloadAnomalyDetected";
        message = "Attack signature detected from process '" + std::string(evt->process) + "' (PID " +
                  std::to_string(evt->pid) + "), rule '" + matched_rule + "'. Connection should be terminated or quarantined.";
    } else {
        return 0;
    }

    RedfishEventMessage event_msg(*evt, message_id, message, severity);
    action_loop_.pushAction(std::make_unique<LogAction>(event_msg.format(), std::string("/var/log/https_guard.log")));
    return 0;
}

int HttpGuardProgram::ringBufferCallback(void* ctx, void* data, size_t size) noexcept
{
    return static_cast<HttpGuardProgram*>(ctx)->ringBufferHandler(data, size);
}

}  // namespace https_guard
