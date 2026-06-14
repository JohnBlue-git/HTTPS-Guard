#include "LogAction.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>

namespace https_guard {

LogAction::LogAction(std::string output_path)
    : output_path_(std::move(output_path))
{
    const auto directory = std::filesystem::path(output_path_).parent_path();
    if (!directory.empty()) {
        std::filesystem::create_directories(directory);
    }
}

void LogAction::execute(const hg_event& event)
{
    const auto [message_id, message, severity] = create_event_details(event);
    if (message_id.empty()) {
        return;
    }

    const std::string payload = formatter_.format(event, message_id, message, severity);
    write_event(payload);
    std::cout << "[HTTPS-Guard] " << message << "\n";
}

std::tuple<std::string, std::string, std::string> LogAction::create_event_details(const hg_event& event) const
{
    std::string severity = "OK";
    std::string message_id;
    std::string message;

    switch (event.event_type) {
        case HG_EVENT_TLS_VERSION_VIOLATION:
            severity = "Critical";
            message_id = "OemSecurityEvent.1.0.0.HttpsTlsVersionViolation";
            message = "Security violation: Process '" + std::string(event.process) + "' (PID " +
                      std::to_string(event.pid) + ") attempted an HTTPS connection using an insecure TLS version (" +
                      TlsVersion(event.tls_version).toString() + "). Packet was blocked.";
            break;

        case HG_EVENT_HTTP_ANOMALY_DETECTED:
        case HG_EVENT_HTTP_PAYLOAD_OBSERVED: {
            std::string matched_rule;
            const bool suspicious = pattern_detector_.isSuspicious(event.payload_snippet, matched_rule) ||
                                    event.event_type == HG_EVENT_HTTP_ANOMALY_DETECTED;

            if (!suspicious) {
                break;
            }

            if (matched_rule.empty()) {
                matched_rule = "kernel-signature";
            }

            severity = "Warning";
            message_id = "OemSecurityEvent.1.0.0.HttpsPayloadAnomalyDetected";
            message = "Attack signature detected from process '" + std::string(event.process) + "' (PID " +
                      std::to_string(event.pid) + "), rule '" + matched_rule + "'. Connection should be terminated or quarantined.";
            break;
        }

        default:
            break;
    }

    return {message_id, message, severity};
}

void LogAction::write_event(const std::string& line)
{
    std::ofstream ofs(output_path_, std::ios::app);
    if (!ofs) {
        std::cerr << "failed to open event log: " << output_path_ << "\n";
        return;
    }
    ofs << line << '\n';
}

}  // namespace https_guard
