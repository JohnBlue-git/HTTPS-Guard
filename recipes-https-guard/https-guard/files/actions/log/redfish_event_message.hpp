#pragma once

#include <chrono>
#include <cstdint>
#include <iomanip>
#include <nlohmann/json.hpp>
#include <sstream>
#include <string>

#include "hg_event.hpp"

namespace https_guard {

class RedfishEventMessage {
public:
    /* Takes the event by reference and keeps only the two scalars it
     * formats. It used to store an hg_event by value, which is no longer
     * possible now that events are polymorphic (the copy would slice off
     * the hook's half) -- and was never needed, since nothing here read
     * more than these. */
    RedfishEventMessage(const hg_event& event,
                        std::string message_id,
                        std::string message,
                        std::string severity)
        : timestamp_ns_(event.timestamp_ns)
        , pid_(event.pid)
        , message_id_(std::move(message_id))
        , message_(std::move(message))
        , severity_(std::move(severity))
    {
    }

    std::string format() const
    {
        json payload;
        payload["@odata.type"] = "#Event.v1_7_0.Event";
        payload["Name"] = "Platform Security Anomaly Event";
        payload["Id"] = std::to_string(timestamp_ns_);

        json event_entry;
        event_entry["EventId"] = std::to_string(timestamp_ns_) + "-" + std::to_string(pid_);
        event_entry["Severity"] = severity_;
        event_entry["MessageId"] = message_id_;
        event_entry["Message"] = message_;
        event_entry["EventTimestamp"] = nowUtcIso8601();
        event_entry["OriginOfCondition"] = {{"@odata.id", "/redfish/v1/Managers/BMC"}};

        payload["Events"] = json::array({event_entry});

        return payload.dump();
    }

    const std::string& getMessageId() const { return message_id_; }
    const std::string& getMessage() const { return message_; }
    const std::string& getSeverity() const { return severity_; }

private:
    static std::string nowUtcIso8601()
    {
        const auto now = std::chrono::system_clock::now();
        const auto t = std::chrono::system_clock::to_time_t(now);

        std::tm tm_utc {};
        gmtime_r(&t, &tm_utc);

        std::ostringstream oss;
        oss << std::put_time(&tm_utc, "%Y-%m-%dT%H:%M:%SZ");
        return oss.str();
    }

    using json = nlohmann::json;

    std::uint64_t timestamp_ns_;
    std::uint32_t pid_;
    std::string message_id_;
    std::string message_;
    std::string severity_;
};

}  // namespace https_guard
