#pragma once

#include <chrono>
#include <iomanip>
#include <nlohmann/json.hpp>
#include <sstream>
#include <string>

#include "hg_event.hpp"

namespace https_guard {

class RedfishEventMessage {
public:
    RedfishEventMessage(const hg_event& event,
                        std::string message_id,
                        std::string message,
                        std::string severity)
        : event_(event)
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
        payload["Id"] = std::to_string(event_.timestamp_ns);

        json event_entry;
        event_entry["EventId"] = std::to_string(event_.timestamp_ns) + "-" + std::to_string(event_.pid);
        event_entry["Severity"] = severity_;
        event_entry["MessageId"] = message_id_;
        event_entry["Message"] = message_;
        event_entry["EventTimestamp"] = nowUtcIso8601();
        event_entry["OriginOfCondition"] = {{"@odata.id", "/redfish/v1/Managers/BMC"}};

        payload["Events"] = json::array({event_entry});

        return payload.dump();
    }

    const hg_event& getEvent() const { return event_; }
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

    hg_event event_;
    std::string message_id_;
    std::string message_;
    std::string severity_;
};

}  // namespace https_guard
