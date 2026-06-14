#include "redfish_formatter.hpp"

#include <chrono>
#include <iomanip>
#include <nlohmann/json.hpp>
#include <sstream>

namespace https_guard {

using json = nlohmann::json;

std::string now_utc_iso8601()
{
	using namespace std::chrono;
	const auto now = system_clock::now();
	const auto t = system_clock::to_time_t(now);

	std::tm tm_utc {};
	gmtime_r(&t, &tm_utc);

	std::ostringstream oss;
	oss << std::put_time(&tm_utc, "%Y-%m-%dT%H:%M:%SZ");
	return oss.str();
}

std::string format_redfish_event(const hg_event& event,
								 const std::string& message_id,
								 const std::string& message,
								 const std::string& severity)
{
	json payload;
	payload["@odata.type"] = "#Event.v1_7_0.Event";
	payload["Name"] = "Platform Security Anomaly Event";
	payload["Id"] = std::to_string(event.timestamp_ns);

	json event_entry;
	event_entry["EventId"] = std::to_string(event.timestamp_ns) + "-" + std::to_string(event.pid);
	event_entry["Severity"] = severity;
	event_entry["MessageId"] = message_id;
	event_entry["Message"] = message;
	event_entry["EventTimestamp"] = now_utc_iso8601();
	event_entry["OriginOfCondition"] = {{"@odata.id", "/redfish/v1/Managers/BMC"}};

	payload["Events"] = json::array({event_entry});

	return payload.dump();
}

}  // namespace https_guard
