#include "redfish_formatter.hpp"

#include <chrono>
#include <iomanip>
#include <sstream>

namespace https_guard {

std::string tls_version_to_string(uint16_t tls_version)
{
	switch (tls_version) {
		case 0x0301:
			return "TLS 1.0";
		case 0x0302:
			return "TLS 1.1";
		case 0x0303:
			return "TLS 1.2";
		case 0x0304:
			return "TLS 1.3";
		default:
			return "Unknown";
	}
}

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
	std::ostringstream payload;
	payload << "{";
	payload << "\"@odata.type\":\"#Event.v1_7_0.Event\",";
	payload << "\"Name\":\"Platform Security Anomaly Event\",";
	payload << "\"Id\":\"" << event.timestamp_ns << "\",";
	payload << "\"Events\":[{";
	payload << "\"EventId\":\"" << event.timestamp_ns << "-" << event.pid << "\",";
	payload << "\"Severity\":\"" << severity << "\",";
	payload << "\"MessageId\":\"" << message_id << "\",";
	payload << "\"Message\":\"" << message << "\",";
	payload << "\"EventTimestamp\":\"" << now_utc_iso8601() << "\",";
	payload << "\"OriginOfCondition\":{\"@odata.id\":\"/redfish/v1/Managers/BMC\"}";
	payload << "}]}";

	return payload.str();
}

}  // namespace https_guard
