#pragma once
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>

namespace https_guard {

/// Escape a string for safe inclusion in a JSON string value.
inline std::string json_escape(const std::string& raw)
{
    std::ostringstream escaped;
    for (char c : raw) {
        switch (c) {
            case '"':  escaped << "\\\""; break;
            case '\\': escaped << "\\\\"; break;
            case '\b': escaped << "\\b";  break;
            case '\f': escaped << "\\f";  break;
            case '\n': escaped << "\\n";  break;
            case '\r': escaped << "\\r";  break;
            case '\t': escaped << "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    escaped << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                            << static_cast<unsigned>(static_cast<unsigned char>(c));
                } else {
                    escaped << c;
                }
                break;
        }
    }
    return escaped.str();
}

/// Convert a TLS version code to a human-readable string.
inline std::string tls_version_to_string(uint16_t tls_version)
{
    switch (tls_version) {
        case 0x0301: return "TLS 1.0";
        case 0x0302: return "TLS 1.1";
        case 0x0303: return "TLS 1.2";
        case 0x0304: return "TLS 1.3";
        default:     return "Unknown";
    }
}

}  // namespace https_guard