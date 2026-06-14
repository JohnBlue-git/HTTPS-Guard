#pragma once
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>

namespace https_guard {

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