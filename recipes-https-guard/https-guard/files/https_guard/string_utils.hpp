#pragma once

#include <cstdint>
#include <string>

namespace https_guard {

class TlsVersion {
public:
    explicit TlsVersion(uint16_t value)
        : value_(value)
    {
    }

    std::string toString() const
    {
        switch (value_) {
            case 0x0301: return "TLS 1.0";
            case 0x0302: return "TLS 1.1";
            case 0x0303: return "TLS 1.2";
            case 0x0304: return "TLS 1.3";
            default:     return "Unknown";
        }
    }

private:
    uint16_t value_;
};

}  // namespace https_guard
