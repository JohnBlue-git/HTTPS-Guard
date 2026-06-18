#pragma once

#include <chrono>
#include <cstdint>
#include <string>

#include <bpf/bpf.h>

#include "blocklist.bpf.h"

namespace https_guard {

inline constexpr const char* kBlocklistMapName = HTTPS_GUARD_BLOCKLIST_MAP_NAME;

class Blocklist {
public:
    static Blocklist& instance() noexcept;

    bool adopt(int map_fd) noexcept;
    void reset() noexcept;

    bool contains(std::uint32_t src_ip_v4) const noexcept;
    int add(std::uint32_t src_ip_v4, std::chrono::seconds ttl) noexcept;

    int fd() const noexcept { return fd_; }

    static std::string formatIp(std::uint32_t src_ip_v4_network_order) noexcept;

private:
    Blocklist() noexcept = default;
    Blocklist(const Blocklist&) = delete;
    Blocklist& operator=(const Blocklist&) = delete;

    int fd_ = -1;
};

}