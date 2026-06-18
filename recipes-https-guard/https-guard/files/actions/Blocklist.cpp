#include <array>
#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <string>

#include "Blocklist.hpp"

namespace https_guard {

Blocklist& Blocklist::instance() noexcept
{
    static Blocklist inst;
    return inst;
}

bool Blocklist::adopt(int map_fd) noexcept
{
    if (map_fd < 0) {
        return false;
    }
    fd_ = map_fd;
    return true;
}

void Blocklist::reset() noexcept
{
    fd_ = -1;
}

bool Blocklist::contains(std::uint32_t src_ip_v4) const noexcept
{
    if (fd_ < 0) {
        return false;
    }

    std::uint64_t expiry = 0;
    if (bpf_map_lookup_elem(fd_, &src_ip_v4, &expiry) != 0) {
        return false;
    }
    return expiry > static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

int Blocklist::add(std::uint32_t src_ip_v4, std::chrono::seconds ttl) noexcept
{
    if (fd_ < 0) {
        return -ENOENT;
    }
    if (ttl.count() <= 0) {
        return -EINVAL;
    }

    const auto now_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    const auto ttl_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(ttl).count();
    const std::uint64_t expiry = static_cast<std::uint64_t>(now_ns + ttl_ns);

    return bpf_map_update_elem(fd_, &src_ip_v4, &expiry, BPF_ANY);
}

std::string Blocklist::formatIp(std::uint32_t src_ip_v4_network_order) noexcept
{
    std::array<char, INET_ADDRSTRLEN> buf{};
    struct in_addr address {};
    address.s_addr = src_ip_v4_network_order;
    if (inet_ntop(AF_INET, &address, buf.data(), buf.size()) == nullptr) {
        return std::string{"0.0.0.0"};
    }
    return std::string{buf.data()};
}

}