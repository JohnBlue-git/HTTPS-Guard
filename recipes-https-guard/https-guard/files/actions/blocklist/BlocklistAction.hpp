#pragma once

#include <chrono>
#include <cstdint>
#include <string>

#include <boost/asio/awaitable.hpp>

#include "../core/ActionLoop.hpp"

namespace https_guard {

/* Refresh / insert a single source IP into the blocklist. */
class BlocklistAddAction final : public IAction {
public:
    // IPv4-only: this daemon's blocklist BPF map is keyed on a 32-bit
    // address and stays that way -- an IPv6-attributed verdict is enforced
    // via BlockTcpAction alone (see dispatch.cpp). Deliberately not renamed
    // to match EventMeta's IpAddress; this constructor's whole reason to
    // stay uint32_t is documenting "this call cannot take a v6 address".
    BlocklistAddAction(std::uint32_t src_ip_v4,
                       std::chrono::seconds ttl,
                       std::string reason) noexcept;

    boost::asio::awaitable<void> execute_async() override;

    std::uint32_t src_ip_v4() const noexcept { return src_ip_v4_; }
    const std::string& reason() const noexcept { return reason_; }

private:
    std::uint32_t      src_ip_v4_;
    std::chrono::seconds ttl_;
    std::string        reason_;
};

}  // namespace https_guard
