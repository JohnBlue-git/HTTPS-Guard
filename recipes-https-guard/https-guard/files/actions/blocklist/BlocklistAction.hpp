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
