#pragma once

#include <array>
#include <cstdint>
#include <string>

#include <boost/asio/awaitable.hpp>

#include "../core/ActionLoop.hpp"

namespace https_guard {

/* Kill a specific TCP 4-tuple via the kernel's tcp_drop facility
 * (NETLINK_INET_DIAG + SOCK_DESTROY).  This tears down the kernel
 * TCP socket without touching the owning process.
 *
 * Dual-stack: see TcpDestroyer.hpp for the address/family convention. */
class BlockTcpAction final : public IAction {
public:
    BlockTcpAction(bool is_ipv6,
                   std::array<std::uint8_t, 16> local_addr,
                   std::array<std::uint8_t, 16> remote_addr,
                   std::uint16_t local_port,
                   std::uint16_t remote_port,
                   std::string reason) noexcept;

    boost::asio::awaitable<void> execute_async() override;

private:
    bool               is_ipv6_;
    std::array<std::uint8_t, 16> local_addr_;
    std::array<std::uint8_t, 16> remote_addr_;
    std::uint16_t      local_port_;
    std::uint16_t      remote_port_;
    std::string        reason_;
};

}  // namespace https_guard