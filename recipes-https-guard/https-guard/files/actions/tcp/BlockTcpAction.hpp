#pragma once

#include <cstdint>
#include <string>

#include <boost/asio/awaitable.hpp>

#include "../core/ActionLoop.hpp"

namespace https_guard {

/* Kill a specific TCP 4-tuple via the kernel's tcp_drop facility
 * (NETLINK_INET_DIAG + SOCK_DESTROY).  This tears down the kernel
 * TCP socket without touching the owning process. */
class BlockTcpAction final : public IAction {
public:
    BlockTcpAction(std::uint32_t src_ip_v4,
                   std::uint32_t dst_ip_v4,
                   std::uint16_t src_port,
                   std::uint16_t dst_port,
                   std::string reason) noexcept;

    boost::asio::awaitable<void> execute_async() override;

private:
    std::uint32_t      src_ip_v4_;
    std::uint32_t      dst_ip_v4_;
    std::uint16_t      src_port_;
    std::uint16_t      dst_port_;
    std::string        reason_;
};

}  // namespace https_guard