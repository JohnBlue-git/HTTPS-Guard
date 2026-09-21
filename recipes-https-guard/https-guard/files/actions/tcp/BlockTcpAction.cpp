#include <array>
#include <cstdint>
#include <string>
#include <utility>

#include <boost/asio/awaitable.hpp>

#include "BlockTcpAction.hpp"
#include "TcpDestroyer.hpp"

namespace https_guard {

BlockTcpAction::BlockTcpAction(bool is_ipv6,
                               std::array<std::uint8_t, 16> local_addr,
                               std::array<std::uint8_t, 16> remote_addr,
                               std::uint16_t local_port,
                               std::uint16_t remote_port,
                               std::string reason) noexcept
    : is_ipv6_(is_ipv6)
    , local_addr_(local_addr)
    , remote_addr_(remote_addr)
    , local_port_(local_port)
    , remote_port_(remote_port)
    , reason_(std::move(reason))
{}

boost::asio::awaitable<void> BlockTcpAction::execute_async()
{
    TcpDestroyer destroyer(
        is_ipv6_, local_addr_, remote_addr_,
        local_port_, remote_port_, reason_);

    /*
     * Truly async Netlink SOCK_DESTROY – the coroutine suspends
     * while the Asio reactor (epoll) waits for the fd to become
     * writable / readable.  No extra threads, no polling.
     */
    co_await destroyer.async_execute();

    co_return;
}

}  // namespace https_guard