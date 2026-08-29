#include <cstdint>
#include <string>
#include <utility>

#include <boost/asio/awaitable.hpp>

#include "BlockTcpAction.hpp"
#include "TcpDestroyer.hpp"

namespace https_guard {

BlockTcpAction::BlockTcpAction(std::uint32_t local_ip_v4,
                               std::uint32_t remote_ip_v4,
                               std::uint16_t local_port,
                               std::uint16_t remote_port,
                               std::string reason) noexcept
    : local_ip_v4_(local_ip_v4)
    , remote_ip_v4_(remote_ip_v4)
    , local_port_(local_port)
    , remote_port_(remote_port)
    , reason_(std::move(reason))
{}

boost::asio::awaitable<void> BlockTcpAction::execute_async()
{
    TcpDestroyer destroyer(
        local_ip_v4_, remote_ip_v4_,
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