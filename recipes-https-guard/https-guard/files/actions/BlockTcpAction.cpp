#include <cstdint>
#include <string>
#include <utility>

#include <boost/asio/awaitable.hpp>

#include "BlockTcpAction.hpp"
#include "TcpDestroyer.hpp"

namespace https_guard {

BlockTcpAction::BlockTcpAction(std::uint32_t src_ip_v4,
                               std::uint32_t dst_ip_v4,
                               std::uint16_t src_port,
                               std::uint16_t dst_port,
                               std::string reason) noexcept
    : src_ip_v4_(src_ip_v4)
    , dst_ip_v4_(dst_ip_v4)
    , src_port_(src_port)
    , dst_port_(dst_port)
    , reason_(std::move(reason))
{}

boost::asio::awaitable<void> BlockTcpAction::execute_async()
{
    TcpDestroyer destroyer(
        src_ip_v4_, dst_ip_v4_,
        src_port_, dst_port_, reason_);

    /*
     * Truly async Netlink SOCK_DESTROY – the coroutine suspends
     * while the Asio reactor (epoll) waits for the fd to become
     * writable / readable.  No extra threads, no polling.
     */
    co_await destroyer.async_execute();

    co_return;
}

}  // namespace https_guard