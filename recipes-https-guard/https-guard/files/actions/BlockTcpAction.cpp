#include <chrono>
#include <cstdint>
#include <future>
#include <memory>
#include <string>
#include <utility>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/use_awaitable.hpp>

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
    auto destroyer = std::make_shared<TcpDestroyer>(
        src_ip_v4_, dst_ip_v4_,
        src_port_, dst_port_, reason_);

    /*
     * Offload the blocking sendmsg / recvmsg to a C++ runtime-managed
     * thread pool via std::async.  This keeps the ActionLoop's single
     * io_context thread available for other coroutines.
     *
     * The shared_ptr keeps the RAII TcpDestroyer alive until the
     * blocking call completes; its destructor then closes the fd.
     */
    std::future<bool> future = std::async(std::launch::async,
        [destroyer]() noexcept { return destroyer->execute(); });

    /*
     * Poll the future in a spin-loop that yields back to the Asio
     * event loop after each short wait, so other work on the
     * ActionLoop is not starved.
     */
    while (future.wait_for(std::chrono::milliseconds(1))
           != std::future_status::ready) {
        co_await boost::asio::post(boost::asio::use_awaitable);
    }

    co_return;
}

}  // namespace https_guard