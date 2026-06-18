#pragma once

#include <cstdint>
#include <string>

#include <boost/asio/awaitable.hpp>

namespace https_guard {

/**
 * RAII wrapper around a NETLINK_INET_DIAG socket used to issue
 * SOCK_DESTROY commands to the kernel.
 *
 * The fd is opened (with SOCK_NONBLOCK) and connected to the kernel
 * in the constructor; closed in the destructor.  The actual Netlink
 * send / recv is a true Boost.Asio async operation using the
 * posix::stream_descriptor, so no thread or poll loop is needed.
 */
class TcpDestroyer {
public:
    TcpDestroyer(std::uint32_t src_ip_v4,
                 std::uint32_t dst_ip_v4,
                 std::uint16_t src_port,
                 std::uint16_t dst_port,
                 std::string reason) noexcept;

    ~TcpDestroyer() noexcept;

    TcpDestroyer(const TcpDestroyer&) = delete;
    TcpDestroyer& operator=(const TcpDestroyer&) = delete;

    /**
     * Send SOCK_DESTROY for the configured 4-tuple and read the
     * kernel's acknowledgment.
     *
     * This is a true async coroutine – it uses the executor of the
     * calling coroutine to register the fd with epoll, so no extra
     * threads or busy-poll loops are required.
     *
     * @return true if the destroy request was accepted
     *         (NLMSG_ERROR with error == 0).
     */
    boost::asio::awaitable<bool> async_execute() noexcept;

private:
    int              nl_fd_ = -1;
    std::uint32_t    src_ip_v4_;
    std::uint32_t    dst_ip_v4_;
    std::uint16_t    src_port_;
    std::uint16_t    dst_port_;
    std::string      reason_;
};

}  // namespace https_guard