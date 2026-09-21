#pragma once

#include <array>
#include <cstdint>
#include <string>

#include <boost/asio/awaitable.hpp>

#include <linux/inet_diag.h>

namespace https_guard {

/**
 * RAII wrapper around a NETLINK_INET_DIAG socket used to issue
 * SOCK_DESTROY commands to the kernel.
 *
 * The fd is opened (with SOCK_NONBLOCK) and connected to the kernel
 * in the constructor; closed in the destructor.  The actual Netlink
 * send / recv is a true Boost.Asio async operation using the
 * posix::stream_descriptor, so no thread or poll loop is needed.
 *
 * Dual-stack: addresses are 16 bytes regardless of family (network byte
 * order, matching EventMeta's IpAddress convention), with `is_ipv6`
 * selecting which shape the kernel's socket-diagnostics API should read
 * them as. For an IPv4 tuple, only the first 4 bytes are meaningful; the
 * rest are zero, exactly as EventMeta::IpAddress::setV4() already leaves
 * them, so no caller needs to special-case the two families when building
 * one of these.
 */
class TcpDestroyer {
public:
    TcpDestroyer(bool is_ipv6,
                 std::array<std::uint8_t, 16> local_addr,
                 std::array<std::uint8_t, 16> remote_addr,
                 std::uint16_t local_port,
                 std::uint16_t remote_port,
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

    /**
     * Populates req's family, ports and addresses from a dual-stack tuple.
     *
     * Pure -- no socket, no I/O -- so the field-population logic is
     * unit-testable on its own. This is deliberate: this exact logic (byte
     * order, local/remote orientation) has been wrong twice before in this
     * file's history, silently, with no test to catch it -- see DESIGN.md.
     *
     * Ports are host byte order in (this project's EventMeta convention),
     * converted to network order here. Addresses are network byte order in
     * and copied verbatim, since inet_diag_sockid's idiag_src/idiag_dst want
     * exactly that.
     */
    static void populateRequest(struct inet_diag_req_v2& req,
                                 bool is_ipv6,
                                 const std::array<std::uint8_t, 16>& local_addr,
                                 const std::array<std::uint8_t, 16>& remote_addr,
                                 std::uint16_t local_port,
                                 std::uint16_t remote_port) noexcept;

private:
    int              nl_fd_ = -1;
    bool             is_ipv6_;
    std::array<std::uint8_t, 16> local_addr_;
    std::array<std::uint8_t, 16> remote_addr_;
    std::uint16_t    local_port_;
    std::uint16_t    remote_port_;
    std::string      reason_;
};

}  // namespace https_guard