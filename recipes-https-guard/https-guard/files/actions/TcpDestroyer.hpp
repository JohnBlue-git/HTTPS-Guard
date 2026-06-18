#pragma once

#include <cstdint>
#include <string>

namespace https_guard {

/**
 * RAII wrapper around a NETLINK_INET_DIAG socket used to issue
 * SOCK_DESTROY commands to the kernel.
 *
 * The fd is opened in the constructor and closed in the destructor,
 * ensuring no resource leak regardless of the return path.
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
     * @return true if the destroy request was accepted
     *         (NLMSG_ERROR with error == 0).
     *
     * When the fd could not be opened in the constructor this
     * returns false without attempting any Netlink operation.
     */
    bool execute() noexcept;

private:
    int              nl_fd_ = -1;
    std::uint32_t    src_ip_v4_;
    std::uint32_t    dst_ip_v4_;
    std::uint16_t    src_port_;
    std::uint16_t    dst_port_;
    std::string      reason_;
};

}  // namespace https_guard