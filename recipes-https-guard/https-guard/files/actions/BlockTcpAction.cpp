#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <utility>

#include <arpa/inet.h>
#include <cstddef>

#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "BlockTcpAction.hpp"

namespace https_guard {
namespace {

/* Minimal Netlink message for SOCK_DESTROY on an AF_INET TCP 4-tuple. */
struct diag_nl_msg {
    struct nlmsghdr          nlh;
    struct inet_diag_req_v2  req;
};

/* Format a network-byte-order IPv4 address for logging. */
std::string formatIp(std::uint32_t ip) noexcept
{
    std::array<char, INET_ADDRSTRLEN> buf{};
    struct in_addr addr {};
    addr.s_addr = ip;
    if (inet_ntop(AF_INET, &addr, buf.data(), buf.size()) == nullptr) {
        return std::string{"0.0.0.0"};
    }
    return std::string{buf.data()};
}

}  // anonymous namespace

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
    /* ------------------------------------------------------------------
     * Open a NETLINK_INET_DIAG socket for the SOCK_DESTROY operation.
     *
     * tcp_drop / SOCK_DESTROY (Linux 4.10+) instructs the kernel to
     * tear down the TCP socket that matches the given 4-tuple *without*
     * touching the owning process.  The process receives a standard
     * error (typically EPIPE / ECONNRESET) on its next I/O operation.
     * ------------------------------------------------------------------ */
    const int nl_fd = socket(AF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC,
                             NETLINK_INET_DIAG);
    if (nl_fd < 0) {
        std::cerr << "BlockTcpAction: socket(NETLINK_INET_DIAG) failed: "
                  << std::strerror(errno) << " (" << errno << ")\n";
        co_return;
    }

    /* Build the SOCK_DESTROY request for the exact TCP 4-tuple. */
    struct diag_nl_msg msg{};
    msg.nlh.nlmsg_len   = sizeof(msg);
    msg.nlh.nlmsg_type  = SOCK_DESTROY;          /* <linux/inet_diag.h> */
    msg.nlh.nlmsg_flags = NLM_F_REQUEST;
    msg.nlh.nlmsg_seq   = 1;

    msg.req.sdiag_family   = AF_INET;
    msg.req.sdiag_protocol = IPPROTO_TCP;
    msg.req.idiag_states   = 0xFFF;               /* all TCP states */

    /*
     * All address/port fields are already in network byte order in the
     * hg_event, so we copy them verbatim.
     *
     * idiag_cookie must be initialised to all-ones (~0ULL); the kernel
     * interprets this as "don't care / match any socket".  A zero
     * cookie would require an exact cookie match which is almost never
     * what we want.
     */
    msg.req.id.idiag_sport  = src_port_;
    msg.req.id.idiag_dport  = dst_port_;
    msg.req.id.idiag_src[0] = src_ip_v4_;
    msg.req.id.idiag_dst[0] = dst_ip_v4_;
    msg.req.id.idiag_cookie[0] = ~0ULL;
    msg.req.id.idiag_cookie[1] = ~0ULL;

    /* Send the destroy command. */
    struct sockaddr_nl nl_addr{};
    nl_addr.nl_family = AF_NETLINK;

    struct iovec iov;
    std::memset(&iov, 0, sizeof(iov));
    iov.iov_base = &msg;
    iov.iov_len  = sizeof(msg);

    struct msghdr nl_hdr;
    std::memset(&nl_hdr, 0, sizeof(nl_hdr));
    nl_hdr.msg_name    = &nl_addr;
    nl_hdr.msg_namelen = sizeof(nl_addr);
    nl_hdr.msg_iov     = &iov;
    nl_hdr.msg_iovlen  = 1;

    const ssize_t sent = sendmsg(nl_fd, &nl_hdr, 0);
    if (sent < 0) {
        std::cerr << "BlockTcpAction: SOCK_DESTROY sendmsg failed: "
                  << std::strerror(errno) << " (" << errno << ")\n";
        close(nl_fd);
        co_return;
    }

    /* ------------------------------------------------------------------
     * Read the kernel's reply.
     * Even though SOCK_DESTROY is asynchronous from the kernel's
     * perspective, Netlink will return an NLMSG_ERROR / NLMSG_DONE
     * indicating whether the destroy request was *accepted* (not
     * whether the socket has already been destroyed).
     * ------------------------------------------------------------------ */
    std::uint8_t reply_buf[8192];

    iov.iov_base = reply_buf;
    iov.iov_len  = sizeof(reply_buf);

    struct sockaddr_nl reply_addr{};
    nl_hdr.msg_name    = &reply_addr;
    nl_hdr.msg_namelen = sizeof(reply_addr);

    const ssize_t recvd = recvmsg(nl_fd, &nl_hdr, 0);
    if (recvd < 0) {
        std::cerr << "BlockTcpAction: SOCK_DESTROY recvmsg failed: "
                  << std::strerror(errno) << " (" << errno << ")\n";
        close(nl_fd);
        co_return;
    }

    close(nl_fd);

    /* Parse the Netlink response header. */
    if (recvd < static_cast<ssize_t>(sizeof(struct nlmsghdr))) {
        std::cerr << "BlockTcpAction: short Netlink reply (" << recvd << " bytes)\n";
        co_return;
    }

    const auto* nl_reply = reinterpret_cast<const struct nlmsghdr*>(reply_buf);

    if (nl_reply->nlmsg_type == NLMSG_ERROR) {
        /* NLMSG_ERROR carries an nlmsgerr struct; error == 0 means success. */
        const auto* err = static_cast<const struct nlmsgerr*>(NLMSG_DATA(nl_reply));
        const int nl_err = err->error;

        if (nl_err == 0) {
            std::cerr << "BlockTcpAction: destroyed TCP connection "
                      << formatIp(src_ip_v4_) << ":" << ntohs(src_port_)
                      << " -> " << formatIp(dst_ip_v4_) << ":" << ntohs(dst_port_)
                      << " reason=" << reason_ << "\n";
        } else {
            std::cerr << "BlockTcpAction: SOCK_DESTROY failed for "
                      << formatIp(src_ip_v4_) << ":" << ntohs(src_port_)
                      << " -> " << formatIp(dst_ip_v4_) << ":" << ntohs(dst_port_)
                      << " reason=" << reason_
                      << " netlink_error=" << nl_err
                      << " (" << std::strerror(-nl_err) << ")\n";
        }
    } else {
        std::cerr << "BlockTcpAction: unexpected Netlink reply type "
                  << nl_reply->nlmsg_type << '\n';
    }

    co_return;
}

}  // namespace https_guard