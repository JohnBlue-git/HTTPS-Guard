#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <utility>

#include <arpa/inet.h>
#include <cstddef>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/posix/stream_descriptor.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "TcpDestroyer.hpp"

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

/*
 * Prepare the SOCK_DESTROY Netlink message into the caller-provided
 * msghdr/iovec so that the calling coroutine can send it.
 */
void buildDestroyRequest(const struct diag_nl_msg& msg,
                         struct msghdr& nl_hdr,
                         struct iovec& iov,
                         struct sockaddr_nl& nl_addr) noexcept
{
    std::memset(&nl_addr, 0, sizeof(nl_addr));
    nl_addr.nl_family = AF_NETLINK;

    std::memset(&iov, 0, sizeof(iov));
    iov.iov_base = const_cast<diag_nl_msg*>(&msg);
    iov.iov_len  = sizeof(msg);

    std::memset(&nl_hdr, 0, sizeof(nl_hdr));
    nl_hdr.msg_name    = &nl_addr;
    nl_hdr.msg_namelen = sizeof(nl_addr);
    nl_hdr.msg_iov     = &iov;
    nl_hdr.msg_iovlen  = 1;
}

}  // anonymous namespace

TcpDestroyer::TcpDestroyer(std::uint32_t local_ip_v4,
                           std::uint32_t remote_ip_v4,
                           std::uint16_t local_port,
                           std::uint16_t remote_port,
                           std::string reason) noexcept
    : local_ip_v4_(local_ip_v4)
    , remote_ip_v4_(remote_ip_v4)
    , local_port_(local_port)
    , remote_port_(remote_port)
    , reason_(std::move(reason))
{
    /*
     * Open with SOCK_NONBLOCK so the fd can be used with
     * Boost.Asio's reactor (epoll) for true async I/O.
     */
    nl_fd_ = socket(AF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
                    NETLINK_INET_DIAG);
    if (nl_fd_ < 0) {
        std::cerr << "BlockTcpAction: socket(NETLINK_INET_DIAG) failed: "
                  << std::strerror(errno) << " (" << errno << ")\n";
    }
}

TcpDestroyer::~TcpDestroyer() noexcept
{
    if (nl_fd_ >= 0) {
        close(nl_fd_);
    }
}

boost::asio::awaitable<bool> TcpDestroyer::async_execute() noexcept
{
    if (nl_fd_ < 0) {
        co_return false;
    }

    /* Build the SOCK_DESTROY request for the exact TCP 4-tuple. */
    struct diag_nl_msg msg{};
    msg.nlh.nlmsg_len   = sizeof(msg);
    msg.nlh.nlmsg_type  = SOCK_DESTROY;          /* <linux/inet_diag.h> */
    /* NLM_F_ACK matters here, and its absence hid a working enforcement path.
     *
     * With NLM_F_REQUEST alone, netlink replies only on *error* -- a
     * successful SOCK_DESTROY sends nothing back. While CONFIG_INET_DIAG was
     * missing from the kernel every request failed, so a reply always
     * arrived and the failure was always logged; once the kernel could
     * actually honour the request, success became completely silent and this
     * code sat waiting for a reply that was never coming.
     *
     * For a security daemon that is the wrong way round: a successful
     * teardown is precisely the event worth recording. Asking for an ack
     * makes the kernel answer either way, which also makes the
     * "destroyed TCP connection" branch below reachable at all. */
    msg.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    msg.nlh.nlmsg_seq   = 1;

    msg.req.sdiag_family   = AF_INET;
    msg.req.sdiag_protocol = IPPROTO_TCP;
    msg.req.idiag_states   = 0xFFF;               /* all TCP states */

    /*
     * Byte order at this boundary -- the reason SOCK_DESTROY never worked
     * before.
     *
     * EventMeta's convention (see detections/core/event_meta.hpp) is:
     *   - addresses: NETWORK byte order
     *   - ports:     HOST byte order
     *
     * inet_diag_sockid wants both in network byte order: idiag_src/idiag_dst
     * are __be32 and idiag_sport/idiag_dport are __be16. So the addresses
     * copy verbatim, but the ports must be converted here.
     *
     * Orientation: inet_diag_sockid's src/sport is the socket's LOCAL end
     * and dst/dport the peer, which is why this class takes local_ and
     * remote_ parameters rather than src/dst. Under the old src/dst names the XDP hook passed
     * these inverted (an ingress packet's source is the peer, not us), so
     * even a byte-order-correct request described a socket that does not
     * exist.
     *
     * The previous code asserted in a comment that *all* of these fields
     * were already network order and copied the ports verbatim too. They
     * were not, so the kernel was asked for a byte-swapped port -- e.g. 443
     * (0x01BB) looked up as 47873 (0xBB01) -- matched nothing, and returned
     * -ENOENT every time. Every "connection blocked" message this daemon
     * has ever emitted was therefore inaccurate.
     *
     * idiag_cookie must be initialised to all-ones (~0ULL); the kernel
     * interprets this as "don't care / match any socket".  A zero
     * cookie would require an exact cookie match which is almost never
     * what we want.
     */
    msg.req.id.idiag_sport  = htons(local_port_);
    msg.req.id.idiag_dport  = htons(remote_port_);
    msg.req.id.idiag_src[0] = local_ip_v4_;
    msg.req.id.idiag_dst[0] = remote_ip_v4_;
    msg.req.id.idiag_cookie[0] = ~0ULL;
    msg.req.id.idiag_cookie[1] = ~0ULL;

    /* ------------------------------------------------------------------
     * Truly async Netlink I/O via Boost.Asio's reactor.
     *
     * We wrap the non-blocking fd in a posix::stream_descriptor and
     * use async_wait() to be notified by epoll when the socket is
     * ready for writing / reading.  The actual sendmsg/recvmsg calls
     * are issued after readiness is confirmed, so they never block.
     * No thread, no polling loop, no busy-wait.
     * ------------------------------------------------------------------ */

    boost::asio::posix::stream_descriptor desc(
        co_await boost::asio::this_coro::executor);
    desc.assign(nl_fd_);

    /* ---- Send the destroy command ---- */
    struct iovec iov;
    struct msghdr nl_hdr;
    struct sockaddr_nl nl_addr;

    buildDestroyRequest(msg, nl_hdr, iov, nl_addr);

    co_await desc.async_wait(
        boost::asio::posix::stream_descriptor::wait_write,
        boost::asio::use_awaitable);

    const ssize_t sent = sendmsg(nl_fd_, &nl_hdr, 0);
    if (sent < 0) {
        std::cerr << "BlockTcpAction: SOCK_DESTROY sendmsg failed: "
                  << std::strerror(errno) << " (" << errno << ")\n";
        desc.release();
        co_return false;
    }

    /* ---- Read the kernel's reply ---- */
    std::uint8_t reply_buf[8192];

    struct iovec riov;
    std::memset(&riov, 0, sizeof(riov));
    riov.iov_base = reply_buf;
    riov.iov_len  = sizeof(reply_buf);

    struct sockaddr_nl reply_addr{};

    struct msghdr rcv_hdr;
    std::memset(&rcv_hdr, 0, sizeof(rcv_hdr));
    rcv_hdr.msg_name    = &reply_addr;
    rcv_hdr.msg_namelen = sizeof(reply_addr);
    rcv_hdr.msg_iov     = &riov;
    rcv_hdr.msg_iovlen  = 1;

    co_await desc.async_wait(
        boost::asio::posix::stream_descriptor::wait_read,
        boost::asio::use_awaitable);

    const ssize_t recvd = recvmsg(nl_fd_, &rcv_hdr, 0);
    if (recvd < 0) {
        std::cerr << "BlockTcpAction: SOCK_DESTROY recvmsg failed: "
                  << std::strerror(errno) << " (" << errno << ")\n";
        desc.release();
        co_return false;
    }

    /* Release ownership of the fd back to TcpDestroyer's destructor. */
    desc.release();

    /* Parse the Netlink response header. */
    if (recvd < static_cast<ssize_t>(sizeof(struct nlmsghdr))) {
        std::cerr << "BlockTcpAction: short Netlink reply ("
                  << recvd << " bytes)\n";
        co_return false;
    }

    const auto* nl_reply = reinterpret_cast<const struct nlmsghdr*>(reply_buf);

    if (nl_reply->nlmsg_type == NLMSG_ERROR) {
        /* NLMSG_ERROR carries an nlmsgerr struct; error == 0 means success. */
        const auto* err = static_cast<const struct nlmsgerr*>(NLMSG_DATA(nl_reply));
        const int nl_err = err->error;

        if (nl_err == 0) {
            std::cerr << "BlockTcpAction: destroyed TCP connection "
                      << formatIp(local_ip_v4_) << ":" << local_port_
                      << " -> " << formatIp(remote_ip_v4_) << ":" << remote_port_
                      << " reason=" << reason_ << "\n";
            co_return true;
        } else {
            std::cerr << "BlockTcpAction: SOCK_DESTROY failed for "
                      << formatIp(local_ip_v4_) << ":" << local_port_
                      << " -> " << formatIp(remote_ip_v4_) << ":" << remote_port_
                      << " reason=" << reason_
                      << " netlink_error=" << nl_err
                      << " (" << std::strerror(-nl_err) << ")\n";
            co_return false;
        }
    } else {
        std::cerr << "BlockTcpAction: unexpected Netlink reply type "
                  << nl_reply->nlmsg_type << '\n';
        co_return false;
    }
}

}  // namespace https_guard